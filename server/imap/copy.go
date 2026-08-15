package imap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
)

func (s *IMAPSession) Copy(ctx context.Context, numSet imap.NumSet, mboxName string) (*imap.CopyData, error) {
	// First phase: Read session state with read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		s.DebugLog("failed to acquire read lock within timeout")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}

	if s.selectedMailbox == nil {
		release()
		s.DebugLog("copy failed: no mailbox selected")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "no mailbox selected",
		}
	}
	selectedMailboxID := s.selectedMailbox.ID
	selectedMailboxName := s.selectedMailbox.Name
	AccountID := s.AccountID()
	release()

	// Use decoded numSet - this safely acquires its own read lock
	decodedNumSet := s.decodeNumSet(numSet)

	// Middle phase: Database operations outside lock
	destMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(ctx, AccountID, mboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.DebugLog("copy failed: destination mailbox does not exist", "mailbox", mboxName)
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeTryCreate,
				Text: fmt.Sprintf("destination mailbox '%s' does not exist", mboxName),
			}
		}
		return nil, s.internalError("failed to fetch destination mailbox '%s': %v", mboxName, err)
	}

	// RFC 4314 §4: COPY requires the 'i' (insert) right on the destination. We fetch
	// the user's full rights here so the same value can drive per-flag filtering of
	// the copied messages below (the owner holds every right).
	destRights, err := s.userRightsForMailbox(ctx, destMailbox.ID, destMailbox.AccountID)
	if err != nil {
		return nil, s.internalError("failed to check destination permissions: %v", err)
	}
	if !strings.ContainsRune(destRights, 'i') {
		s.DebugLog("user does not have insert permission on destination", "mailbox", mboxName)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to copy messages to this mailbox",
		}
	}

	// Get the messages to determine their UIDs
	messages, err := s.server.rdb.GetMessagesByNumSetWithRetry(ctx, selectedMailboxID, decodedNumSet)
	if err != nil {
		return nil, s.internalError("failed to retrieve messages for copy: %v", err)
	}

	if len(messages) == 0 {
		return nil, nil
	}

	// Collect source UIDs
	var sourceUIDs []imap.UID
	for _, msg := range messages {
		sourceUIDs = append(sourceUIDs, msg.UID)
	}

	// Identify cross-account operations and relocate S3 objects if necessary.
	destS3Domain := s.Session.User.Domain()
	destS3Localpart := s.Session.User.LocalPart()
	if destMailbox.AccountID != s.AccountID() {
		domain, localpart, err := s.server.rdb.ResolveAccountS3Owner(ctx, destMailbox.AccountID)
		if err != nil {
			return nil, s.internalError("failed to resolve owner for destination mailbox: %v", err)
		}
		destS3Domain = domain
		destS3Localpart = localpart
	}

	// ensureDestObject makes the body readable under the destination owner's S3 path.
	// It runs under GetS3ObjectLockID(destination account, hash), the lock the cleaner
	// holds while it re-checks that nothing references an object and deletes it: without
	// it, an object whose only rows for this account are expunged can be deleted between
	// the existence check and the copy, and the new message row would point at nothing
	// (the 404 NoSuchKey hazard the APPEND dedup and IsContentHashUploaded describe).
	ensureDestObject := func(contentHash, sourceKey, destKey string) error {
		return s.server.rdb.ExecuteWithS3ObjectSessionLock(ctx, contentHash, destMailbox.AccountID, func() error {
			exists, err := s.server.s3.ExistsWithRetry(ctx, destKey)
			if err != nil {
				s.WarnLog("failed to check if S3 object exists at destination", "destKey", destKey, "error", err)
			}
			if exists {
				return nil
			}
			return s.server.s3.CopyWithRetry(ctx, sourceKey, destKey)
		})
	}

	type crossAccountObject struct{ contentHash, sourceKey, destKey string }
	var crossAccountObjects []crossAccountObject
	seenHashes := make(map[string]bool)

	for _, msg := range messages {
		if msg.AccountID == destMailbox.AccountID {
			continue // Same owner: body already lives under the correct S3 path.
		}
		// Cross-account copy: the new row will be owned by the destination mailbox
		// owner, so the body must be reachable under the owner's S3 path.
		if msg.IsUploaded {
			// Body is in S3 under the source's path; copy it to the owner's path.
			if seenHashes[msg.ContentHash] {
				continue
			}
			seenHashes[msg.ContentHash] = true
			obj := crossAccountObject{
				contentHash: msg.ContentHash,
				sourceKey:   helpers.NewS3Key(msg.S3Domain, msg.S3Localpart, msg.ContentHash),
				destKey:     helpers.NewS3Key(destS3Domain, destS3Localpart, msg.ContentHash),
			}
			if err := ensureDestObject(obj.contentHash, obj.sourceKey, obj.destKey); err != nil {
				return nil, s.internalError("failed to copy S3 object for message: %v", err)
			}
			crossAccountObjects = append(crossAccountObjects, obj)
		} else if s.server.uploader != nil {
			// Body is still staged locally under the source account. Hardlink it to
			// the owner's staging path so the uploader (re-staged in CopyMessages)
			// uploads it under the owner's path. Failing here would silently lose the
			// body, so treat it as fatal rather than warning and proceeding.
			sourcePath := s.server.uploader.FilePath(msg.ContentHash, msg.AccountID)
			destPath := s.server.uploader.FilePath(msg.ContentHash, destMailbox.AccountID)
			if sourcePath != destPath {
				if err := helpers.LinkOrCopyFile(sourcePath, destPath); err != nil {
					return nil, s.internalError("failed to stage local file for cross-account copy: %v", err)
				}
			}
		}
	}

	// Perform the batch copy operation
	uidMap, newMessageIDs, err := s.server.rdb.CopyMessagesWithRetry(ctx, &sourceUIDs, selectedMailboxID, destMailbox.ID, destMailbox.AccountID, destS3Domain, destS3Localpart, s.server.hostname)
	if err != nil {
		switch {
		case errors.Is(err, resilient.ErrCommitOutcomeUnknown):
			// The COMMIT's acknowledgement was lost: the copy may or may not have applied.
			// Answering OK here on a copy that rolled back is the dangerous outcome — a
			// client that implements move as COPY+STORE+EXPUNGE would then delete the
			// source of messages that never reached the destination. Resolve it exactly:
			// the copied rows carry BIGSERIAL ids that exist iff the transaction committed,
			// so read them back. Only a confirmed commit yields OK; every other case
			// (confirmed rollback, or a read-back that itself fails) yields a retryable NO,
			// which is loss-safe because a rolled-back copy left the source intact.
			committed, rbErr := s.server.rdb.CopiedMessagesCommittedWithRetry(ctx, newMessageIDs)
			if rbErr != nil {
				s.WarnLog("COPY commit outcome unknown and read-back failed; answering retryable NO",
					"error", rbErr, "commit_error", err)
				return nil, &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Text: "Copy could not be confirmed, please retry",
				}
			}
			if !committed {
				s.InfoLog("COPY commit acknowledgement lost; read-back confirms it did NOT commit, answering retryable NO")
				return nil, &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Text: "Copy could not be completed, please retry",
				}
			}
			// Confirmed committed despite the lost acknowledgement: the captured uidMap is
			// authoritative, so fall through to the normal success path.
			s.WarnLog("COPY commit acknowledgement was lost but read-back confirms the copy committed; answering OK",
				"messages", len(newMessageIDs))
		case strings.Contains(err.Error(), "source and destination mailboxes cannot be the same"):
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Text: "Cannot copy messages to the same mailbox",
			}
		default:
			return nil, s.internalError("failed to copy messages: %v", err)
		}
	}

	// The lock above is released before the rows exist, so a cleaner that was already
	// waiting on it could still have found the object unreferenced and deleted it. Re-run
	// the check now that the copied rows are committed: from here on they keep the
	// object out of every orphan check, so this pass either finds it intact or restores
	// it for good.
	for _, obj := range crossAccountObjects {
		if err := ensureDestObject(obj.contentHash, obj.sourceKey, obj.destKey); err != nil {
			s.ErrorLog("failed to re-validate copied S3 object after copy", "destKey", obj.destKey, "error", err)
		}
	}

	// Pin this session to the master DB (same rationale as APPEND, append.go).
	// COPY writes into the destination mailbox; pinning gives read-your-writes so
	// a subsequent SELECT/STATUS of the destination in this session (or a poll
	// after copying into the currently-selected mailbox) reads the new messages
	// from the master rather than a lagging read replica.
	s.useMasterDB.Store(true)

	// RFC 4314 §4: only flags the user has the right to set are stored on the newly
	// created messages (\Seen↔'s', \Deleted↔'t', other flags↔'w'); a missing flag
	// right must NOT fail the COPY. The owner holds every right, so this is a no-op
	// for personal mailboxes. Copies preserve source flags, so we strip the ones the
	// user may not set on the destination, grouped per flag for efficient batching.
	if !(strings.ContainsRune(destRights, 's') && strings.ContainsRune(destRights, 't') && strings.ContainsRune(destRights, 'w')) {
		stripUIDsByFlag := make(map[imap.Flag][]imap.UID)
		for _, msg := range messages {
			destUID, ok := uidMap[msg.UID]
			if !ok {
				continue
			}
			msgFlags := db.BitwiseToFlags(msg.BitwiseFlags)
			for _, cf := range msg.CustomFlags {
				msgFlags = append(msgFlags, imap.Flag(cf))
			}
			for _, f := range msgFlags {
				if !flagRightHeld(f, destRights) {
					stripUIDsByFlag[f] = append(stripUIDsByFlag[f], destUID)
				}
			}
		}
		for f, uids := range stripUIDsByFlag {
			if _, rmErr := s.server.rdb.RemoveMessageFlagsBatchWithRetry(ctx, uids, destMailbox.ID, []imap.Flag{f}); rmErr != nil {
				// The copy already succeeded; log and continue rather than fail it.
				s.WarnLog("failed to strip flag the user cannot set on COPY", "flag", string(f), "error", rmErr)
			}
		}
	}

	// The uidMap contains the mapping of original UIDs to new UIDs.
	// We need to construct the UID sets for the response.
	var sourceUIDSet, destUIDSet imap.UIDSet
	for oldUID, newUID := range uidMap {
		sourceUIDSet.AddNum(oldUID)
		destUIDSet.AddNum(newUID)
	}

	copyData := &imap.CopyData{
		UIDValidity: destMailbox.UIDValidity,
		SourceUIDs:  sourceUIDSet,
		DestUIDs:    destUIDSet,
	}

	s.DebugLog("messages copied", "from", selectedMailboxName, "to", mboxName)

	// Track for session summary
	s.messagesCopied.Add(uint32(len(uidMap)))

	return copyData, nil
}
