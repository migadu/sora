package imap

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
)

func (s *IMAPSession) Copy(ctx context.Context, numSet imap.NumSet, mboxName string) (*imap.CopyData, error) {
	ctx = s.pinnedContext(ctx)

	// The client's numbering holds still while its numbers are resolved (seqViewMu).
	s.seqViewMu.RLock()
	defer s.seqViewMu.RUnlock()

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
	view := s.seqViewLocked()
	decodedNumSet := s.decodeNumSetLocked(view, numSet)
	release()

	if imapErr := s.sharedRootDestinationRefusal("COPY", mboxName); imapErr != nil {
		return nil, imapErr
	}

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
	messages, err := s.server.rdb.GetMessagesByNumSetWithRetry(view.context(ctx), selectedMailboxID, decodedNumSet)
	if err != nil {
		return nil, s.internalError("failed to retrieve messages for copy: %v", err)
	}

	if len(messages) == 0 {
		return nil, nil
	}

	if selectedMailboxID == destMailbox.ID {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Cannot copy messages to the same mailbox",
		}
	}

	// Collect source UIDs
	var sourceUIDs []imap.UID
	for _, msg := range messages {
		sourceUIDs = append(sourceUIDs, msg.UID)
	}

	// The hash each cross-account body is made available for below. CopyMessages copies a
	// source only if it still has it, since a rekey can rename it before the INSERT.
	sourceHashes := crossAccountSourceHashes(messages, destMailbox.AccountID)
	if checkCrossAccountSourceBudget(messages, sourceHashes) != nil {
		return nil, s.crossAccountBodyLimitError("COPY")
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

	// COPY's transaction holds account-independent destination body locks before checking S3 and
	// until its rows commit, as MOVE does. A body staged locally is re-staged instead.
	type crossAccountObject struct {
		sourceKey, destKey string
		sourcePending      bool
	}
	destObjects := make(map[string]crossAccountObject)
	var destHashes []string

	for _, msg := range messages {
		if msg.AccountID == destMailbox.AccountID {
			continue // Same owner: body already lives under the correct S3 path.
		}
		// Cross-account copy: the new row will be owned by the destination mailbox
		// owner, so the body must be reachable under the owner's S3 path.
		if !msg.IsUploaded {
			if s.server.uploader == nil {
				continue
			}
			// Body is still staged locally under the source account. Hardlink it to
			// the owner's staging path so the uploader (re-staged in CopyMessages)
			// uploads it under the owner's path. Failing here would silently lose the
			// body, so treat it as fatal rather than warning and proceeding. A body
			// that is not on this node is in S3 already, or on its way there: it
			// takes the S3 path below.
			staged, ierr := s.stageCrossAccountBody("copy", msg.ContentHash, msg.AccountID, destMailbox.AccountID)
			if ierr != nil {
				return nil, ierr
			}
			if staged {
				continue
			}
		}
		// Body is in S3 under the source's path; copy it to the owner's path.
		if _, seen := destObjects[msg.ContentHash]; seen {
			continue
		}
		destObjects[msg.ContentHash] = crossAccountObject{
			sourceKey:     helpers.NewS3Key(msg.S3Domain, msg.S3Localpart, msg.ContentHash),
			destKey:       helpers.NewS3Key(destS3Domain, destS3Localpart, msg.ContentHash),
			sourcePending: !msg.IsUploaded,
		}
		destHashes = append(destHashes, msg.ContentHash)
	}

	ensureDestObject := func(ctx context.Context, contentHash string) error {
		obj := destObjects[contentHash]
		exists, err := s.server.s3.ExistsWithRetry(ctx, obj.destKey)
		if err != nil {
			s.WarnLog("failed to check if S3 object exists at destination", "destKey", obj.destKey, "error", err)
		}
		if exists {
			return nil
		}
		return s.server.s3.CopyWithRetry(ctx, obj.sourceKey, obj.destKey)
	}

	// Perform the batch copy operation
	writeCtx, ownMessagesDone := s.beginOwnMessages(ctx, destMailbox.ID)
	var copied []imap.UID
	defer func() { ownMessagesDone(copied...) }()
	uidMap, newMessageIDs, err := s.server.rdb.CopyMessagesWithRetry(writeCtx, &sourceUIDs, selectedMailboxID, destMailbox.ID, destMailbox.AccountID, destS3Domain, destS3Localpart, s.server.instanceID, sourceHashes, destHashes, ensureDestObject)
	if err != nil {
		var destErr *resilient.DestObjectError
		switch {
		case errors.As(err, &destErr):
			return nil, s.crossAccountObjectError(destObjects[destErr.ContentHash].sourcePending, destErr.Err)
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
		case errors.Is(err, db.ErrCrossAccountBodyLimit):
			return nil, s.crossAccountBodyLimitError("COPY")
		case errors.Is(err, db.ErrCopySourceChanged):
			// A source body was renamed (sora-admin import rekey) after it was made
			// available above, under the old hash. Nothing was written; a new COPY reads the
			// new hash. RFC 5530 §3: INUSE, "The operation may succeed if the client tries
			// again later."
			s.InfoLog("COPY source changed during the copy; answering retryable NO", "error", err)
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeInUse,
				Text: "Messages changed during the copy, please retry",
			}
		case strings.Contains(err.Error(), "source and destination mailboxes cannot be the same"):
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Text: "Cannot copy messages to the same mailbox",
			}
		default:
			return nil, s.internalError("failed to copy messages: %v", err)
		}
	}

	copied = slices.Collect(maps.Values(uidMap))

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
			stripCtx, chainStrip := db.ChainModSeqWindow(writeCtx, destMailbox.ID)
			if _, rmErr := s.server.rdb.RemoveMessageFlagsBatchWithRetry(stripCtx, uids, destMailbox.ID, []imap.Flag{f}); rmErr != nil {
				// The copy already succeeded; log and continue rather than fail it.
				s.WarnLog("failed to strip flag the user cannot set on COPY", "flag", string(f), "error", rmErr)
			} else {
				chainStrip()
			}
		}
	}

	copyData := &imap.CopyData{
		UIDValidity: destMailbox.UIDValidity,
		UIDMapping:  copyUIDMapping(uidMap),
	}

	s.DebugLog("messages copied", "from", selectedMailboxName, "to", mboxName)

	// Track for session summary
	s.messagesCopied.Add(uint32(len(uidMap)))

	return copyData, nil
}

// crossAccountSourceHashes maps the UID of every message a COPY or MOVE re-keys to
// destAccountID, the owner of its destination mailbox, to the message's content hash.
func crossAccountSourceHashes(messages []db.Message, destAccountID int64) map[imap.UID]string {
	hashes := make(map[imap.UID]string)
	for _, msg := range messages {
		if msg.AccountID != destAccountID {
			hashes[msg.UID] = msg.ContentHash
		}
	}
	return hashes
}

// checkCrossAccountSourceBudget includes destination-owned legacy rows whenever
// any selected row is rekeyed. The primary write transaction repeats this check
// from a fresh read under account-rekey guards before taking body locks.
func checkCrossAccountSourceBudget(messages []db.Message, rekeyed map[imap.UID]string) error {
	if len(rekeyed) == 0 {
		return nil
	}
	hashes := make(map[imap.UID]string, len(messages))
	for _, msg := range messages {
		hashes[msg.UID] = msg.ContentHash
	}
	return db.CheckCrossAccountBodies(hashes)
}

// crossAccountBodyLimitError answers a COPY or MOVE that would re-key more distinct
// source bodies into another account than db.MaxCrossAccountBodies. The budget
// includes source/destination body claims and FTS locks. Nothing was copied or moved, and a
// smaller set succeeds. RFC 5530 §3, LIMIT: "The operation ran up against an implementation
// limit of some kind".
func (s *IMAPSession) crossAccountBodyLimitError(command string) *imap.Error {
	s.InfoLog("refused a cross-account command over the body limit", "command", command, "max", db.MaxCrossAccountBodies)
	return &imap.Error{
		Type: imap.StatusResponseTypeNo,
		Code: imap.ResponseCodeLimit,
		Text: fmt.Sprintf("%s across accounts is limited to %d distinct message bodies", command, db.MaxCrossAccountBodies),
	}
}

// stageCrossAccountBody links the staging file of a body that is not uploaded yet from
// the source account's spool directory to the destination owner's, where the upload that
// CopyMessages or MoveMessages re-stages under the owner reads it. It reports false, with
// no error, when the file is not on this node: the body was staged on another backend
// and is still pending there, or its upload finished and removed the file after the
// command read the message (a read racing the upload, or a lagging replica). The caller
// then handles the body as an uploaded one, in S3.
func (s *IMAPSession) stageCrossAccountBody(command, contentHash string, srcAccountID, destAccountID int64) (bool, *imap.Error) {
	err := s.server.uploader.LinkStaged(contentHash, srcAccountID, destAccountID)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		s.InfoLog("staged body is not on this node, copying it in S3 instead", "command", command, "hash", contentHash, "source_account_id", srcAccountID)
		return false, nil
	}
	// A fault of this node's spool. The error names its files, which mean nothing to
	// the client, so the response carries only the cause.
	s.WarnLog("failed to stage body for cross-account "+command, "hash", contentHash, "error", err)
	return false, s.internalError("failed to stage message body for cross-account %s: %v", command, helpers.FileErrorCause(err))
}

// crossAccountObjectError answers a failed S3 check or copy of a cross-account body.
// notStagedHere is set for a body the command read as not uploaded and did not find in
// this node's spool: when its source object is missing too, it is staged on another
// backend whose upload is still pending, and a retry succeeds once that upload is done.
func (s *IMAPSession) crossAccountObjectError(notStagedHere bool, err error) *imap.Error {
	if notStagedHere && resilient.IsNotFoundError(err) {
		s.InfoLog("body is neither on this node nor in S3 yet, answering UNAVAILABLE", "error", err)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeUnavailable,
			Text: "Message is still being stored, please try again later",
		}
	}
	return s.internalError("failed to copy S3 object for message: %v", err)
}
