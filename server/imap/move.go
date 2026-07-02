package imap

import (
	"fmt"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/helpers"
)

func (s *IMAPSession) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	// First, safely read necessary session state
	var selectedMailboxID int64
	var decodedNumSet imap.NumSet

	// Acquire read mutex to safely read session state
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.DebugLog("failed to acquire read lock within timeout")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}

	if s.selectedMailbox == nil {
		release() // Release read lock
		s.DebugLog("no mailbox selected")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "No mailbox selected",
		}
	}
	selectedMailboxID = s.selectedMailbox.ID

	// Use our helper method that assumes the mutex is held (read lock is sufficient)
	decodedNumSet = s.decodeNumSetLocked(numSet)
	release() // Release read lock

	// Perform database operations outside of lock
	destMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, s.AccountID(), dest)
	if err != nil {
		s.DebugLog("destination mailbox not found", "mailbox", dest, "error", err)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeTryCreate,
			Text: fmt.Sprintf("destination mailbox '%s' not found", dest),
		}
	}

	// Check ACL permissions in a single round trip: 'i' (insert) on the destination,
	// plus 't' (delete-msg) and 'e' (expunge) on the source. The owner fast-path in
	// has_mailbox_right() makes this cheap for the common same-owner move.
	hasInsertRight, hasDeleteRight, hasExpungeRight, err := s.server.rdb.CheckMoveRightsWithRetry(s.ctx, selectedMailboxID, destMailbox.ID, s.AccountID())
	if err != nil {
		return s.internalError("failed to check move permissions: %v", err)
	}
	if !hasInsertRight {
		s.DebugLog("user does not have insert permission on destination mailbox", "mailbox", dest)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to move messages to this mailbox",
		}
	}
	if !hasDeleteRight || !hasExpungeRight {
		s.DebugLog("user does not have delete/expunge permission on source mailbox")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to delete messages from the source mailbox",
		}
	}

	// Check if the context is still valid before proceeding
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted before message retrieval")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Session closed during move operation",
		}
	}

	messages, err := s.server.rdb.GetMessagesByNumSetWithRetry(s.ctx, selectedMailboxID, decodedNumSet)
	if err != nil {
		return s.internalError("failed to retrieve messages: %v", err)
	}

	var sourceUIDs []imap.UID
	for _, msg := range messages {
		sourceUIDs = append(sourceUIDs, msg.UID)
	}

	// Identify cross-account operations and relocate S3 objects if necessary.
	destS3Domain := s.Session.User.Domain()
	destS3Localpart := s.Session.User.LocalPart()
	if destMailbox.AccountID != s.AccountID() {
		domain, localpart, err := s.server.rdb.ResolveAccountS3Owner(s.ctx, destMailbox.AccountID)
		if err != nil {
			return s.internalError("failed to resolve owner for destination mailbox: %v", err)
		}
		destS3Domain = domain
		destS3Localpart = localpart
	}

	for _, msg := range messages {
		if msg.AccountID == destMailbox.AccountID {
			continue // Same owner: body already lives under the correct S3 path.
		}
		// Cross-account move: the new row will be owned by the destination mailbox
		// owner, so the body must be reachable under the owner's S3 path.
		if msg.IsUploaded {
			// Body is in S3 under the source's path; copy it to the owner's path
			// (skip if the owner already has it, e.g. via dedup).
			sourceKey := helpers.NewS3Key(msg.S3Domain, msg.S3Localpart, msg.ContentHash)
			destKey := helpers.NewS3Key(destS3Domain, destS3Localpart, msg.ContentHash)
			exists, err := s.server.s3.ExistsWithRetry(s.ctx, destKey)
			if err != nil {
				s.WarnLog("failed to check if S3 object exists at destination", "destKey", destKey, "error", err)
			}
			if !exists {
				if err := s.server.s3.CopyWithRetry(s.ctx, sourceKey, destKey); err != nil {
					return s.internalError("failed to copy S3 object for message: %v", err)
				}
			}
		} else if s.server.uploader != nil {
			// Body is still staged locally under the source account. Hardlink it to
			// the owner's staging path so the uploader (re-staged in MoveMessages)
			// uploads it under the owner's path. Failing here would silently lose the
			// body, so treat it as fatal rather than warning and proceeding.
			sourcePath := s.server.uploader.FilePath(msg.ContentHash, msg.AccountID)
			destPath := s.server.uploader.FilePath(msg.ContentHash, destMailbox.AccountID)
			if sourcePath != destPath {
				if err := helpers.LinkOrCopyFile(sourcePath, destPath); err != nil {
					return s.internalError("failed to stage local file for cross-account move: %v", err)
				}
			}
		}
	}

	// Check if the context is still valid before attempting the move
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted before moving messages")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Session closed during move operation",
		}
	}

	messageUIDMap, err := s.server.rdb.MoveMessagesWithRetry(s.ctx, &sourceUIDs, selectedMailboxID, destMailbox.ID, destMailbox.AccountID, destS3Domain, destS3Localpart, s.server.hostname)
	if err != nil {
		return s.internalError("failed to move messages: %v", err)
	}

	// Pin this session to the master DB (same rationale as APPEND, append.go).
	// MOVE's RFC 6851 §3.3 inline EXPUNGE notifications are emitted by the
	// post-command poll (see the NOTE below), which reads from the pinned DB.
	// Without the pin, a lagging read replica could compute that poll from stale
	// data and drop the EXPUNGEs that must precede the tagged OK. Also gives
	// read-your-writes for any subsequent command in this session.
	s.useMasterDB.Store(true)

	// Trigger spam training if configured and moving to/from Junk folder
	if s.server.spamTraining != nil && len(messageUIDMap) > 0 {
		s.triggerSpamTraining(s.ctx, destMailbox.ID, s.selectedMailbox.Name, dest, messageUIDMap)
	}

	var mappedSourceUIDs []imap.UID
	var mappedDestUIDs []imap.UID

	for originalUID, newUID := range messageUIDMap {
		mappedSourceUIDs = append(mappedSourceUIDs, imap.UID(originalUID))
		mappedDestUIDs = append(mappedDestUIDs, imap.UID(newUID))
	}

	if len(mappedSourceUIDs) > 0 && len(mappedDestUIDs) > 0 {
		copyData := &imap.CopyData{
			UIDValidity: destMailbox.UIDValidity,             // UIDVALIDITY of the destination mailbox
			SourceUIDs:  imap.UIDSetNum(mappedSourceUIDs...), // Original UIDs (source mailbox)
			DestUIDs:    imap.UIDSetNum(mappedDestUIDs...),   // New UIDs in the destination mailbox
		}

		if err := w.WriteCopyData(copyData); err != nil {
			return s.internalError("failed to write COPYUID: %v", err)
		}
	} else {
		s.DebugLog("no messages were moved, skipping COPYUID response")
	}

	// NOTE: We do NOT send EXPUNGE notifications here directly.
	//
	// go-imap calls conn.poll() (which runs sora's DB poll) BEFORE sending the
	// tagged OK response. The DB poll detects the soft-expunges from MoveMessages,
	// queues them via QueueExpunge on the tracker, and flushes them to the client.
	// This satisfies RFC 6851 §3.3 (EXPUNGE must appear before tagged OK).

	// Track for session summary
	s.messagesMoved.Add(uint32(len(messageUIDMap)))

	return nil
}
