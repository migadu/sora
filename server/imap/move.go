package imap

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
)

func (s *IMAPSession) Move(ctx context.Context, w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	if err := s.requireCapability(imap.CapMove, "MOVE"); err != nil {
		return err
	}
	ctx = s.pinnedContext(ctx)

	// The client's numbering holds still while its numbers are resolved (seqViewMu).
	s.seqViewMu.RLock()
	defer s.seqViewMu.RUnlock()

	// First, safely read necessary session state
	var selectedMailbox *db.DBMailbox
	var selectedMailboxID int64
	var decodedNumSet imap.NumSet

	// Acquire read mutex to safely read session state
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
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
	// RFC 6851 §3.3: MOVE has the effect of COPY, STORE +FLAGS.SILENT \Deleted and
	// UID EXPUNGE, so a read-only selection refuses it as it refuses STORE and EXPUNGE
	// (RFC 9051 §6.3.3: after EXAMINE "No changes to the permanent state of the
	// mailbox ... are permitted").
	if s.selectedReadOnly.Load() {
		release()
		s.DebugLog("move rejected: mailbox selected read-only")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCode("READ-ONLY"),
			Text: "Mailbox is read-only",
		}
	}
	selectedMailbox = s.selectedMailbox
	selectedMailboxID = selectedMailbox.ID

	view := s.seqViewLocked()
	decodedNumSet = s.decodeNumSetLocked(view, numSet)
	release() // Release read lock

	if imapErr := s.sharedRootDestinationRefusal("MOVE", dest); imapErr != nil {
		return imapErr
	}

	// Perform database operations outside of lock
	destMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(ctx, s.AccountID(), dest)
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
	hasInsertRight, hasDeleteRight, hasExpungeRight, err := s.server.rdb.CheckMoveRightsWithRetry(ctx, selectedMailboxID, destMailbox.ID, s.AccountID())
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
	if ctx.Err() != nil {
		s.DebugLog("request aborted before message retrieval")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Session closed during move operation",
		}
	}

	messages, err := s.server.rdb.GetMessagesByNumSetWithRetry(view.context(ctx), selectedMailboxID, decodedNumSet)
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
		domain, localpart, err := s.server.rdb.ResolveAccountS3Owner(ctx, destMailbox.AccountID)
		if err != nil {
			return s.internalError("failed to resolve owner for destination mailbox: %v", err)
		}
		destS3Domain = domain
		destS3Localpart = localpart
	}

	// A cross-account move re-keys its rows to the destination owner's S3 path. A body
	// already in S3 must exist under that path when they commit: MoveMessagesWithRetry
	// checks or copies it (ensureDestObject) in the move's own transaction while that
	// holds the object's lock, the lock the cleaner takes before it deletes an object no
	// row it can see references, which the moved rows are not until that transaction
	// commits. A body still staged locally is linked to the owner's staging path instead,
	// for the upload MoveMessages re-stages.
	type destObject struct {
		sourceKey, destKey string
		sourcePending      bool
	}
	destObjects := make(map[string]destObject)
	var destHashes []string
	// The hash each cross-account body is made available for below. MoveMessages moves a
	// source only if it still has it, since a rekey can rename it before the rows are locked.
	sourceHashes := make(map[imap.UID]string)
	for _, msg := range messages {
		if msg.AccountID == destMailbox.AccountID {
			continue // Same owner: body already lives under the correct S3 path.
		}
		sourceHashes[msg.UID] = msg.ContentHash
		if !msg.IsUploaded {
			if s.server.uploader == nil {
				continue
			}
			// A local body is linked for the owner's pending upload. If its staging
			// file is on another node, defer the S3 fallback to the locked phase.
			staged, err := s.stageCrossAccountBody("move", msg.ContentHash, msg.AccountID, destMailbox.AccountID)
			if err != nil {
				return err
			}
			if staged {
				continue
			}
		}
		if _, seen := destObjects[msg.ContentHash]; !seen {
			destObjects[msg.ContentHash] = destObject{
				sourceKey:     helpers.NewS3Key(msg.S3Domain, msg.S3Localpart, msg.ContentHash),
				destKey:       helpers.NewS3Key(destS3Domain, destS3Localpart, msg.ContentHash),
				sourcePending: !msg.IsUploaded,
			}
			destHashes = append(destHashes, msg.ContentHash)
		}
	}

	// Check if the context is still valid before attempting the move
	if ctx.Err() != nil {
		s.DebugLog("request aborted before moving messages")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Session closed during move operation",
		}
	}

	// ensureDestObject runs while the move's transaction holds the object's lock.
	ensureDestObject := func(ctx context.Context, contentHash string) error {
		obj := destObjects[contentHash]
		exists, err := s.server.s3.ExistsWithRetry(ctx, obj.destKey)
		if err != nil {
			s.WarnLog("failed to check if S3 object exists at destination", "destKey", obj.destKey, "error", err)
		}
		if exists {
			return nil // e.g. the owner already has the body
		}
		return s.server.s3.CopyWithRetry(ctx, obj.sourceKey, obj.destKey)
	}

	writeCtx, ownMessagesDone := s.beginOwnMessages(ctx, destMailbox.ID)
	messageUIDMap, err := s.server.rdb.MoveMessagesWithRetry(writeCtx, &sourceUIDs, selectedMailboxID, destMailbox.ID, destMailbox.AccountID, destS3Domain, destS3Localpart, s.server.instanceID, sourceHashes, destHashes, ensureDestObject)
	if err != nil {
		ownMessagesDone()
		var destErr *resilient.DestObjectError
		if errors.As(err, &destErr) {
			return s.crossAccountObjectError(destObjects[destErr.ContentHash].sourcePending, destErr.Err)
		}
		if errors.Is(err, db.ErrMoveSourceChanged) {
			// A source body was renamed (sora-admin import rekey) after it was made
			// available above, under the old hash. Nothing was written; a new MOVE reads the
			// new hash. RFC 5530 §3: INUSE, "The operation may succeed if the client tries
			// again later."
			s.InfoLog("MOVE source changed during the move; answering retryable NO", "error", err)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeInUse,
				Text: "Messages changed during the move, please retry",
			}
		}
		return s.internalError("failed to move messages: %v", err)
	}
	ownMessagesDone(slices.Collect(maps.Values(messageUIDMap))...)

	// Pin this session to the master DB (same rationale as APPEND, append.go).
	// MOVE's RFC 6851 §3.3 inline EXPUNGE notifications are emitted by the
	// post-command poll (see the NOTE below), which reads from the pinned DB.
	// Without the pin, a lagging read replica could compute that poll from stale
	// data and drop the EXPUNGEs that must precede the tagged OK. Also gives
	// read-your-writes for any subsequent command in this session.
	s.useMasterDB.Store(true)

	// Trigger spam training if configured and moving to/from Junk folder
	if s.server.spamTraining != nil && len(messageUIDMap) > 0 {
		s.triggerSpamTraining(selectedMailbox, destMailbox, messages, messageUIDMap, destS3Domain, destS3Localpart)
	}

	if len(messageUIDMap) > 0 {
		copyData := &imap.CopyData{
			UIDValidity: destMailbox.UIDValidity, // UIDVALIDITY of the destination mailbox
			UIDMapping:  copyUIDMapping(messageUIDMap),
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
