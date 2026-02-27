package imap

import (
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/consts"
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

	// Check ACL permissions on destination - requires 'i' (insert) right
	hasInsertRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, destMailbox.ID, s.AccountID(), 'i')
	if err != nil {
		return s.internalError("failed to check insert permission on destination: %v", err)
	}
	if !hasInsertRight {
		s.DebugLog("user does not have insert permission on destination mailbox", "mailbox", dest)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to move messages to this mailbox",
		}
	}

	// Check ACL permissions on source - requires 't' (delete-msg) and 'e' (expunge) rights
	hasDeleteRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, selectedMailboxID, s.AccountID(), 't')
	if err != nil {
		return s.internalError("failed to check delete permission on source: %v", err)
	}
	hasExpungeRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, selectedMailboxID, s.AccountID(), 'e')
	if err != nil {
		return s.internalError("failed to check expunge permission on source: %v", err)
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

	// Check if the context is still valid before attempting the move
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted before moving messages")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Session closed during move operation",
		}
	}

	messageUIDMap, err := s.server.rdb.MoveMessagesWithRetry(s.ctx, &sourceUIDs, selectedMailboxID, destMailbox.ID, s.AccountID())
	if err != nil {
		return s.internalError("failed to move messages: %v", err)
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

	isTrashFolder := strings.EqualFold(dest, "Trash") || dest == consts.MailboxTrash
	if isTrashFolder && len(mappedDestUIDs) > 0 {
		s.DebugLog("automatically marking moved messages as seen in Trash folder", "count", len(mappedDestUIDs))

		for _, uid := range mappedDestUIDs {
			_, _, err := s.server.rdb.AddMessageFlagsWithRetry(s.ctx, uid, destMailbox.ID, []imap.Flag{imap.FlagSeen})
			if err != nil {
				s.DebugLog("failed to mark message as seen in Trash", "uid", uid, "error", err)
			}
		}
	}

	// RFC 6851 §3.3: MOVE MUST include EXPUNGE notifications for the removed messages
	// before the tagged OK response. Sequence numbers must be reported in descending order
	// because each EXPUNGE causes renumbering of higher sequence numbers.
	if len(messages) > 0 {
		// Collect sequence numbers of moved messages and sort descending
		seqNums := make([]uint32, 0, len(messages))
		for _, msg := range messages {
			// Only include messages that were actually moved (present in the UID map)
			if _, ok := messageUIDMap[msg.UID]; ok {
				seqNums = append(seqNums, msg.Seq)
			}
		}

		// Sort descending — each EXPUNGE renumbers, so highest first
		for i, j := 0, len(seqNums)-1; i < j; i, j = i+1, j-1 {
			seqNums[i], seqNums[j] = seqNums[j], seqNums[i]
		}

		// Use the session tracker to queue expunge events. This ensures:
		// 1. The tracker's internal message count is decremented correctly
		// 2. EXPUNGE notifications are sent to the client when flushed
		// 3. No tracker desync on next poll (which would force disconnection)
		// We previously used w.WriteExpunge() which bypassed the tracker.
		if s.mailboxTracker != nil {
			for _, seq := range seqNums {
				s.mailboxTracker.QueueExpunge(seq)
			}
		} else {
			// Fallback: write directly if no tracker (shouldn't happen in normal operation)
			for _, seq := range seqNums {
				if err := w.WriteExpunge(seq); err != nil {
					s.DebugLog("failed to write EXPUNGE", "seq", seq, "error", err)
				}
			}
		}

		// Update session message count to match
		current := s.currentNumMessages.Load()
		removed := uint32(len(seqNums))
		if removed > current {
			removed = current
		}
		s.currentNumMessages.Store(current - removed)
		s.DebugLog("sent EXPUNGE notifications for moved messages", "count", len(seqNums))
	}

	// Track for session summary
	s.messagesMoved.Add(uint32(len(messageUIDMap)))

	return nil
}
