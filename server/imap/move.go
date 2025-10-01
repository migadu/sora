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
		s.Log("[MOVE] Failed to acquire read lock within timeout")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}

	if s.selectedMailbox == nil {
		release() // Release read lock
		s.Log("[MOVE] no mailbox selected")
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
	destMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, s.UserID(), dest)
	if err != nil {
		s.Log("[MOVE] destination mailbox '%s' not found: %v", dest, err)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeTryCreate,
			Text: fmt.Sprintf("destination mailbox '%s' not found", dest),
		}
	}

	// Check if the context is still valid before proceeding
	if s.ctx.Err() != nil {
		s.Log("[MOVE] request aborted before message retrieval, aborting operation")
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
		s.Log("[MOVE] request aborted before moving messages, aborting operation")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Session closed during move operation",
		}
	}

	messageUIDMap, err := s.server.rdb.MoveMessagesWithRetry(s.ctx, &sourceUIDs, selectedMailboxID, destMailbox.ID, s.UserID())
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
		s.Log("[MOVE] no messages were moved (potentially already expunged), skipping COPYUID response")
	}

	isTrashFolder := strings.EqualFold(dest, "Trash") || dest == consts.MailboxTrash
	if isTrashFolder && len(mappedDestUIDs) > 0 {
		s.Log("[MOVE] automatically marking %d moved messages as seen in Trash folder", len(mappedDestUIDs))

		for _, uid := range mappedDestUIDs {
			_, _, err := s.server.rdb.AddMessageFlagsWithRetry(s.ctx, uid, destMailbox.ID, []imap.Flag{imap.FlagSeen})
			if err != nil {
				s.Log("[MOVE] failed to mark message UID %d as seen in Trash: %v", uid, err)
				// Continue with other messages even if one fails
			}
		}
	}

	return nil
}
