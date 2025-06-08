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
	var sessionTrackerSnapshot *imapserver.SessionTracker

	// Acquire read mutex to safely read session state
	s.mutex.RLock()
	if s.selectedMailbox == nil {
		s.mutex.RUnlock()
		s.Log("[MOVE] no mailbox selected")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "No mailbox selected",
		}
	}
	selectedMailboxID = s.selectedMailbox.ID
	selectedMailboxUIDValidity := s.selectedMailbox.UIDValidity
	sessionTrackerSnapshot = s.sessionTracker

	// Use our helper method that assumes the mutex is held (read lock is sufficient)
	decodedNumSet = s.decodeNumSetLocked(numSet)
	s.mutex.RUnlock()

	// Perform database operations outside of lock
	destMailbox, err := s.server.db.GetMailboxByName(s.ctx, s.UserID(), dest)
	if err != nil {
		s.Log("[MOVE] destination mailbox '%s' not found: %v", dest, err)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: fmt.Sprintf("destination mailbox '%s' not found", dest),
		}
	}

	// Check if the context is still valid before proceeding
	if s.ctx.Err() != nil {
		s.Log("[MOVE] context cancelled before message retrieval, aborting operation")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Session closed during move operation",
		}
	}

	messages, err := s.server.db.GetMessagesByNumSet(s.ctx, selectedMailboxID, decodedNumSet)
	if err != nil {
		return s.internalError("failed to retrieve messages: %v", err)
	}

	var sourceUIDs []imap.UID
	var seqNums []uint32

	for _, msg := range messages {
		sourceUIDs = append(sourceUIDs, msg.UID)
		seqNums = append(seqNums, uint32(msg.Seq))
	}

	// Check if the context is still valid before attempting the move
	if s.ctx.Err() != nil {
		s.Log("[MOVE] context cancelled before moving messages, aborting operation")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Session closed during move operation",
		}
	}

	messageUIDMap, err := s.server.db.MoveMessages(s.ctx, &sourceUIDs, selectedMailboxID, destMailbox.ID, s.UserID())
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
			UIDValidity: selectedMailboxUIDValidity,          // UIDVALIDITY of the source mailbox
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
			_, _, err := s.server.db.AddMessageFlags(s.ctx, uid, destMailbox.ID, []imap.Flag{imap.FlagSeen})
			if err != nil {
				s.Log("[MOVE] failed to mark message UID %d as seen in Trash: %v", uid, err)
				// Continue with other messages even if one fails
			}
		}
	}

	// Before sending expunge responses, check if context is still valid
	if s.ctx.Err() != nil {
		s.Log("[MOVE] context cancelled after moving messages, skipping expunge notifications")
		return nil
	}

	// Verify we still have a valid session tracker for expunge notifications
	if sessionTrackerSnapshot == nil {
		s.Log("[MOVE] session tracker is nil, cannot generate expunge notifications")
		return nil
	}

	// Expunge messages in the source mailbox
	for _, seqNum := range seqNums {
		sessionSeqNum := sessionTrackerSnapshot.EncodeSeqNum(seqNum)
		if sessionSeqNum > 0 { // Only write if the message was known to this session and not yet expunged by it
			if err := w.WriteExpunge(sessionSeqNum); err != nil {
				s.Log("[MOVE] error writing expunge for sessionSeqNum %d (dbSeq %d): %v", sessionSeqNum, seqNum, err)
				return s.internalError("failed to write EXPUNGE: %v", err)
			}
		} else {
			s.Log("[MOVE] message with DB seq %d not found in current session view, skipping expunge notification for it.", seqNum)
		}
	}

	return nil
}
