package imap

import (
	"fmt"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Copy(numSet imap.NumSet, mboxName string) (*imap.CopyData, error) {
	// First phase: Read session state with read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.Log("[COPY] Failed to acquire read lock within timeout")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}

	if s.selectedMailbox == nil {
		release()
		s.Log("[COPY] copy failed: no mailbox selected")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "no mailbox selected",
		}
	}
	selectedMailboxID := s.selectedMailbox.ID
	selectedMailboxName := s.selectedMailbox.Name
	userID := s.UserID()
	release()

	// Use decoded numSet - this safely acquires its own read lock
	decodedNumSet := s.decodeNumSet(numSet)

	// Middle phase: Database operations outside lock
	destMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, userID, mboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.Log("[COPY] copy failed: destination mailbox '%s' does not exist", mboxName)
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeTryCreate,
				Text: fmt.Sprintf("destination mailbox '%s' does not exist", mboxName),
			}
		}
		return nil, s.internalError("failed to fetch destination mailbox '%s': %v", mboxName, err)
	}

	// Check ACL permissions - requires 'i' (insert) right on destination mailbox
	hasInsertRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, destMailbox.ID, userID, 'i')
	if err != nil {
		return nil, s.internalError("failed to check insert permission on destination: %v", err)
	}
	if !hasInsertRight {
		s.Log("[COPY] user does not have insert permission on destination mailbox '%s'", mboxName)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to copy messages to this mailbox",
		}
	}

	// Get the messages to determine their UIDs
	messages, err := s.server.rdb.GetMessagesByNumSetWithRetry(s.ctx, selectedMailboxID, decodedNumSet)
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

	// Perform the batch copy operation
	uidMap, err := s.server.rdb.CopyMessagesWithRetry(s.ctx, &sourceUIDs, selectedMailboxID, destMailbox.ID, userID)
	if err != nil {
		return nil, s.internalError("failed to copy messages: %v", err)
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

	s.Log("[COPY] messages copied from %s to %s", selectedMailboxName, mboxName)

	return copyData, nil
}
