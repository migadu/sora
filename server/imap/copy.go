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

	messages, err := s.server.rdb.GetMessagesByNumSetWithRetry(s.ctx, selectedMailboxID, decodedNumSet)
	if err != nil {
		return nil, s.internalError("failed to retrieve messages for copy: %v", err)
	}

	var sourceUIDs imap.UIDSet
	var destUIDs imap.UIDSet

	if len(messages) == 0 {
		return nil, nil
	}

	for _, msg := range messages {
		sourceUIDs.AddNum(msg.UID)
		copiedUID, err := s.server.rdb.InsertMessageCopyWithRetry(s.ctx, msg.UID, msg.MailboxID, destMailbox.ID, destMailbox.Name)
		if err != nil {
			return nil, s.internalError("failed to insert copied message: %v", err)
		}
		destUIDs.AddNum(imap.UID(copiedUID))
	}

	if len(sourceUIDs) == 0 || len(destUIDs) == 0 {
		return nil, nil
	}

	copyData := &imap.CopyData{
		UIDValidity: destMailbox.UIDValidity,
		SourceUIDs:  sourceUIDs,
		DestUIDs:    destUIDs,
	}

	s.Log("[COPY] messages copied from %s to %s", selectedMailboxName, mboxName)

	return copyData, nil
}
