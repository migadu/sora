package imap

import (
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Delete(mboxName string) error {
	// First phase: Read-only validation with read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.Log("[DELETE] Failed to acquire read lock")
		return s.internalError("failed to acquire lock for delete")
	}
	userID := s.UserID()
	release()

	// Check if special mailbox - no lock needed
	for _, specialMailbox := range consts.DefaultMailboxes {
		if strings.EqualFold(mboxName, specialMailbox) {
			s.Log("[DELETE] attempt to delete special mailbox '%s'", mboxName)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNoPerm,
				Text: fmt.Sprintf("Mailbox '%s' is a special mailbox and cannot be deleted", mboxName),
			}
		}
	}

	// Middle phase: Database operations outside lock
	mailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, userID, mboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.Log("[DELETE] mailbox '%s' not found", mboxName)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("Mailbox '%s' not found", mboxName),
			}
		}
		return s.internalError("failed to fetch mailbox '%s': %v", mboxName, err)
	}

	// RFC 3501 Section 6.3.4: It is an error to delete a mailbox that has
	// inferior hierarchical names.
	if mailbox.HasChildren {
		s.Log("[DELETE] attempt to delete mailbox '%s' which has children", mboxName)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: fmt.Sprintf("Mailbox '%s' has children and cannot be deleted.", mboxName),
		}
	}

	// Final phase: actual deletion - no locks needed as it's a DB operation
	err = s.server.rdb.DeleteMailboxWithRetry(s.ctx, mailbox.ID, userID)
	if err != nil {
		return s.internalError("failed to delete mailbox '%s': %v", mboxName, err)
	}

	s.Log("[DELETE] mailbox deleted: %s", mboxName)
	return nil
}
