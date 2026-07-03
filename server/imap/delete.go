package imap

import (
	"context"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Delete(ctx context.Context, mboxName string) error {
	// First phase: Read-only validation with read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		s.DebugLog("failed to acquire read lock")
		return s.internalError("failed to acquire lock for delete")
	}
	AccountID := s.AccountID()
	release()

	// Check if special mailbox - no lock needed
	for _, specialMailbox := range consts.DefaultMailboxes {
		if strings.EqualFold(mboxName, specialMailbox) {
			s.DebugLog("attempt to delete special mailbox", "mailbox", mboxName)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNoPerm,
				Text: fmt.Sprintf("Mailbox '%s' is a special mailbox and cannot be deleted", mboxName),
			}
		}
	}

	// Middle phase: Database operations outside lock
	mailbox, err := s.server.rdb.GetMailboxByNameWithRetry(ctx, AccountID, mboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.DebugLog("mailbox not found", "mailbox", mboxName)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("Mailbox '%s' not found", mboxName),
			}
		}
		return s.internalError("failed to fetch mailbox '%s': %v", mboxName, err)
	}

	// Check ACL permissions - requires 'x' (delete) right
	hasDeleteRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(ctx, mailbox.ID, AccountID, 'x')
	if err != nil {
		return s.internalError("failed to check delete permission: %v", err)
	}
	if !hasDeleteRight {
		s.DebugLog("user does not have delete permission on mailbox", "mailbox", mboxName)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to delete this mailbox",
		}
	}

	// RFC 3501 Section 6.3.4: It is an error to delete a mailbox that has
	// inferior hierarchical names.
	if mailbox.HasChildren {
		s.DebugLog("attempt to delete mailbox which has children", "mailbox", mboxName)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: fmt.Sprintf("Mailbox '%s' has children and cannot be deleted.", mboxName),
		}
	}

	// Final phase: two-phase deletion. Mark the mailbox deleted (O(1) single-row
	// update) and return immediately; the background cleaner expunges its messages
	// and removes the row. This keeps DELETE off the per-mailbox lock for the whole
	// bulk expunge, which previously drove DELETE P99 to ~1 minute on large folders.
	// Use mailbox.AccountID (the owner) not AccountID (the requester) for shared mailbox support.
	err = s.server.rdb.SoftDeleteMailboxWithRetry(ctx, mailbox.ID, mailbox.AccountID)
	if err != nil {
		return s.internalError("failed to delete mailbox '%s': %v", mboxName, err)
	}

	s.DebugLog("mailbox soft-deleted (pending background purge)", "mailbox", mboxName)
	s.useMasterDB.Store(true) // Pin session to master DB for read-your-writes consistency
	return nil
}
