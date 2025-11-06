package imap

import (
	"github.com/migadu/sora/consts"
)

// Subscribe to a mailbox
func (s *IMAPSession) Subscribe(mailboxName string) error {
	return s.updateSubscriptionStatus(mailboxName, true)
}

// Unsubscribe from a mailbox
func (s *IMAPSession) Unsubscribe(mailboxName string) error {
	return s.updateSubscriptionStatus(mailboxName, false)
}

// Helper function to handle both subscribe and unsubscribe logic
func (s *IMAPSession) updateSubscriptionStatus(mailboxName string, subscribe bool) error {
	// First phase: Read validation with read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.InfoLog("[SUBSCRIBE/UNSUBSCRIBE] Failed to acquire read lock")
		return s.internalError("failed to acquire lock for subscription update")
	}
	AccountID := s.AccountID()
	release()

	// Middle phase: Database operations outside lock
	mailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, AccountID, mailboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.InfoLog("Mailbox '%s' does not exist", mailboxName)
			return nil
		}
		return s.internalError("failed to fetch mailbox '%s': %v", mailboxName, err)
	}

	// Final phase: Update subscription - no locks needed as it's a DB operation
	err = s.server.rdb.SetMailboxSubscribedWithRetry(s.ctx, mailbox.ID, AccountID, subscribe)
	if err != nil {
		return s.internalError("failed to set subscription status for mailbox '%s': %v", mailboxName, err)
	}

	action := "subscribed"
	if !subscribe {
		action = "unsubscribed"
	}
	s.DebugLog("[SUBSCRIBE] mailbox '%s' %s", mailboxName, action)

	return nil
}
