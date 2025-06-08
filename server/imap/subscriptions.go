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
	s.mutex.RLock()
	userID := s.UserID()
	s.mutex.RUnlock()

	// Middle phase: Database operations outside lock
	mailbox, err := s.server.db.GetMailboxByName(s.ctx, userID, mailboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.Log("Mailbox '%s' does not exist", mailboxName)
			return nil
		}
		return s.internalError("failed to fetch mailbox '%s': %v", mailboxName, err)
	}

	// Final phase: Update subscription - no locks needed as it's a DB operation
	err = s.server.db.SetMailboxSubscribed(s.ctx, mailbox.ID, userID, subscribe)
	if err != nil {
		return s.internalError("failed to set subscription status for mailbox '%s': %v", mailboxName, err)
	}

	action := "subscribed"
	if !subscribe {
		action = "unsubscribed"
	}
	s.Log("[SUBSCRIBE] mailbox '%s' %s", mailboxName, action)

	return nil
}
