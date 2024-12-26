package imap

import (
	"context"

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
	s.mutex.Lock()
	defer s.mutex.Unlock()

	ctx := context.Background()

	// Fetch the mailbox by its full path
	mailbox, err := s.server.db.GetMailboxByName(ctx, s.UserID(), mailboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.Log("Mailbox '%s' does not exist", mailboxName)
			return nil
		}
		return s.internalError("failed to fetch mailbox '%s': %v", mailboxName, err)
	}

	// Set subscription status
	err = s.server.db.SetMailboxSubscribed(ctx, mailbox.ID, subscribe)
	if err != nil {
		return s.internalError("failed to set subscription status for mailbox '%s': %v", mailboxName, err)
	}

	action := "subscribed"
	if !subscribe {
		action = "unsubscribed"
	}
	s.Log("Mailbox '%s' %s", mailboxName, action)

	return nil
}
