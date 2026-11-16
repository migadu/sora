package imap

import (
	"context"
)

// Subscribe to a mailbox (RFC 3501 §6.3.6 / RFC 9051 §6.3.7). Subscriptions are
// name-based and decoupled from mailbox existence: subscribing a name with no
// mailbox is valid and persists, and the subscription survives the mailbox's
// deletion.
func (s *IMAPSession) Subscribe(ctx context.Context, mailboxName string) error {
	return s.updateSubscriptionStatus(ctx, mailboxName, true)
}

// Unsubscribe from a mailbox.
func (s *IMAPSession) Unsubscribe(ctx context.Context, mailboxName string) error {
	return s.updateSubscriptionStatus(ctx, mailboxName, false)
}

// updateSubscriptionStatus handles both subscribe and unsubscribe against the
// name-based subscription store.
func (s *IMAPSession) updateSubscriptionStatus(ctx context.Context, mailboxName string, subscribe bool) error {
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		s.InfoLog("failed to acquire read lock")
		return s.internalError("failed to acquire lock for subscription update")
	}
	AccountID := s.AccountID()
	release()

	// Subscribe of any name — including one with no mailbox — is always persisted.
	// Unsubscribe leaves a default mailbox's subscription in place: db.Unsubscribe
	// keeps it, as only the database can tell which names are a default mailbox's.
	own := s.beginOwnTreeChange()
	defer own.end()
	change, err := s.server.rdb.UpdateSubscriptionReturningStateWithRetry(ctx, AccountID, mailboxName, subscribe)
	if err != nil {
		return s.internalError("failed to update subscription status for mailbox '%s': %v", mailboxName, err)
	}

	action := "subscribed"
	if !subscribe {
		action = "unsubscribed"
	}
	s.DebugLog("mailbox subscription changed", "mailbox", mailboxName, "action", action)
	s.useMasterDB.Store(true) // Pin session to master DB for read-your-writes consistency
	own.subscribed(change)

	return nil
}
