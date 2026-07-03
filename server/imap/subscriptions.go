package imap

import (
	"context"
	"strings"

	"github.com/migadu/sora/consts"
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

	// Default mailboxes are kept permanently subscribed: ignore an unsubscribe of
	// a default name (preserves the prior SetMailboxSubscribed behavior). Subscribe
	// of any name — including one with no mailbox — is always persisted.
	if !subscribe {
		for _, def := range consts.DefaultMailboxes {
			if strings.EqualFold(mailboxName, def) {
				s.DebugLog("ignoring unsubscribe for default mailbox", "mailbox", mailboxName)
				return nil
			}
		}
	}

	var err error
	if subscribe {
		err = s.server.rdb.SubscribeWithRetry(ctx, AccountID, mailboxName)
	} else {
		err = s.server.rdb.UnsubscribeWithRetry(ctx, AccountID, mailboxName)
	}
	if err != nil {
		return s.internalError("failed to update subscription status for mailbox '%s': %v", mailboxName, err)
	}

	action := "subscribed"
	if !subscribe {
		action = "unsubscribed"
	}
	s.DebugLog("mailbox subscription changed", "mailbox", mailboxName, "action", action)
	s.useMasterDB.Store(true) // Pin session to master DB for read-your-writes consistency

	return nil
}
