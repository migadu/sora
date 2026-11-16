package delivery

import (
	"context"
	"errors"
	"fmt"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/sieveengine"
)

// ResolvedSieveDestination binds a copy's flags to the physical mailbox resolved
// for this delivery. Storage uses Target directly, without looking its name up again.
type ResolvedSieveDestination struct {
	sieveengine.Destination
	Target *db.DBMailbox
}

// ResolveSieveDestinations runs after size checks and body staging. Complete all
// requested :create actions first, then group actual mailbox IDs (including ACL
// and missing-target fallbacks), retaining the last explicit action's flags.
func ResolveSieveDestinations(ctx context.Context, rdb *resilient.ResilientDatabase, shared config.SharedMailboxesConfig, accountID int64, result sieveengine.Result, redirectFailed bool, log func(string, ...any)) ([]ResolvedSieveDestination, error) {
	ctx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	for _, name := range result.CreateMailboxes {
		if normalized, err := helpers.MailboxNameToCreate(name); err == nil {
			name = normalized
		}
		if _, err := resolveFileintoMailbox(ctx, rdb, shared, accountID, name, true, log); err != nil {
			return nil, err
		}
	}
	targets := make(map[string]*db.DBMailbox)
	dests, err := result.DestinationsByKey(redirectFailed, func(name string, _ bool) (string, error) {
		target := targets[name]
		if target == nil {
			var err error
			target, err = resolveFileintoMailbox(ctx, rdb, shared, accountID, name, false, log)
			if err != nil {
				return "", err
			}
			targets[name] = target
		}
		return fmt.Sprintf("%d:%d", target.AccountID, target.ID), nil
	})
	if err != nil {
		return nil, err
	}
	resolved := make([]ResolvedSieveDestination, len(dests))
	for i, dest := range dests {
		resolved[i] = ResolvedSieveDestination{Destination: dest, Target: targets[dest.Mailbox]}
	}
	return resolved, nil
}

// resolveFileintoMailbox shares the existing target/create/ACL/fallback policy
// between both storage paths; owner resolution and staging remain in their saves.
func resolveFileintoMailbox(ctx context.Context, rdb *resilient.ResilientDatabase, shared config.SharedMailboxesConfig, accountID int64, name string, create bool, log func(string, ...any)) (*db.DBMailbox, error) {
	mailbox, err := FileintoTarget(ctx, rdb, shared, accountID, name)
	if errors.Is(err, consts.ErrMailboxNotFound) && create && !shared.InNamespace(name) {
		mailbox, err = rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, name)
		if errors.Is(err, consts.ErrMailboxInvalidName) {
			err = consts.ErrMailboxNotFound
		}
	}
	if err != nil && !errors.Is(err, consts.ErrMailboxNotFound) {
		return nil, err
	}
	reason := err
	if err == nil && mailbox.AccountID != accountID {
		allowed, permErr := rdb.CheckMailboxPermissionWithRetry(ctx, mailbox.ID, accountID, db.ACLRightInsert)
		if permErr != nil || !allowed {
			reason = permErr
			err = consts.ErrMailboxNotFound
		}
	}
	if errors.Is(err, consts.ErrMailboxNotFound) {
		if log != nil {
			log("Sieve fileinto %q is unavailable or has no insert right; keeping in INBOX (err=%v)", name, reason)
		}
		return rdb.GetMailboxByNameWithRetry(ctx, accountID, consts.MailboxInbox)
	}
	return mailbox, nil
}
