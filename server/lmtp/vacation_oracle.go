package lmtp

import (
	"context"
	"fmt"
	"time"

	"github.com/migadu/sora/pkg/resilient"
)

// Vacation auto-reply loop prevention works at two levels:
//
//  1. Message-level suppression (RFC 5230 §4.5) — implemented by
//     delivery.shouldSuppressVacation and invoked by the shared vacation handler:
//     null sender, Auto-Submitted, Precedence bulk/junk/list, and List-Id.
//  2. Rate-limiting via the VacationOracle below: the Sieve engine only triggers a
//     vacation action once per (account, sender, response identity) within the configured duration.

// dbVacationOracle implements the sieveengine.VacationOracle interface using the database.
type dbVacationOracle struct {
	rdb *resilient.ResilientDatabase
}

// IsVacationResponseAllowed checks if a vacation response is allowed for the given original sender and response identity.
func (o *dbVacationOracle) IsVacationResponseAllowed(ctx context.Context, AccountID int64, originalSender string, responseIdentity string, duration time.Duration) (bool, error) {
	hasRecent, err := o.rdb.HasRecentVacationResponseWithRetry(ctx, AccountID, originalSender, responseIdentity, duration)
	if err != nil {
		return false, fmt.Errorf("checking db for recent vacation response: %w", err)
	}
	return !hasRecent, nil // Allowed if no recent response found
}

// RecordVacationResponseSent records that a vacation response has been sent.
func (o *dbVacationOracle) RecordVacationResponseSent(ctx context.Context, AccountID int64, originalSender string, responseIdentity string) error {
	return o.rdb.RecordVacationResponseWithRetry(ctx, AccountID, originalSender, responseIdentity)
}

// CountRedirectsSince returns the number of redirects performed by the given account within the specified duration window.
func (o *dbVacationOracle) CountRedirectsSince(ctx context.Context, accountID int64, window time.Duration) (int, error) {
	return o.rdb.CountRedirectsSinceWithRetry(ctx, accountID, window)
}

// RecordRedirect records that a redirect action was performed.
func (o *dbVacationOracle) RecordRedirect(ctx context.Context, accountID int64) error {
	return o.rdb.RecordRedirectWithRetry(ctx, accountID)
}
