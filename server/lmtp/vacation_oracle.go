package lmtp

import (
	"context"
	"fmt"
	"time"

	"github.com/migadu/sora/pkg/resilient"
)

// dbVacationOracle implements the sieveengine.VacationOracle interface using the database.
type dbVacationOracle struct {
	rdb *resilient.ResilientDatabase
}

// IsVacationResponseAllowed checks if a vacation response is allowed for the given original sender and handle.
func (o *dbVacationOracle) IsVacationResponseAllowed(ctx context.Context, userID int64, originalSender string, handle string, duration time.Duration) (bool, error) {
	// Note: Current db.HasRecentVacationResponse does not take 'handle'.
	// This might require DB schema/method changes or adapting how 'handle' is stored/checked.
	// For this example, we'll ignore 'handle' for the DB check, assuming the DB stores per (userID, originalSender).
	hasRecent, err := o.rdb.HasRecentVacationResponseWithRetry(ctx, userID, originalSender, duration)
	if err != nil {
		return false, fmt.Errorf("checking db for recent vacation response: %w", err)
	}
	return !hasRecent, nil // Allowed if no recent response found
}

// RecordVacationResponseSent records that a vacation response has been sent.
func (o *dbVacationOracle) RecordVacationResponseSent(ctx context.Context, userID int64, originalSender string, handle string) error {
	// Note: Current db.RecordVacationResponse does not take 'handle'.
	// This might require DB schema/method changes or adapting how 'handle' is stored/recorded.
	// For this example, we'll ignore 'handle' for the DB recording.
	return o.rdb.RecordVacationResponseWithRetry(ctx, userID, originalSender)
}
