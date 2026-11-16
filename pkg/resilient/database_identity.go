package resilient

import (
	"context"

	"github.com/migadu/sora/db"
)

// GetDatabaseIdentityWithRetry reads the persisted identity from the operational
// primary, never from a possibly stale or independently configured read replica.
// It does not cache or manufacture an identity when the primary cannot provide it.
func (rd *ResilientDatabase) GetDatabaseIdentityWithRetry(ctx context.Context) (string, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).GetDatabaseIdentity(ctx)
	}
	result, err := rd.executeReadWithRetry(ctx, adminRetryConfig, timeoutAdmin, op, db.ErrDatabaseIdentityUnavailable)
	if err != nil {
		return "", err
	}
	return result.(string), nil
}
