package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/retry"
)

// credentialChangesRetryConfig is a single attempt: every node reads credential_changes
// every few seconds, so the next read is the retry, and it resumes from the last read that
// succeeded (see credchanges.Watcher).
var credentialChangesRetryConfig = retry.BackoffConfig{
	InitialInterval: time.Second,
	MaxInterval:     time.Second,
	Multiplier:      1,
	MaxRetries:      0,
	OperationName:   "db_credential_changes",
}

// GetCredentialChangesSinceWithRetry returns the accounts whose logins changed since the
// given time (see db.GetCredentialChangesSince). One attempt only.
func (rd *ResilientDatabase) GetCredentialChangesSinceWithRetry(ctx context.Context, since time.Time) (db.CredentialChanges, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetCredentialChangesSince(ctx, since)
	}
	result, err := rd.executeReadWithRetry(ctx, credentialChangesRetryConfig, timeoutRead, op)
	if err != nil {
		return db.CredentialChanges{}, err
	}
	return result.(db.CredentialChanges), nil
}

// PruneCredentialChangesWithRetry deletes the changes recorded before the given time (see
// db.PruneCredentialChanges). One attempt only: the next prune is the retry.
func (rd *ResilientDatabase) PruneCredentialChangesWithRetry(ctx context.Context, before time.Time) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).PruneCredentialChanges(ctx, tx, before)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, credentialChangesRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}
