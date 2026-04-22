package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
)

// --- Uploader Worker Wrappers ---

// ExecuteWithS3ObjectSessionLock uses a session-level advisory lock via a dedicated DB connection.
// This allows the lock (and execution) to happen safely over long-running operations (like S3 transfers)
// without holding open a PostgreSQL transaction, entirely avoiding database bloat and vacuum blockages.
func (rd *ResilientDatabase) ExecuteWithS3ObjectSessionLock(ctx context.Context, contentHash string, accountID int64, executionFunc func() error) error {
	pool := rd.getOperationalDatabaseForOperation(true).GetWritePool()

	// Use a 30s timeout purely for acquiring the connection and the lock
	lockCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	conn, err := pool.Acquire(lockCtx)
	if err != nil {
		return err
	}
	defer conn.Release()

	lockID := db.GetS3ObjectLockID(accountID, contentHash)
	_, err = conn.Exec(lockCtx, "SELECT pg_advisory_lock($1)", lockID)
	if err != nil {
		return err // Could not acquire lock or context was canceled
	}

	defer func() {
		// Use a detached background context to absolutely guarantee the unlock fires
		// even if the incoming context is canceled or expired.
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", lockID)
	}()

	// Execute the operation
	return executionFunc()
}

func (rd *ResilientDatabase) AcquireAndLeasePendingUploadsWithRetry(ctx context.Context, instanceId string, limit int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(true).AcquireAndLeasePendingUploads(ctx, tx, instanceId, limit, retryInterval, maxAttempts)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.([]db.PendingUpload), nil
}

func (rd *ResilientDatabase) MarkUploadAttemptWithRetry(ctx context.Context, contentHash string, accountID int64) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).MarkUploadAttempt(ctx, tx, contentHash, accountID)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	return err
}

func (rd *ResilientDatabase) IsContentHashUploadedWithRetry(ctx context.Context, contentHash string, accountID int64) (bool, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).IsContentHashUploaded(ctx, contentHash, accountID)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutRead, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

func (rd *ResilientDatabase) ExhaustUploadAttemptsWithRetry(ctx context.Context, contentHash string, accountID int64, maxAttempts int) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).ExhaustUploadAttempts(ctx, tx, contentHash, accountID, maxAttempts)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	return err
}

func (rd *ResilientDatabase) DeleteFailedUploadWithRetry(ctx context.Context, contentHash string, accountID int64) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(true).DeleteFailedUpload(ctx, tx, contentHash, accountID)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) PendingUploadExistsWithRetry(ctx context.Context, contentHash string, accountID int64) (bool, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).PendingUploadExists(ctx, contentHash, accountID)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutRead, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}
