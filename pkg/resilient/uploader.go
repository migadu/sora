package resilient

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// --- Uploader Worker Wrappers ---

// ExecuteWithS3ObjectLock runs executionFunc while holding the per-object advisory lock
// that the cleaner's S3 deletion takes as well (db.GetS3ObjectLockID). Cross-account IMAP
// COPY holds it around its server-side copy; an upload only passes db.PassS3WriteGate and
// holds nothing across its transfer. The lock is held in a db.AdvisoryLockTx for exactly
// the duration of executionFunc: transaction-scoped,
// so it is released with its backend whatever pooler the write pool goes through, and
// held in a transaction that is otherwise idle and read-only, so the S3 transfer inside
// executionFunc pins one pooled connection but no write transaction, snapshot or xid.
// It waits for a current holder (a cleaner batch confirming this object is an orphan)
// for at most 30 seconds.
//
// executionFunc runs under a context that is cancelled if the lock is lost meanwhile
// (the backend died, a failover, a failed keepalive), so the S3 transfer stops rather
// than finishing unprotected; a loss noticed only after it returned is reported as an
// error.
func (rd *ResilientDatabase) ExecuteWithS3ObjectLock(ctx context.Context, contentHash string, accountID int64, executionFunc func(ctx context.Context) error) error {
	// Bounds acquiring the connection and waiting for the lock, not executionFunc.
	lockCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	lock, err := rd.getOperationalDatabaseForOperation(ctx, true).BeginAdvisoryLockTx(lockCtx)
	if err != nil {
		return err
	}
	defer lock.Release()

	if err := lock.Lock(lockCtx, db.GetS3ObjectLockID(accountID, contentHash)); err != nil {
		return err // Could not acquire lock or context was canceled
	}

	guarded, done := lock.Guard(ctx)
	defer done()
	if err := executionFunc(guarded); err != nil {
		return err
	}
	if err := lock.Err(); err != nil {
		return fmt.Errorf("S3 object lock was lost while the guarded work ran: %w", err)
	}
	return nil
}

func (rd *ResilientDatabase) AcquireAndLeasePendingUploadsWithRetry(ctx context.Context, instanceId string, limit int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).AcquireAndLeasePendingUploads(ctx, tx, instanceId, limit, retryInterval, maxAttempts)
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

func (rd *ResilientDatabase) RecordInstanceHeartbeatWithRetry(ctx context.Context, instanceID string) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).RecordInstanceHeartbeat(ctx, tx, instanceID)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	return err
}

func (rd *ResilientDatabase) MarkUploadAttemptWithRetry(ctx context.Context, contentHash string, accountID int64) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).MarkUploadAttempt(ctx, tx, contentHash, accountID)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	return err
}

func (rd *ResilientDatabase) IsContentHashUploadedWithRetry(ctx context.Context, contentHash string, accountID int64, s3Domain, s3Localpart string) (bool, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).IsContentHashUploaded(ctx, contentHash, accountID, s3Domain, s3Localpart)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutRead, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

// PendingUploadKeysWithRetry lists the S3 keys still to be written for an upload. It is
// pinned to the master: the message rows and the pending_uploads row commit in one
// transaction, and a lagging replica answering "no keys" would be read by the uploader
// as "nothing left to write" — finalizing an upload that never happened.
func (rd *ResilientDatabase) PendingUploadKeysWithRetry(ctx context.Context, contentHash string, accountID int64) ([]string, error) {
	masterCtx := context.WithValue(ctx, consts.UseMasterDBKey, true)
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).PendingUploadKeys(ctx, contentHash, accountID)
	}
	result, err := rd.executeReadWithRetry(masterCtx, cleanupRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.([]string), nil
}

// PassS3WriteGateWithRetry asks whether an upload may write its objects now and, if so,
// leases its pending row to it for ttl (see db.PassS3WriteGate). The gate reads and locks
// on the primary, where every deleter takes the same per-object lock.
func (rd *ResilientDatabase) PassS3WriteGateWithRetry(ctx context.Context, pendingID, accountID int64, contentHash string, ttl time.Duration) (db.S3WriteGate, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).PassS3WriteGate(ctx, pendingID, accountID, contentHash, ttl)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutRead, op)
	if err != nil {
		return db.S3WriteBusy, err
	}
	return result.(db.S3WriteGate), nil
}

// RenewPendingUploadLeaseWithRetry extends the lease of an upload in flight; false means
// its pending row is gone (see db.RenewPendingUploadLease).
func (rd *ResilientDatabase) RenewPendingUploadLeaseWithRetry(ctx context.Context, pendingID int64, ttl time.Duration) (bool, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).RenewPendingUploadLease(ctx, pendingID, ttl)
	}
	result, err := rd.executeReadWithRetry(ctx, leaseRetryConfig, timeoutWrite, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

// ReleasePendingUploadLeaseWithRetry ends the lease of an upload that did not finish (see
// db.ReleasePendingUploadLease).
func (rd *ResilientDatabase) ReleasePendingUploadLeaseWithRetry(ctx context.Context, pendingID int64) error {
	op := func(ctx context.Context) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).ReleasePendingUploadLease(ctx, pendingID)
	}
	_, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	return err
}

// CompleteLeasedS3UploadWithRetry finalizes an upload whose leased pending row still
// exists, and returns db.ErrPendingUploadGone, with nothing changed, when it does not
// (see db.CompleteLeasedS3Upload).
func (rd *ResilientDatabase) CompleteLeasedS3UploadWithRetry(ctx context.Context, pendingID int64, contentHash string, accountID int64, writtenKeys []string) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).CompleteLeasedS3Upload(ctx, tx, pendingID, contentHash, accountID, writtenKeys)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, importExportRetryConfig, timeoutWrite, op, db.ErrPendingUploadGone)
	return err
}

func (rd *ResilientDatabase) ResetUploadAttemptsWithRetry(ctx context.Context, contentHash string, accountID int64) (bool, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).ResetUploadAttempts(ctx, tx, contentHash, accountID)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

func (rd *ResilientDatabase) DeleteFailedUploadWithRetry(ctx context.Context, contentHash string, accountID int64) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).DeleteFailedUpload(ctx, tx, contentHash, accountID)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) PendingUploadExistsWithRetry(ctx context.Context, contentHash string, accountID int64) (bool, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).PendingUploadExists(ctx, contentHash, accountID)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutRead, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

func (rd *ResilientDatabase) PendingUploadRetryableWithRetry(ctx context.Context, contentHash string, accountID int64, maxAttempts int) (bool, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).PendingUploadRetryable(ctx, contentHash, accountID, maxAttempts)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutRead, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}
