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

// ExecuteWithS3ObjectLock runs executionFunc under an exclusive global content-hash
// lock. Account ID does not change its namespace; equal hashes under different S3
// keys also coordinate conservatively. It checks durable deletion intents first.
// This is a lock/claim helper, not a remote DELETE protocol: destructive body
// operations must use ExecuteWithS3BodyCleanup so uncertainty remains fenced.
//
// The callback gets a context canceled on observed holder loss and bound to this
// holder/hash. Cancellation cannot retract an accepted provider operation. SQL that
// admits an uploaded reference must take its own shared locks and synchronously
// verify overlap with this original holder, then retain those locks through commit.
// The outer read-only holder uses one pooled connection; acquiring it is bounded by
// 30 seconds, and the callback uses its caller's context.
func (rd *ResilientDatabase) ExecuteWithS3ObjectLock(ctx context.Context, contentHash string, accountID int64, executionFunc func(ctx context.Context) error) error {
	return rd.executeWithS3ObjectLocks(ctx, []string{contentHash}, func(ctx context.Context, lock *db.AdvisoryLockTx) error {
		if err := lock.Lock(ctx, db.GetS3ObjectLockID(accountID, contentHash)); err != nil {
			return err
		}
		return lock.CheckS3BodyClaims(ctx, []string{contentHash})
	}, executionFunc)
}

// ExecuteWithSharedS3ObjectLocks runs storage work under global content-hash locks
// in shared mode; accountID is compatibility metadata, not part of their namespace.
// Imports and rekey new-body writes carry the resulting exact-hash claim context
// into their own write transactions. Those transactions must acquire their shared
// locks before checking the original holder, closing the gap even when an intervening
// DELETE already completed and cleared its intent. Shared holders can overlap each
// other but exclude destructive cleanup. Lifetime and failure limits are the same
// as ExecuteWithS3ObjectLock; this helper alone is not a SQL commit fence.
func (rd *ResilientDatabase) ExecuteWithSharedS3ObjectLocks(ctx context.Context, accountID int64, contentHashes []string, executionFunc func(ctx context.Context) error) error {
	return rd.executeWithS3ObjectLocks(ctx, contentHashes, func(ctx context.Context, lock *db.AdvisoryLockTx) error {
		return lock.LockS3ObjectsShared(ctx, accountID, contentHashes)
	}, executionFunc)
}

// executeWithS3ObjectLocks opens a db.AdvisoryLockTx, takes its locks with acquire, and
// runs executionFunc while they are held (see ExecuteWithS3ObjectLock).
func (rd *ResilientDatabase) executeWithS3ObjectLocks(ctx context.Context, hashes []string, acquire func(ctx context.Context, lock *db.AdvisoryLockTx) error, executionFunc func(ctx context.Context) error) error {
	// Bounds acquiring the connection and waiting for the lock, not executionFunc.
	lockCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	lock, err := rd.getOperationalDatabaseForOperation(ctx, true).BeginAdvisoryLockTx(lockCtx)
	if err != nil {
		return err
	}
	defer lock.Release()

	if err := acquire(lockCtx, lock); err != nil {
		return err // Could not acquire lock or context was canceled
	}
	guarded, done := lock.Guard(ctx)
	defer done()
	guarded = lock.S3BodyClaimContext(guarded, hashes)
	if err := executionFunc(guarded); err != nil {
		return err
	}
	checkCtx, stopCheck := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stopCheck()
	if err := lock.Ping(checkCtx); err != nil {
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
// leases its pending row to owner alone for ttl (see db.PassS3WriteGate). The gate reads
// and locks on the primary, where every deleter takes the same per-object lock.
func (rd *ResilientDatabase) PassS3WriteGateWithRetry(ctx context.Context, pendingID, accountID int64, contentHash, owner string, ttl time.Duration) (db.S3WriteGate, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).PassS3WriteGate(ctx, pendingID, accountID, contentHash, owner, ttl)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutRead, op)
	if err != nil {
		return db.S3WriteBusy, err
	}
	return result.(db.S3WriteGate), nil
}

// RenewPendingUploadLeaseWithRetry extends owner's lease of an upload in flight; false
// means its pending row is gone or leased to someone else (see db.RenewPendingUploadLease).
func (rd *ResilientDatabase) RenewPendingUploadLeaseWithRetry(ctx context.Context, pendingID int64, owner string, ttl time.Duration) (bool, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).RenewPendingUploadLease(ctx, pendingID, owner, ttl)
	}
	result, err := rd.executeReadWithRetry(ctx, leaseRetryConfig, timeoutWrite, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

// ReleasePendingUploadLeaseWithRetry ends owner's lease of an upload that did not finish
// (see db.ReleasePendingUploadLease).
func (rd *ResilientDatabase) ReleasePendingUploadLeaseWithRetry(ctx context.Context, pendingID int64, owner string) error {
	op := func(ctx context.Context) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).ReleasePendingUploadLease(ctx, pendingID, owner)
	}
	_, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	return err
}

// CompleteLeasedS3UploadWithRetry finalizes an upload whose pending row is still leased
// to owner, and returns db.ErrUploadLeaseLost, with nothing changed, when it is not (see
// db.CompleteLeasedS3Upload).
func (rd *ResilientDatabase) CompleteLeasedS3UploadWithRetry(ctx context.Context, pendingID int64, owner, contentHash string, accountID int64, writtenKeys []string) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).CompleteLeasedS3Upload(ctx, tx, pendingID, owner, contentHash, accountID, writtenKeys)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, importExportRetryConfig, timeoutWrite, op, db.ErrUploadLeaseLost)
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

// DeleteFailedUploadWithRetry deletes a parked upload whose body is lost, and its unuploaded
// message rows, unless the row was re-armed or is leased meanwhile (see
// db.DeleteFailedUpload).
func (rd *ResilientDatabase) DeleteFailedUploadWithRetry(ctx context.Context, contentHash string, accountID int64, maxAttempts int) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).DeleteFailedUpload(ctx, tx, contentHash, accountID, maxAttempts)
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
