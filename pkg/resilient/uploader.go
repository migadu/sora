package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/retry"
)

// --- Uploader Worker Wrappers ---

func (rd *ResilientDatabase) AcquireAndLeasePendingUploadsWithRetry(ctx context.Context, instanceId string, limit int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error) {
	var uploads []db.PendingUpload
	err := retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		writeCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
		defer cancel()

		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(true).AcquireAndLeasePendingUploads(writeCtx, tx, instanceId, limit, retryInterval, maxAttempts)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}

		if err := tx.Commit(ctx); err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}

		if result != nil {
			uploads = result.([]db.PendingUpload)
		} else {
			uploads = nil
		}
		return nil
	}, cleanupRetryConfig)
	return uploads, err
}

func (rd *ResilientDatabase) MarkUploadAttemptWithRetry(ctx context.Context, contentHash string, accountID int64) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		writeCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
		defer cancel()

		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabaseForOperation(true).MarkUploadAttempt(writeCtx, tx, contentHash, accountID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}

		if err := tx.Commit(ctx); err != nil {
			return err
		}

		return nil
	}, cleanupRetryConfig)
}

func (rd *ResilientDatabase) IsContentHashUploadedWithRetry(ctx context.Context, contentHash string, accountID int64) (bool, error) {
	var isUploaded bool
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).IsContentHashUploaded(readCtx, contentHash, accountID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		isUploaded = result.(bool)
		return nil
	}, cleanupRetryConfig)
	return isUploaded, err
}
