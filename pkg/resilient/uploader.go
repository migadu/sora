package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
)

// --- Uploader Worker Wrappers ---

func (rd *ResilientDatabase) AcquireAndLeasePendingUploadsWithRetry(ctx context.Context, instanceId string, limit int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
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
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).MarkUploadAttempt(ctx, tx, contentHash, accountID)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	return err
}

func (rd *ResilientDatabase) IsContentHashUploadedWithRetry(ctx context.Context, contentHash string, accountID int64) (bool, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).IsContentHashUploaded(ctx, contentHash, accountID)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutRead, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}
