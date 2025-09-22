package resilient

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/retry"
)

// --- Admin Credentials Wrappers ---

func (rd *ResilientDatabase) AddCredentialWithRetry(ctx context.Context, req db.AddCredentialRequest) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).AddCredential(ctx, tx, req)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	return err
}

func (rd *ResilientDatabase) ListCredentialsWithRetry(ctx context.Context, email string) ([]db.Credential, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).ListCredentials(ctx, email)
	}
	result, err := rd.executeReadWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	if err != nil {
		return nil, err
	}
	return result.([]db.Credential), nil
}

func (rd *ResilientDatabase) DeleteCredentialWithRetry(ctx context.Context, email string) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).DeleteCredential(ctx, tx, email)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	return err
}

func (rd *ResilientDatabase) GetCredentialDetailsWithRetry(ctx context.Context, email string) (*db.CredentialDetails, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetCredentialDetails(ctx, email)
	}
	result, err := rd.executeReadWithRetry(ctx, adminRetryConfig, timeoutAdmin, op, consts.ErrUserNotFound)
	if err != nil {
		return nil, err
	}
	return result.(*db.CredentialDetails), nil
}

// --- Admin Tool Wrappers ---

// adminRetryConfig provides a default retry strategy for short-lived admin CLI commands.
var adminRetryConfig = retry.BackoffConfig{
	InitialInterval: 250 * time.Millisecond,
	MaxInterval:     3 * time.Second,
	Multiplier:      1.8,
	Jitter:          true,
	MaxRetries:      3,
}

func (rd *ResilientDatabase) CreateAccountWithRetry(ctx context.Context, req db.CreateAccountRequest) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).CreateAccount(ctx, tx, req)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	return err
}

func (rd *ResilientDatabase) CreateAccountWithCredentialsWithRetry(ctx context.Context, req db.CreateAccountWithCredentialsRequest) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).CreateAccountWithCredentials(ctx, tx, req)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) ListAccountsWithRetry(ctx context.Context) ([]*db.AccountSummary, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).ListAccounts(ctx)
	}
	result, err := rd.executeReadWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	if err != nil {
		return nil, err
	}
	// Convert []AccountSummary to []*AccountSummary
	summaries := result.([]db.AccountSummary)
	accounts := make([]*db.AccountSummary, len(summaries))
	for i := range summaries {
		accounts[i] = &summaries[i]
	}
	return accounts, nil
}

func (rd *ResilientDatabase) GetAccountDetailsWithRetry(ctx context.Context, email string) (*db.AccountDetails, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetAccountDetails(ctx, email)
	}
	result, err := rd.executeReadWithRetry(ctx, adminRetryConfig, timeoutAdmin, op, consts.ErrUserNotFound)
	if err != nil {
		return nil, err
	}
	return result.(*db.AccountDetails), nil
}

func (rd *ResilientDatabase) UpdateAccountWithRetry(ctx context.Context, req db.UpdateAccountRequest) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).UpdateAccount(ctx, tx, req)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	return err
}

func (rd *ResilientDatabase) DeleteAccountWithRetry(ctx context.Context, email string) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).DeleteAccount(ctx, tx, email)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	return err
}

func (rd *ResilientDatabase) RestoreAccountWithRetry(ctx context.Context, email string) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).RestoreAccount(ctx, tx, email)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	return err
}

func (rd *ResilientDatabase) CleanupFailedUploadsWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).CleanupFailedUploads(ctx, tx, gracePeriod)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) InsertMessageFromImporterWithRetry(ctx context.Context, options *db.InsertMessageOptions) (messageID int64, uid int64, err error) {
	// Importer writes are less safe to retry automatically, so limit retries.
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     3 * time.Second,
		Multiplier:      1.8,
		Jitter:          true,
		MaxRetries:      2,
	}

	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		id, u, opErr := rd.getOperationalDatabaseForOperation(true).InsertMessageFromImporter(ctx, tx, options)
		if opErr != nil {
			return nil, opErr
		}
		return []int64{id, u}, nil
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, config, timeoutAdmin, op)
	if err != nil {
		return 0, 0, err
	}

	resSlice, ok := result.([]int64)
	if !ok || len(resSlice) < 2 {
		return 0, 0, errors.New("unexpected result type from importer insert")
	}

	return resSlice[0], resSlice[1], nil
}

func (rd *ResilientDatabase) CleanupSoftDeletedAccountsWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).CleanupSoftDeletedAccounts(ctx, tx, gracePeriod)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) CleanupOldVacationResponsesWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).CleanupOldVacationResponses(ctx, tx, gracePeriod)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) CleanupOldHealthStatusesWithRetry(ctx context.Context, retention time.Duration) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).CleanupOldHealthStatuses(ctx, tx, retention)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) GetUserScopedObjectsForCleanupWithRetry(ctx context.Context, gracePeriod time.Duration, batchSize int) ([]db.UserScopedObjectForCleanup, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetUserScopedObjectsForCleanup(ctx, gracePeriod, batchSize)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.([]db.UserScopedObjectForCleanup), nil
}

func (rd *ResilientDatabase) PruneOldMessageBodiesWithRetry(ctx context.Context, retention time.Duration) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).PruneOldMessageBodies(ctx, tx, retention)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) GetUnusedContentHashesWithRetry(ctx context.Context, batchSize int) ([]string, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetUnusedContentHashes(ctx, batchSize)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.([]string), nil
}

func (rd *ResilientDatabase) GetDanglingAccountsForFinalDeletionWithRetry(ctx context.Context, batchSize int) ([]int64, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetDanglingAccountsForFinalDeletion(ctx, batchSize)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.([]int64), nil
}

func (rd *ResilientDatabase) DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(ctx context.Context, candidates []db.UserScopedObjectForCleanup) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).DeleteExpungedMessagesByS3KeyPartsBatch(ctx, tx, candidates)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) DeleteMessageContentsByHashBatchWithRetry(ctx context.Context, hashes []string) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).DeleteMessageContentsByHashBatch(ctx, tx, hashes)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) FinalizeAccountDeletionsWithRetry(ctx context.Context, accountIDs []int64) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).FinalizeAccountDeletions(ctx, tx, accountIDs)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

// --- Resilient Execution Helpers ---

// executeWriteInTxWithRetry provides a generic wrapper for executing a write operation within a resilient, retriable transaction.
func (rd *ResilientDatabase) executeWriteInTxWithRetry(ctx context.Context, config retry.BackoffConfig, opType timeoutType, op func(ctx context.Context, tx pgx.Tx) (interface{}, error), nonRetryableErrors ...error) (interface{}, error) {
	var result interface{}
	err := retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		opCtx, cancel := rd.withTimeout(ctx, opType)
		defer cancel()

		res, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return op(opCtx, tx)
		})
		if cbErr != nil {
			for _, nonRetryableErr := range nonRetryableErrors {
				if errors.Is(cbErr, nonRetryableErr) {
					return retry.Stop(cbErr)
				}
			}
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

		result = res
		return nil
	}, config)
	return result, err
}

// executeReadWithRetry provides a generic wrapper for executing a read operation with retries and circuit breaker protection.
func (rd *ResilientDatabase) executeReadWithRetry(ctx context.Context, config retry.BackoffConfig, opType timeoutType, op func(ctx context.Context) (interface{}, error), nonRetryableErrors ...error) (interface{}, error) {
	var result interface{}
	err := retry.WithRetryAdvanced(ctx, func() error {
		opCtx, cancel := rd.withTimeout(ctx, opType)
		defer cancel()

		res, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return op(opCtx)
		})
		if cbErr != nil {
			for _, nonRetryableErr := range nonRetryableErrors {
				if errors.Is(cbErr, nonRetryableErr) {
					return retry.Stop(cbErr)
				}
			}
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		result = res
		return nil
	}, config)
	return result, err
}
