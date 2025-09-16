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
	return retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		adminCtx, cancel := rd.withTimeout(ctx, timeoutAdmin)
		defer cancel()

		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			// Assuming db.AddCredential is refactored to accept a transaction.
			return nil, rd.getOperationalDatabaseForOperation(true).AddCredential(adminCtx, tx, req)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}

		if err := tx.Commit(ctx); err != nil {
			return err // Let retry logic handle commit errors
		}

		return nil
	}, adminRetryConfig)
}

func (rd *ResilientDatabase) ListCredentialsWithRetry(ctx context.Context, email string) ([]db.Credential, error) {
	var credentials []db.Credential
	err := retry.WithRetryAdvanced(ctx, func() error {
		adminCtx, cancel := rd.withTimeout(ctx, timeoutAdmin)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).ListCredentials(adminCtx, email)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			credentials = result.([]db.Credential)
		} else {
			credentials = nil
		}
		return nil
	}, adminRetryConfig)
	return credentials, err
}

func (rd *ResilientDatabase) DeleteCredentialWithRetry(ctx context.Context, email string) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		adminCtx, cancel := rd.withTimeout(ctx, timeoutAdmin)
		defer cancel()

		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			// Assuming db.DeleteCredential is refactored to accept a transaction.
			return nil, rd.getOperationalDatabaseForOperation(true).DeleteCredential(adminCtx, tx, email)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}

		if err := tx.Commit(ctx); err != nil {
			return err // Let retry logic handle commit errors
		}

		return nil
	}, adminRetryConfig)
}

func (rd *ResilientDatabase) GetCredentialDetailsWithRetry(ctx context.Context, email string) (*db.CredentialDetails, error) {
	var details *db.CredentialDetails
	err := retry.WithRetryAdvanced(ctx, func() error {
		adminCtx, cancel := rd.withTimeout(ctx, timeoutAdmin)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetCredentialDetails(adminCtx, email)
		})
		if cbErr != nil {
			if errors.Is(cbErr, consts.ErrUserNotFound) {
				return retry.Stop(cbErr)
			}
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			details = result.(*db.CredentialDetails)
		} else {
			details = nil
		}
		return nil
	}, adminRetryConfig)
	return details, err
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
	return retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		adminCtx, cancel := rd.withTimeout(ctx, timeoutAdmin)
		defer cancel()

		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			// Assuming db.CreateAccount is refactored to accept a transaction.
			return nil, rd.getOperationalDatabaseForOperation(true).CreateAccount(adminCtx, tx, req)
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

		return nil
	}, adminRetryConfig)
}

func (rd *ResilientDatabase) CreateAccountWithCredentialsWithRetry(ctx context.Context, req db.CreateAccountWithCredentialsRequest) (int64, error) {
	var accountID int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		adminCtx, cancel := rd.withTimeout(ctx, timeoutAdmin)
		defer cancel()

		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(true).CreateAccountWithCredentials(adminCtx, tx, req)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}

		accountID = result.(int64)

		if err := tx.Commit(ctx); err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}

		return nil
	}, adminRetryConfig)
	
	return accountID, err
}

func (rd *ResilientDatabase) ListAccountsWithRetry(ctx context.Context) ([]*db.AccountSummary, error) {
	var accounts []*db.AccountSummary
	err := retry.WithRetryAdvanced(ctx, func() error {
		adminCtx, cancel := rd.withTimeout(ctx, timeoutAdmin)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).ListAccounts(adminCtx)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			// Convert []AccountSummary to []*AccountSummary
			summaries := result.([]db.AccountSummary)
			accounts = make([]*db.AccountSummary, len(summaries))
			for i := range summaries {
				accounts[i] = &summaries[i]
			}
		} else {
			accounts = nil
		}
		return nil
	}, adminRetryConfig)
	return accounts, err
}

func (rd *ResilientDatabase) GetAccountDetailsWithRetry(ctx context.Context, email string) (*db.AccountDetails, error) {
	var details *db.AccountDetails
	err := retry.WithRetryAdvanced(ctx, func() error {
		adminCtx, cancel := rd.withTimeout(ctx, timeoutAdmin)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetAccountDetails(adminCtx, email)
		})
		if cbErr != nil {
			if errors.Is(cbErr, consts.ErrUserNotFound) {
				return retry.Stop(cbErr)
			}
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			details = result.(*db.AccountDetails)
		} else {
			details = nil
		}
		return nil
	}, adminRetryConfig)
	return details, err
}

func (rd *ResilientDatabase) UpdateAccountWithRetry(ctx context.Context, req db.UpdateAccountRequest) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		adminCtx, cancel := rd.withTimeout(ctx, timeoutAdmin)
		defer cancel()

		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			// Assuming db.UpdateAccount is refactored to accept a transaction.
			return nil, rd.getOperationalDatabaseForOperation(true).UpdateAccount(adminCtx, tx, req)
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

		return nil
	}, adminRetryConfig)
}

func (rd *ResilientDatabase) DeleteAccountWithRetry(ctx context.Context, email string) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		adminCtx, cancel := rd.withTimeout(ctx, timeoutAdmin)
		defer cancel()

		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			// Assuming db.DeleteAccount is refactored to accept a transaction.
			return nil, rd.getOperationalDatabaseForOperation(true).DeleteAccount(adminCtx, tx, email)
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

		return nil
	}, adminRetryConfig)
}

func (rd *ResilientDatabase) RestoreAccountWithRetry(ctx context.Context, email string) error {
	return retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		adminCtx, cancel := rd.withTimeout(ctx, timeoutAdmin)
		defer cancel()

		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			// Assuming db.RestoreAccount is refactored to accept a transaction.
			return nil, rd.getOperationalDatabaseForOperation(true).RestoreAccount(adminCtx, tx, email)
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

		return nil
	}, adminRetryConfig)
}

func (rd *ResilientDatabase) CleanupFailedUploadsWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	var count int64
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
			return rd.getOperationalDatabaseForOperation(true).CleanupFailedUploads(writeCtx, tx, gracePeriod)
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

		count = result.(int64)
		return nil
	}, cleanupRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) InsertMessageFromImporterWithRetry(ctx context.Context, options *db.InsertMessageOptions) (messageID int64, uid int64, err error) {
	config := retry.BackoffConfig{MaxRetries: 2} // Writes are less safe to retry automatically
	err = retry.WithRetry(ctx, func() error {
		// Begin a resilient transaction.
		tx, txErr := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if txErr != nil {
			if rd.isRetryableError(txErr) {
				return txErr
			}
			return retry.Stop(txErr)
		}
		defer tx.Rollback(ctx)

		// Use admin timeout for importer operations
		adminCtx, cancel := rd.withTimeout(ctx, timeoutAdmin)
		defer cancel()

		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			// Pass the transaction to the refactored db method.
			messageID, uid, err = rd.getOperationalDatabaseForOperation(true).InsertMessageFromImporter(adminCtx, tx, options)
			return nil, err
		})

		if cbErr != nil {
			if rd.isRetryableError(cbErr) {
				return cbErr // Retry the whole transaction.
			}
			return retry.Stop(cbErr)
		}

		// Commit the transaction.
		if commitErr := tx.Commit(ctx); commitErr != nil {
			if rd.isRetryableError(commitErr) {
				return commitErr // Retry on commit failure.
			}
			return retry.Stop(commitErr)
		}

		return nil
	}, config)
	return messageID, uid, err
}

func (rd *ResilientDatabase) CleanupSoftDeletedAccountsWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	var count int64
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
			return rd.getOperationalDatabaseForOperation(true).CleanupSoftDeletedAccounts(writeCtx, tx, gracePeriod)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}

		if err := tx.Commit(ctx); err != nil {
			return err // Let retry logic handle commit errors
		}

		count = result.(int64)
		return nil
	}, cleanupRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) CleanupOldVacationResponsesWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	var count int64
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
			return rd.getOperationalDatabaseForOperation(true).CleanupOldVacationResponses(writeCtx, tx, gracePeriod)
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

		count = result.(int64)
		return nil
	}, cleanupRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) CleanupOldHealthStatusesWithRetry(ctx context.Context, retention time.Duration) (int64, error) {
	var count int64
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
			return rd.getOperationalDatabaseForOperation(true).CleanupOldHealthStatuses(writeCtx, tx, retention)
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

		count = result.(int64)
		return nil
	}, cleanupRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) GetUserScopedObjectsForCleanupWithRetry(ctx context.Context, gracePeriod time.Duration, batchSize int) ([]db.UserScopedObjectForCleanup, error) {
	var candidates []db.UserScopedObjectForCleanup
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetUserScopedObjectsForCleanup(readCtx, gracePeriod, batchSize)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			candidates = result.([]db.UserScopedObjectForCleanup)
		} else {
			candidates = nil
		}
		return nil
	}, cleanupRetryConfig)
	return candidates, err
}

func (rd *ResilientDatabase) PruneOldMessageBodiesWithRetry(ctx context.Context, retention time.Duration) (int64, error) {
	var count int64
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
			return rd.getOperationalDatabaseForOperation(true).PruneOldMessageBodies(writeCtx, tx, retention)
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
		count = result.(int64)
		return nil
	}, cleanupRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) GetUnusedContentHashesWithRetry(ctx context.Context, batchSize int) ([]string, error) {
	var hashes []string
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetUnusedContentHashes(readCtx, batchSize)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			hashes = result.([]string)
		} else {
			hashes = nil
		}
		return nil
	}, cleanupRetryConfig)
	return hashes, err
}

func (rd *ResilientDatabase) GetDanglingAccountsForFinalDeletionWithRetry(ctx context.Context, batchSize int) ([]int64, error) {
	var accounts []int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetDanglingAccountsForFinalDeletion(readCtx, batchSize)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			accounts = result.([]int64)
		} else {
			accounts = nil
		}
		return nil
	}, cleanupRetryConfig)
	return accounts, err
}

func (rd *ResilientDatabase) DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(ctx context.Context, candidates []db.UserScopedObjectForCleanup) (int64, error) {
	var count int64
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
			return rd.getOperationalDatabaseForOperation(true).DeleteExpungedMessagesByS3KeyPartsBatch(writeCtx, tx, candidates)
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

		count = result.(int64)
		return nil
	}, cleanupRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) DeleteMessageContentsByHashBatchWithRetry(ctx context.Context, hashes []string) (int64, error) {
	var count int64
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
			return rd.getOperationalDatabaseForOperation(true).DeleteMessageContentsByHashBatch(writeCtx, tx, hashes)
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

		count = result.(int64)
		return nil
	}, cleanupRetryConfig)
	return count, err
}

func (rd *ResilientDatabase) FinalizeAccountDeletionsWithRetry(ctx context.Context, accountIDs []int64) (int64, error) {
	var count int64
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
			return rd.getOperationalDatabaseForOperation(true).FinalizeAccountDeletions(writeCtx, tx, accountIDs)
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

		count = result.(int64)
		return nil
	}, cleanupRetryConfig)
	return count, err
}
