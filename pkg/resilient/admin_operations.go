package resilient

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/retry"
)

// --- Admin Credentials Wrappers ---

func (rd *ResilientDatabase) AddCredentialWithRetry(ctx context.Context, req db.AddCredentialRequest) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).AddCredential(ctx, tx, req)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	return err
}

func (rd *ResilientDatabase) ListCredentialsWithRetry(ctx context.Context, email string) ([]db.Credential, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).ListCredentials(ctx, email)
	}
	result, err := rd.executeReadWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	if err != nil {
		return nil, err
	}
	return result.([]db.Credential), nil
}

func (rd *ResilientDatabase) IsAddressOwnedByAccountWithRetry(ctx context.Context, accountID int64, address string) (bool, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).IsAddressOwnedByAccount(ctx, accountID, address)
	}
	result, err := rd.executeReadWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

func (rd *ResilientDatabase) DeleteCredentialWithRetry(ctx context.Context, email string) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).DeleteCredential(ctx, tx, email)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	return err
}

func (rd *ResilientDatabase) GetCredentialDetailsWithRetry(ctx context.Context, email string) (*db.CredentialDetails, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetCredentialDetails(ctx, email)
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
	OperationName:   "db_admin",
}

func (rd *ResilientDatabase) CreateAccountWithRetry(ctx context.Context, req db.CreateAccountRequest) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).CreateAccount(ctx, tx, req)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) CreateAccountWithCredentialsWithRetry(ctx context.Context, req db.CreateAccountWithCredentialsRequest) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).CreateAccountWithCredentials(ctx, tx, req)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) ListAccountsWithRetry(ctx context.Context) ([]*db.AccountSummary, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).ListAccounts(ctx)
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

func (rd *ResilientDatabase) GetAccountsByDomain(ctx context.Context, domain string) ([]db.AccountSummary, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetAccountsByDomain(ctx, domain)
	}
	result, err := rd.executeReadWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	if err != nil {
		return nil, err
	}
	return result.([]db.AccountSummary), nil
}

func (rd *ResilientDatabase) GetAliasCredentialsByDomain(ctx context.Context, domain string) ([]string, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetAliasCredentialsByDomain(ctx, domain)
	}
	result, err := rd.executeReadWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	if err != nil {
		return nil, err
	}
	return result.([]string), nil
}

func (rd *ResilientDatabase) ListAccountsByDomainWithRetry(ctx context.Context, domain string) ([]db.AccountSummary, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).ListAccountsByDomain(ctx, domain)
	}
	result, err := rd.executeReadWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	if err != nil {
		return nil, err
	}
	return result.([]db.AccountSummary), nil
}

func (rd *ResilientDatabase) GetAccountDetailsWithRetry(ctx context.Context, email string) (*db.AccountDetails, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetAccountDetails(ctx, email)
	}
	result, err := rd.executeReadWithRetry(ctx, adminRetryConfig, timeoutAdmin, op, consts.ErrUserNotFound)
	if err != nil {
		return nil, err
	}
	return result.(*db.AccountDetails), nil
}

func (rd *ResilientDatabase) UpdateAccountWithRetry(ctx context.Context, req db.UpdateAccountRequest) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).UpdateAccount(ctx, tx, req)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	return err
}

func (rd *ResilientDatabase) DeleteAccountWithRetry(ctx context.Context, email string) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).DeleteAccount(ctx, tx, email)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	return err
}

func (rd *ResilientDatabase) RestoreAccountWithRetry(ctx context.Context, email string) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).RestoreAccount(ctx, tx, email)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	return err
}

func (rd *ResilientDatabase) CleanupFailedUploadsWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).CleanupFailedUploads(ctx, tx, gracePeriod)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) InsertMessageFromImporterWithRetry(ctx context.Context, options *db.InsertMessageOptions) (messageID int64, uid int64, err error) {
	// Lock the mailbox at the Go level to prevent connection pool starvation during mass concurrent imports.
	unlock := rd.getOperationalDatabaseForOperation(ctx, true).LockMailbox(options.MailboxID)
	defer unlock()

	// Importer writes are less safe to retry automatically, so limit retries.
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     3 * time.Second,
		Multiplier:      1.8,
		Jitter:          true,
		MaxRetries:      2,
		OperationName:   "db_importer_insert_message",
	}

	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		id, u, opErr := rd.getOperationalDatabaseForOperation(ctx, true).InsertMessageFromImporter(ctx, tx, options)
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

func (rd *ResilientDatabase) InsertMessagesFromImporterBatchWithRetry(ctx context.Context, options []*db.InsertMessageOptions) ([]int64, []int64, []string, error) {
	if len(options) == 0 {
		return nil, nil, nil, nil
	}

	// Lock the mailbox at the Go level to prevent connection pool starvation during mass concurrent imports.
	unlock := rd.getOperationalDatabaseForOperation(ctx, true).LockMailbox(options[0].MailboxID)
	defer unlock()

	// Importer writes are less safe to retry automatically, so limit retries.
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     3 * time.Second,
		Multiplier:      1.8,
		Jitter:          true,
		MaxRetries:      2,
		OperationName:   "db_importer_insert_messages_batch",
	}

	type batchResult struct {
		rowIDs []int64
		uids   []int64
		hashes []string
	}

	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		rowIDs, uids, hashes, opErr := rd.getOperationalDatabaseForOperation(ctx, true).InsertMessagesFromImporterBatch(ctx, tx, options)
		if opErr != nil {
			return nil, opErr
		}
		return batchResult{rowIDs: rowIDs, uids: uids, hashes: hashes}, nil
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, config, timeoutAdmin, op)
	if err != nil || result == nil {
		return nil, nil, nil, err
	}

	res := result.(batchResult)
	return res.rowIDs, res.uids, res.hashes, nil
}

func (rd *ResilientDatabase) CleanupSoftDeletedAccountsWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).CleanupSoftDeletedAccounts(ctx, tx, gracePeriod)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

// ListSoftDeletedMailboxesWithRetry reads the next batch of tombstoned mailboxes to purge.
func (rd *ResilientDatabase) ListSoftDeletedMailboxesWithRetry(ctx context.Context, gracePeriod time.Duration, limit int) ([]db.SoftDeletedMailbox, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).ListSoftDeletedMailboxes(ctx, gracePeriod, limit)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.([]db.SoftDeletedMailbox), nil
}

// PurgeSoftDeletedMailboxesWithRetry hard-deletes a batch of two-phase-deleted mailboxes
// (the IMAP DELETE path stamps deleted_at; this performs the deferred per-message expunge
// + row removal). It reads the batch in one fast query, then hard-deletes each mailbox in
// its OWN transaction via DeleteMailboxWithRetry.
//
// Per-mailbox transactions are essential. Batching many large mailboxes under a single
// write deadline would roll the entire batch back on timeout and — because tombstones are
// processed oldest-first — never make progress (a poison pill). Isolating each delete also
// means one oversized/stuck mailbox is skipped and retried next tick instead of blocking
// the rest of the batch. Returns the number purged this call.
func (rd *ResilientDatabase) PurgeSoftDeletedMailboxesWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	const batchLimit = 50

	mailboxes, err := rd.ListSoftDeletedMailboxesWithRetry(ctx, gracePeriod, batchLimit)
	if err != nil {
		return 0, err
	}

	var purged int64
	for _, m := range mailboxes {
		if ctx.Err() != nil {
			return purged, ctx.Err()
		}
		// DeleteMailboxWithRetry runs in its own transaction with the administrative
		// timeout + write retries. The stored account_id is the owner, which DeleteMailbox
		// gates on (the owner always holds the delete right, incl. for shared mailboxes).
		if err := rd.DeleteMailboxWithRetry(ctx, m.ID, m.AccountID); err != nil {
			if errors.Is(err, consts.ErrMailboxNotFound) {
				// Already removed (e.g. by a concurrent account purge).
				continue
			}
			// Don't let one stuck/oversized mailbox abort the batch; it remains a tombstone
			// and is retried next cycle while the rest of the batch proceeds.
			logger.Warn("Cleanup: failed to purge soft-deleted mailbox; will retry next cycle",
				"component", "CLEANUP", "mailbox_id", m.ID, "error", err)
			continue
		}
		purged++
	}
	return purged, nil
}

func (rd *ResilientDatabase) CleanupOldVacationResponsesWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).CleanupOldVacationResponses(ctx, tx, gracePeriod)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) CleanupOldRedirectsWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).CleanupOldRedirects(ctx, tx, gracePeriod)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) CleanupOldHealthStatusesWithRetry(ctx context.Context, retention time.Duration) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).CleanupOldHealthStatuses(ctx, tx, retention)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) GetUserScopedObjectsForCleanupWithRetry(ctx context.Context, gracePeriod time.Duration, batchSize int) ([]db.UserScopedObjectForCleanup, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetUserScopedObjectsForCleanup(ctx, gracePeriod, batchSize)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutSearch, op)
	if err != nil {
		return nil, err
	}
	return result.([]db.UserScopedObjectForCleanup), nil
}

func (rd *ResilientDatabase) PruneOldMessageVectorsWithRetry(ctx context.Context, retention time.Duration) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).PruneOldMessageVectors(ctx, tx, retention)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutAdmin, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}
func (rd *ResilientDatabase) GetUnusedFTSHashesWithRetry(ctx context.Context, batchSize int) ([]string, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetUnusedFTSHashes(ctx, batchSize)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutSearch, op)
	if err != nil {
		return nil, err
	}
	return result.([]string), nil
}

func (rd *ResilientDatabase) DeleteMessagesFTSByHashBatchWithRetry(ctx context.Context, hashes []string) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).DeleteMessagesFTSByHashBatch(ctx, tx, hashes)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) GetDanglingAccountsForFinalDeletionWithRetry(ctx context.Context, batchSize int) ([]int64, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetDanglingAccountsForFinalDeletion(ctx, batchSize)
	}
	result, err := rd.executeReadWithRetry(ctx, cleanupRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.([]int64), nil
}

func (rd *ResilientDatabase) DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(ctx context.Context, candidates []db.UserScopedObjectForCleanup) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).DeleteExpungedMessagesByS3KeyPartsBatch(ctx, tx, candidates)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) FinalizeAccountDeletionsWithRetry(ctx context.Context, accountIDs []int64) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).FinalizeAccountDeletions(ctx, tx, accountIDs)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

// --- Resilient Execution Helpers ---

// executeWriteInTxWithRetry provides a generic wrapper for executing a write operation within a resilient, retriable transaction.
func (rd *ResilientDatabase) executeWriteInTxWithRetry(ctx context.Context, config retry.BackoffConfig, opType timeoutType, op func(ctx context.Context, tx pgx.Tx) (any, error), nonRetryableErrors ...error) (any, error) {
	var result any
	err := retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		// Use background context for rollback to ensure it always completes, even if the
		// request context has expired. If we use the request context and it's canceled/expired,
		// pgx will fail to send ROLLBACK to PostgreSQL, leaving an uncommitted transaction that
		// may later be auto-committed when the connection is returned to the pool or closed.
		// This caused data loss where INSERT operations succeeded on the PostgreSQL side but
		// the client timed out, then rollback failed silently, leaving orphaned database rows
		// while the application deleted the local files (believing the transaction failed).
		defer tx.Rollback(context.Background())

		opCtx, cancel := rd.withTimeout(ctx, opType)
		defer cancel()

		res, cbErr := rd.writeBreaker.Execute(func() (any, error) {
			// Bound how long statements in this transaction wait for a row lock, so a
			// blocked write fails fast with 55P03 instead of parking on a connection
			// for the full write_timeout (which starves the pool). SET LOCAL is
			// transaction-scoped, so it is correct under every PgBouncer pooling mode
			// and reverts on commit/rollback. Empty when lock_timeout is disabled.
			if rd.lockTimeoutStmt != "" {
				if _, lerr := tx.Exec(opCtx, rd.lockTimeoutStmt); lerr != nil {
					return nil, lerr
				}
			}
			return op(opCtx, tx)
		})
		if cbErr != nil {
			// Log circuit breaker state to understand failure patterns.
			// Only log at Warn for actual system failures (retryable errors like deadlocks,
			// connection issues). Business logic errors (ErrNoRows, ErrMailboxNotFound, etc.)
			// are expected and should not produce noisy Warn logs.
			state := rd.writeBreaker.State()
			counts := rd.writeBreaker.Counts()

			// Log at WARN only for system failures or when breaker is not CLOSED
			// Business logic errors log at DEBUG to reduce noise
			if !rd.isBusinessLogicError(cbErr) && (rd.isRetryableError(cbErr) || state != circuitbreaker.StateClosed) {
				logger.Warn("Write transaction operation failed through circuit breaker", "component", "RESILIENT-FAILOVER",
					"error", cbErr, "breaker_state", state, "total_failures", counts.TotalFailures,
					"total_requests", counts.Requests, "consecutive_failures", counts.ConsecutiveFailures)
			} else {
				logger.Debug("Write transaction returned application error", "component", "RESILIENT-FAILOVER",
					"error", cbErr)
			}

			// Save result even on error (for cases like ErrMessageExists that return useful data)
			result = res

			// When the write pool is pointed at a server that became a read-only
			// standby after a failover, all write operations fail with SQLSTATE 25006
			// ("read_only_sql_transaction"). A plain Ping still succeeds against the
			// old primary, so the health check does not detect the problem on its own.
			// Resetting the pool here drops all existing connections immediately, so
			// the next attempt — once the circuit breaker transitions to HALF_OPEN —
			// will open a fresh connection that DNS / the load balancer can route to
			// the new primary.
			if isReadOnlyTransactionError(cbErr) {
				rd.resetCurrentWritePool()
			}

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

		// Check if context was canceled before attempting commit.
		// Even if the operation succeeded, we must not commit if the context is canceled
		// because the caller has abandoned the operation (e.g., client disconnect).
		// Without this check, the COMMIT may succeed on PostgreSQL's side while the
		// client receives a context error, leaving the caller unaware that rows (e.g.,
		// pending_uploads) were persisted. This creates orphaned records that reference
		// local files the caller never finished writing or already cleaned up.
		if ctx.Err() != nil {
			return retry.Stop(ctx.Err())
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
func (rd *ResilientDatabase) executeReadWithRetry(ctx context.Context, config retry.BackoffConfig, opType timeoutType, op func(ctx context.Context) (any, error), nonRetryableErrors ...error) (any, error) {
	var result any
	err := retry.WithRetryAdvanced(ctx, func() error {
		opCtx, cancel := rd.withTimeout(ctx, opType)
		defer cancel()

		res, cbErr := rd.queryBreaker.Execute(func() (any, error) {
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

func (rd *ResilientDatabase) ProcessFTSBatchWithRetry(ctx context.Context, limit int) (int, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).ProcessFTSBatch(ctx, tx, limit)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, cleanupRetryConfig, timeoutAdmin, op)
	if err != nil {
		return 0, err
	}
	return result.(int), nil
}
