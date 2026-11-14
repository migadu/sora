package resilient

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
)

// --- Flag Management Wrappers ---

func (rd *ResilientDatabase) AddMessageFlagsWithRetry(ctx context.Context, messageUID imap.UID, mailboxID int64, newFlags []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	type flagUpdateResult struct {
		flags  []imap.Flag
		modSeq int64
	}
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		flags, modSeq, err := rd.getOperationalDatabaseForOperation(ctx, true).AddMessageFlags(ctx, tx, messageUID, mailboxID, newFlags)
		if err != nil {
			return nil, err
		}
		return flagUpdateResult{flags: flags, modSeq: modSeq}, nil
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, 0, err
	}

	res := result.(flagUpdateResult)
	return res.flags, res.modSeq, nil
}

func (rd *ResilientDatabase) RemoveMessageFlagsWithRetry(ctx context.Context, messageUID imap.UID, mailboxID int64, flagsToRemove []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	type flagUpdateResult struct {
		flags  []imap.Flag
		modSeq int64
	}
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		flags, modSeq, err := rd.getOperationalDatabaseForOperation(ctx, true).RemoveMessageFlags(ctx, tx, messageUID, mailboxID, flagsToRemove)
		if err != nil {
			return nil, err
		}
		return flagUpdateResult{flags: flags, modSeq: modSeq}, nil
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, 0, err
	}

	res := result.(flagUpdateResult)
	return res.flags, res.modSeq, nil
}

func (rd *ResilientDatabase) SetMessageFlagsWithRetry(ctx context.Context, messageUID imap.UID, mailboxID int64, newFlags []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	type flagUpdateResult struct {
		flags  []imap.Flag
		modSeq int64
	}
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		flags, modSeq, err := rd.getOperationalDatabaseForOperation(ctx, true).SetMessageFlags(ctx, tx, messageUID, mailboxID, newFlags)
		if err != nil {
			return nil, err
		}
		return flagUpdateResult{flags: flags, modSeq: modSeq}, nil
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, 0, err
	}

	res := result.(flagUpdateResult)
	return res.flags, res.modSeq, nil
}

// --- Fetch Wrappers ---

func (rd *ResilientDatabase) AddMessageFlagsBatchWithRetry(ctx context.Context, messageUIDs []imap.UID, mailboxID int64, newFlags []imap.Flag, unchangedSince ...uint64) ([]db.BatchFlagUpdateResult, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).AddMessageFlagsBatch(ctx, tx, messageUIDs, mailboxID, newFlags, unchangedSince...)
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, err
	}
	return result.([]db.BatchFlagUpdateResult), nil
}

func (rd *ResilientDatabase) RemoveMessageFlagsBatchWithRetry(ctx context.Context, messageUIDs []imap.UID, mailboxID int64, flagsToRemove []imap.Flag, unchangedSince ...uint64) ([]db.BatchFlagUpdateResult, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).RemoveMessageFlagsBatch(ctx, tx, messageUIDs, mailboxID, flagsToRemove, unchangedSince...)
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, err
	}
	return result.([]db.BatchFlagUpdateResult), nil
}

func (rd *ResilientDatabase) SetMessageFlagsBatchWithRetry(ctx context.Context, messageUIDs []imap.UID, mailboxID int64, newFlags []imap.Flag, unchangedSince ...uint64) ([]db.BatchFlagUpdateResult, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).SetMessageFlagsBatch(ctx, tx, messageUIDs, mailboxID, newFlags, unchangedSince...)
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, err
	}
	return result.([]db.BatchFlagUpdateResult), nil
}

func (rd *ResilientDatabase) SetMessageFlagsBatchWithRightsWithRetry(ctx context.Context, messageUIDs []imap.UID, mailboxID int64, newFlags []imap.Flag, rights string, unchangedSince ...uint64) ([]db.BatchFlagUpdateResult, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).SetMessageFlagsBatchWithRights(ctx, tx, messageUIDs, mailboxID, newFlags, rights, unchangedSince...)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, err
	}
	return result.([]db.BatchFlagUpdateResult), nil
}

func (rd *ResilientDatabase) GetMessageBodyStructureWithRetry(ctx context.Context, uid imap.UID, mailboxID int64) (*imap.BodyStructure, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetMessageBodyStructure(ctx, uid, mailboxID)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.(*imap.BodyStructure), nil
}

func (rd *ResilientDatabase) SearchMessagesSortedWithRetry(ctx context.Context, mailboxID, accountID int64, criteria *imap.SearchCriteria, sortCriteria []imap.SortCriterion, limit, mailboxMessageCount int) ([]db.SearchMessageResult, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).SearchMessagesSorted(ctx, mailboxID, accountID, criteria, sortCriteria, limit, mailboxMessageCount)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutSearch, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []db.SearchMessageResult{}, nil
	}
	return result.([]db.SearchMessageResult), nil
}

// destObjectKeepalive is the longest a COPY/MOVE transaction sits without a statement while
// it makes its destination objects exist in S3. The server kills a session idle in a
// transaction for idle_in_transaction_session_timeout, and the S3 round trips of a large
// operation can outlast that. A variable so tests can shorten it.
var destObjectKeepalive = 30 * time.Second

// MoveMessagesWithRetry moves ids from srcMailboxID into destMailboxID, owned by
// destAccountID, in one write transaction (db.MoveMessages).
//
// destObjects are the bodies of a cross-account move that are in S3 under their source
// key. The moved rows point at destAccountID's key, and ensureDestObject makes the
// object under it exist. The transaction first takes their object locks in shared mode
// (db.LockS3ObjectsSharedInTx), runs ensureDestObject for each while it holds them, and
// only then moves the rows, marked uploaded for exactly these bodies. The cleaner
// deletes an object only under the same lock, after a re-check that finds no row of the
// owner for it, and the moved rows are invisible to that re-check until they commit:
// holding the lock from the check to that commit is what keeps it from deleting the
// object in between. The lock, the check and the rows share one transaction, so no
// second connection is needed while the first is held, and the lock is held in the
// database the rows are written to whatever the write pool fails over to.
//
// The S3 round trips run before the transaction's first write and first row lock, so
// meanwhile it holds the shared locks and its connection but no transaction id or
// snapshot. They are not database time: they run under ctx, not the write timeout, and
// the writes get a write timeout of their own afterwards. A failed S3 call fails the
// move with a *DestObjectError, which the write circuit breaker does not count and the
// retry does not repeat (the S3 calls retry on their own). A statement keeps the
// transaction alive at least every destObjectKeepalive.
func (rd *ResilientDatabase) MoveMessagesWithRetry(ctx context.Context, ids *[]imap.UID, srcMailboxID, destMailboxID int64, destAccountID int64, destS3Domain string, destS3Localpart string, instanceID string, destObjects []string, ensureDestObject func(ctx context.Context, contentHash string) error) (map[imap.UID]imap.UID, error) {
	op := func(opCtx context.Context, tx pgx.Tx) (any, error) {
		if len(destObjects) > 0 {
			if err := db.LockS3ObjectsSharedInTx(opCtx, tx, destAccountID, destObjects); err != nil {
				return nil, err
			}
			if err := rd.ensureDestObjects(ctx, tx, destObjects, ensureDestObject); err != nil {
				return nil, err
			}
			writeCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
			defer cancel()
			opCtx = writeCtx
		}
		return rd.getOperationalDatabaseForOperation(opCtx, true).MoveMessages(opCtx, tx, ids, srcMailboxID, destMailboxID, destAccountID, destS3Domain, destS3Localpart, instanceID, destObjects)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, err
	}
	return result.(map[imap.UID]imap.UID), nil
}

// ensureDestObjects runs ensure for every hash while tx holds their locks. The
// keepalive also runs during a single slow S3 request. Only its goroutine uses tx
// during this phase; it is joined before the caller starts any database writes.
func (rd *ResilientDatabase) ensureDestObjects(ctx context.Context, tx pgx.Tx, hashes []string, ensure func(ctx context.Context, contentHash string) error) (resultErr error) {
	ensureCtx, cancelEnsure := context.WithCancel(ctx)
	defer cancelEnsure()
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(destObjectKeepalive)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				done <- nil
				return
			case <-ctx.Done():
				// The caller's deadline is not a database failure. The S3 callback
				// observes the same cancellation and retains its error classification.
				done <- nil
				return
			case <-ticker.C:
				pingCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
				_, err := tx.Exec(pingCtx, "SELECT 1")
				cancel()
				if err != nil {
					cancelEnsure()
					if ctx.Err() != nil {
						done <- nil
					} else {
						done <- fmt.Errorf("failed to keep the destination object transaction alive: %w", err)
					}
					return
				}
			}
		}
	}()
	defer func() {
		close(stop)
		if err := <-done; err != nil {
			resultErr = err
		}
	}()
	for _, hash := range hashes {
		if err := ensure(ensureCtx, hash); err != nil {
			return &DestObjectError{ContentHash: hash, Err: err}
		}
	}
	return nil
}

// DestObjectError is a failure to make a cross-account COPY/MOVE destination object exist
// in S3. It has no Unwrap on purpose: an S3 timeout, a refused connection or an open S3
// circuit breaker must not pass for a database failure with the write circuit breaker
// or the retry. The caller classifies Err itself.
type DestObjectError struct {
	ContentHash string
	Err         error
}

func (e *DestObjectError) Error() string {
	return fmt.Sprintf("failed to make destination object %s exist: %v", e.ContentHash, e.Err)
}

// --- POP3 and Message List Wrappers ---

func (rd *ResilientDatabase) GetMailboxMessageCountAndSizeSumWithRetry(ctx context.Context, mailboxID int64) (int, int64, error) {
	op := func(ctx context.Context) (any, error) {
		c, s, err := rd.getOperationalDatabaseForOperation(ctx, false).GetMailboxMessageCountAndSizeSum(ctx, mailboxID)
		if err != nil {
			return nil, err
		}
		return []any{c, s}, nil
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return 0, 0, err
	}
	resSlice := result.([]any)
	return resSlice[0].(int), resSlice[1].(int64), nil
}

func (rd *ResilientDatabase) ListMessagesWithRetry(ctx context.Context, mailboxID int64) ([]db.Message, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).ListMessages(ctx, mailboxID)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []db.Message{}, nil
	}
	return result.([]db.Message), nil
}

// ListMessagesForPOP3WithRetry returns the lean POP3Message projection for the
// mailbox. POP3 caches the whole list for the session, so the smaller per-message
// footprint of db.POP3Message (vs db.Message) materially reduces session memory.
func (rd *ResilientDatabase) ListMessagesForPOP3WithRetry(ctx context.Context, mailboxID int64, limit int) ([]db.POP3Message, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).ListMessagesForPOP3(ctx, mailboxID, limit)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []db.POP3Message{}, nil
	}
	return result.([]db.POP3Message), nil
}

func (rd *ResilientDatabase) SearchMessagesWithCriteriaWithRetry(ctx context.Context, mailboxID, accountID int64, criteria *imap.SearchCriteria, limit, mailboxMessageCount int) ([]db.SearchMessageResult, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).SearchMessagesWithCriteria(ctx, mailboxID, accountID, criteria, limit, mailboxMessageCount)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutSearch, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []db.SearchMessageResult{}, nil
	}
	return result.([]db.SearchMessageResult), nil
}

func (rd *ResilientDatabase) GetMessagesForThreadingWithRetry(ctx context.Context, mailboxID, accountID int64, criteria *imap.SearchCriteria, includeSubject, withSeqNums bool, maxMessages int) ([]db.ThreadMessageResult, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetMessagesForThreading(ctx, mailboxID, accountID, criteria, includeSubject, withSeqNums, maxMessages)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutSearch, op, db.ErrThreadTooManyMessages)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []db.ThreadMessageResult{}, nil
	}
	return result.([]db.ThreadMessageResult), nil
}

// --- Message Restoration Wrappers ---

func (rd *ResilientDatabase) ListDeletedMessagesWithRetry(ctx context.Context, params db.ListDeletedMessagesParams) ([]db.DeletedMessage, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).ListDeletedMessages(ctx, params)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []db.DeletedMessage{}, nil
	}
	return result.([]db.DeletedMessage), nil
}

// restoreChunkSize bounds how many messages a single restore transaction touches.
// Each message costs several sequential statements plus statement-level stats
// triggers, and the transaction holds the target mailbox row lock (highest_uid bump)
// until it commits — so a chunk must comfortably fit one admin timeout AND keep the
// user's live IMAP writes on that mailbox from stalling for long. Committed chunks stay
// committed if a later one fails; re-running the same restore is safe because rows that
// are already live are skipped.
const restoreChunkSize = 100

// RestoreMessagesWithRetry restores the expunged messages matching params.
//
// The candidate ids are resolved first (one read), then restored in chunks of
// restoreChunkSize, each in its own transaction with its own timeout and retries. A
// restore of weeks of deletions is therefore never bounded by a single write_timeout,
// and a failure late in the run does not roll back the messages already restored.
// The returned count is the number of messages restored so far, also when err != nil.
func (rd *ResilientDatabase) RestoreMessagesWithRetry(ctx context.Context, params db.RestoreMessagesParams) (int64, error) {
	return rd.restoreMessagesChunked(ctx, params, restoreChunkSize)
}

func (rd *ResilientDatabase) restoreMessagesChunked(ctx context.Context, params db.RestoreMessagesParams, chunkSize int) (int64, error) {
	listOp := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetRestorableMessageIDs(ctx, params)
	}
	listed, err := rd.executeReadWithRetry(ctx, adminRetryConfig, timeoutAdmin, listOp, db.ErrAccountNotFound)
	if err != nil {
		return 0, err
	}
	ids, _ := listed.([]int64)
	if len(ids) == 0 {
		return 0, nil
	}

	var restored int64
	for start := 0; start < len(ids); start += chunkSize {
		end := min(start+chunkSize, len(ids))
		chunk := db.RestoreMessagesParams{Email: params.Email, MessageIDs: ids[start:end]}

		op := func(ctx context.Context, tx pgx.Tx) (any, error) {
			return rd.getOperationalDatabaseForOperation(ctx, true).RestoreMessages(ctx, tx, chunk)
		}
		result, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
		if err != nil {
			return restored, fmt.Errorf("restore stopped at candidates %d-%d of %d after restoring %d message(s): %w",
				start+1, end, len(ids), restored, err)
		}
		n, _ := result.(int64)
		restored += n
		logger.Info("Database: restore progress", "component", "RESILIENT-FAILOVER",
			"email", params.Email, "processed", end, "total", len(ids), "restored", restored)
	}
	return restored, nil
}
