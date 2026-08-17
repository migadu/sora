package resilient

import (
	"context"
	"fmt"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
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

func (rd *ResilientDatabase) AddMessageFlagsBatchWithRetry(ctx context.Context, messageUIDs []imap.UID, mailboxID int64, newFlags []imap.Flag) ([]db.BatchFlagUpdateResult, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).AddMessageFlagsBatch(ctx, tx, messageUIDs, mailboxID, newFlags)
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, err
	}
	return result.([]db.BatchFlagUpdateResult), nil
}

func (rd *ResilientDatabase) RemoveMessageFlagsBatchWithRetry(ctx context.Context, messageUIDs []imap.UID, mailboxID int64, flagsToRemove []imap.Flag) ([]db.BatchFlagUpdateResult, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).RemoveMessageFlagsBatch(ctx, tx, messageUIDs, mailboxID, flagsToRemove)
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, err
	}
	return result.([]db.BatchFlagUpdateResult), nil
}

func (rd *ResilientDatabase) SetMessageFlagsBatchWithRetry(ctx context.Context, messageUIDs []imap.UID, mailboxID int64, newFlags []imap.Flag) ([]db.BatchFlagUpdateResult, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).SetMessageFlagsBatch(ctx, tx, messageUIDs, mailboxID, newFlags)
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

func (rd *ResilientDatabase) GetMessagesSorted(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, sortCriteria []imap.SortCriterion, limit int) ([]db.Message, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetMessagesSorted(ctx, mailboxID, criteria, sortCriteria, limit)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutSearch, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []db.Message{}, nil
	}
	return result.([]db.Message), nil
}

func (rd *ResilientDatabase) SearchMessagesSortedWithRetry(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, sortCriteria []imap.SortCriterion, limit int) ([]db.SearchMessageResult, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).SearchMessagesSorted(ctx, mailboxID, criteria, sortCriteria, limit)
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

func (rd *ResilientDatabase) MoveMessagesWithRetry(ctx context.Context, ids *[]imap.UID, srcMailboxID, destMailboxID int64, destAccountID int64, destS3Domain string, destS3Localpart string, instanceID string) (map[imap.UID]imap.UID, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).MoveMessages(ctx, tx, ids, srcMailboxID, destMailboxID, destAccountID, destS3Domain, destS3Localpart, instanceID)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, err
	}
	return result.(map[imap.UID]imap.UID), nil
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

func (rd *ResilientDatabase) GetMessagesWithCriteriaWithRetry(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, limit int) ([]db.Message, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetMessagesWithCriteria(ctx, mailboxID, criteria, limit)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutSearch, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []db.Message{}, nil
	}
	return result.([]db.Message), nil
}

func (rd *ResilientDatabase) SearchMessagesWithCriteriaWithRetry(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, limit int) ([]db.SearchMessageResult, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).SearchMessagesWithCriteria(ctx, mailboxID, criteria, limit)
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

func (rd *ResilientDatabase) GetMessagesForThreadingWithRetry(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, includeSubject bool) ([]db.ThreadMessageResult, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetMessagesForThreading(ctx, mailboxID, criteria, includeSubject)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutSearch, op)
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
