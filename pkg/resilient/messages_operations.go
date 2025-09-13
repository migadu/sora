package resilient

import (
	"context"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/retry"
)

// --- Flag Management Wrappers ---

func (rd *ResilientDatabase) AddMessageFlagsWithRetry(ctx context.Context, messageUID imap.UID, mailboxID int64, newFlags []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	config := retry.BackoffConfig{MaxRetries: 2}
	err = retry.WithRetry(ctx, func() error {
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
			updatedFlags, modSeq, err = rd.getOperationalDatabaseForOperation(true).AddMessageFlags(writeCtx, tx, messageUID, mailboxID, newFlags)
			return nil, err
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
	}, config)
	return
}

func (rd *ResilientDatabase) RemoveMessageFlagsWithRetry(ctx context.Context, messageUID imap.UID, mailboxID int64, flagsToRemove []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	config := retry.BackoffConfig{MaxRetries: 2}
	err = retry.WithRetry(ctx, func() error {
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
			updatedFlags, modSeq, err = rd.getOperationalDatabaseForOperation(true).RemoveMessageFlags(writeCtx, tx, messageUID, mailboxID, flagsToRemove)
			return nil, err
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
	}, config)
	return
}

func (rd *ResilientDatabase) SetMessageFlagsWithRetry(ctx context.Context, messageUID imap.UID, mailboxID int64, newFlags []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	config := retry.BackoffConfig{MaxRetries: 2}
	err = retry.WithRetry(ctx, func() error {
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
			updatedFlags, modSeq, err = rd.getOperationalDatabaseForOperation(true).SetMessageFlags(writeCtx, tx, messageUID, mailboxID, newFlags)
			return nil, err
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
	}, config)
	return
}

// --- Fetch Wrappers ---

func (rd *ResilientDatabase) GetMessageEnvelopeWithRetry(ctx context.Context, UID imap.UID, mailboxID int64) (*imap.Envelope, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var envelope *imap.Envelope
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetMessageEnvelope(readCtx, UID, mailboxID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			envelope = result.(*imap.Envelope)
		}
		return nil
	}, config)
	return envelope, err
}

func (rd *ResilientDatabase) GetMessageHeadersWithRetry(ctx context.Context, messageUID imap.UID, mailboxID int64) (string, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var headers string
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetMessageHeaders(readCtx, messageUID, mailboxID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		headers = result.(string)
		return nil
	}, config)
	return headers, err
}

func (rd *ResilientDatabase) GetMessageTextBodyWithRetry(ctx context.Context, uid imap.UID, mailboxID int64) (string, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var body string
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetMessageTextBody(readCtx, uid, mailboxID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		body = result.(string)
		return nil
	}, config)
	return body, err
}

func (rd *ResilientDatabase) GetMessagesSorted(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, sortCriteria []imap.SortCriterion) ([]db.Message, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var messages []db.Message
	err := retry.WithRetryAdvanced(ctx, func() error {
		searchCtx, cancel := rd.withTimeout(ctx, timeoutSearch)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetMessagesSorted(searchCtx, mailboxID, criteria, sortCriteria)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		messages = result.([]db.Message)
		return nil
	}, config)
	return messages, err
}

func (rd *ResilientDatabase) MoveMessagesWithRetry(ctx context.Context, ids *[]imap.UID, srcMailboxID, destMailboxID int64, userID int64) (map[imap.UID]imap.UID, error) {
	config := retry.BackoffConfig{MaxRetries: 2}
	var uidMap map[imap.UID]imap.UID
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
			// Assuming db.MoveMessages is refactored to accept a transaction.
			return rd.getOperationalDatabaseForOperation(true).MoveMessages(writeCtx, tx, ids, srcMailboxID, destMailboxID, userID)
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

		uidMap = result.(map[imap.UID]imap.UID)
		return nil
	}, config)
	return uidMap, err
}

// --- POP3 and Message List Wrappers ---

func (rd *ResilientDatabase) GetMailboxMessageCountAndSizeSumWithRetry(ctx context.Context, mailboxID int64) (int, int64, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var count int
	var sizeSum int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			c, s, err := rd.getOperationalDatabaseForOperation(false).GetMailboxMessageCountAndSizeSum(readCtx, mailboxID)
			if err != nil {
				return nil, err
			}
			return []interface{}{c, s}, nil
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		resSlice := result.([]interface{})
		count = resSlice[0].(int)
		sizeSum = resSlice[1].(int64)
		return nil
	}, config)
	return count, sizeSum, err
}

func (rd *ResilientDatabase) ListMessagesWithRetry(ctx context.Context, mailboxID int64) ([]db.Message, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var messages []db.Message
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).ListMessages(readCtx, mailboxID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		messages = result.([]db.Message)
		return nil
	}, config)
	return messages, err
}

func (rd *ResilientDatabase) GetMessagesWithCriteriaWithRetry(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria) ([]db.Message, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var messages []db.Message
	err := retry.WithRetryAdvanced(ctx, func() error {
		searchCtx, cancel := rd.withTimeout(ctx, timeoutSearch)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetMessagesWithCriteria(searchCtx, mailboxID, criteria)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		messages = result.([]db.Message)
		return nil
	}, config)
	return messages, err
}
