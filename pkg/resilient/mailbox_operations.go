package resilient

import (
	"context"
	"errors"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/retry"
	"github.com/migadu/sora/server"
)

// --- Mailbox and Message Wrappers ---

func (rd *ResilientDatabase) GetMailboxByNameWithRetry(ctx context.Context, userID int64, name string) (*db.DBMailbox, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var mailbox *db.DBMailbox
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetMailboxByName(readCtx, userID, name)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			mailbox = result.(*db.DBMailbox)
		}
		return nil
	}, config)
	return mailbox, err
}

func (rd *ResilientDatabase) InsertMessageWithRetry(ctx context.Context, options *db.InsertMessageOptions, upload db.PendingUpload) (messageID int64, uid int64, err error) {
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

		writeCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
		defer cancel()

		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			// Pass the transaction to the refactored db method.
			messageID, uid, err = rd.getOperationalDatabaseForOperation(true).InsertMessage(writeCtx, tx, options, upload)
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

func (rd *ResilientDatabase) GetMessagesByNumSetWithRetry(ctx context.Context, mailboxID int64, numSet imap.NumSet) ([]db.Message, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var messages []db.Message
	err := retry.WithRetryAdvanced(ctx, func() error {
		searchCtx, cancel := rd.withTimeout(ctx, timeoutSearch)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetMessagesByNumSet(searchCtx, mailboxID, numSet)
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

func (rd *ResilientDatabase) GetMailboxSummaryWithRetry(ctx context.Context, mailboxID int64) (*db.MailboxSummary, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var summary *db.MailboxSummary
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetMailboxSummary(readCtx, mailboxID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			summary = result.(*db.MailboxSummary)
		}
		return nil
	}, config)
	return summary, err
}

func (rd *ResilientDatabase) GetMailboxesWithRetry(ctx context.Context, userID int64, subscribed bool) ([]*db.DBMailbox, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var mailboxes []*db.DBMailbox
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetMailboxes(readCtx, userID, subscribed)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		mailboxes = result.([]*db.DBMailbox)
		return nil
	}, config)
	return mailboxes, err
}

func (rd *ResilientDatabase) GetAccountIDByAddressWithRetry(ctx context.Context, address string) (int64, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var accountID int64
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetAccountIDByAddress(readCtx, address)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		accountID = result.(int64)
		return nil
	}, config)
	return accountID, err
}

func (rd *ResilientDatabase) CreateDefaultMailboxesWithRetry(ctx context.Context, userID int64) error {
	config := retry.BackoffConfig{MaxRetries: 2} // Writes are less safe to retry automatically
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
			// Assuming db.CreateDefaultMailboxes is refactored to accept a transaction.
			return nil, rd.getOperationalDatabaseForOperation(true).CreateDefaultMailboxes(writeCtx, tx, userID)
		})
		if cbErr != nil && !rd.isRetryableError(cbErr) {
			return retry.Stop(cbErr)
		}

		if err := tx.Commit(ctx); err != nil {
			return err // Let retry logic handle commit errors
		}

		return nil
	}, config)
}

func (rd *ResilientDatabase) PollMailboxWithRetry(ctx context.Context, mailboxID int64, sinceModSeq uint64) (*db.MailboxPoll, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var poll *db.MailboxPoll
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).PollMailbox(readCtx, mailboxID, sinceModSeq)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			poll = result.(*db.MailboxPoll)
		}
		return nil
	}, config)
	return poll, err
}

func (rd *ResilientDatabase) GetMessagesByFlagWithRetry(ctx context.Context, mailboxID int64, flag imap.Flag) ([]db.Message, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var messages []db.Message
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetMessagesByFlag(readCtx, mailboxID, flag)
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

func (rd *ResilientDatabase) ExpungeMessageUIDsWithRetry(ctx context.Context, mailboxID int64, uids ...imap.UID) (int64, error) {
	config := retry.BackoffConfig{MaxRetries: 2} // Writes are less safe to retry automatically
	var modSeq int64
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
			return rd.getOperationalDatabaseForOperation(true).ExpungeMessageUIDs(writeCtx, tx, mailboxID, uids...)
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

		modSeq = result.(int64)
		return nil
	}, config)
	return modSeq, err
}

func (rd *ResilientDatabase) GetPrimaryEmailForAccountWithRetry(ctx context.Context, accountID int64) (server.Address, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var address server.Address
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetPrimaryEmailForAccount(readCtx, accountID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		address = result.(server.Address)
		return nil
	}, config)
	return address, err
}

// --- Mailbox Management Wrappers ---

func (rd *ResilientDatabase) CopyMessagesWithRetry(ctx context.Context, uids *[]imap.UID, srcMailboxID, destMailboxID int64, userID int64) (map[imap.UID]imap.UID, error) {
	config := retry.BackoffConfig{MaxRetries: 2}
	var uidMap map[imap.UID]imap.UID
	err := retry.WithRetryAdvanced(ctx, func() error {
		// Begin a resilient transaction.
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			// If beginning a transaction fails, it's likely a retryable DB connection issue.
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx) // Ensure rollback on error.

		// The timeout is applied to the entire transaction block.
		writeCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
		defer cancel()

		// Execute the operation within the circuit breaker, passing the transaction.
		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			// Pass the transaction to the refactored db method.
			return rd.getOperationalDatabaseForOperation(true).CopyMessages(writeCtx, tx, uids, srcMailboxID, destMailboxID, userID)
		})

		if cbErr != nil {
			if rd.isRetryableError(cbErr) {
				return cbErr // Retry the whole transaction.
			}
			return retry.Stop(cbErr)
		}

		// Commit the transaction.
		if err := tx.Commit(ctx); err != nil {
			if rd.isRetryableError(err) {
				return err // Retry on commit failure.
			}
			return retry.Stop(err)
		}

		uidMap = result.(map[imap.UID]imap.UID)
		return nil
	}, config)
	return uidMap, err
}

func (rd *ResilientDatabase) CreateMailboxWithRetry(ctx context.Context, userID int64, name string, parentID *int64) error {
	config := retry.BackoffConfig{MaxRetries: 2}
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
			// Assuming db.CreateMailbox is refactored to accept a transaction.
			return nil, rd.getOperationalDatabaseForOperation(true).CreateMailbox(writeCtx, tx, userID, name, parentID)
		})
		if cbErr != nil {
			if errors.Is(cbErr, consts.ErrDBUniqueViolation) || errors.Is(cbErr, consts.ErrMailboxInvalidName) {
				return retry.Stop(cbErr)
			}
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}

		if err := tx.Commit(ctx); err != nil {
			return err // Let retry logic handle commit errors
		}

		return nil
	}, config)
}

func (rd *ResilientDatabase) DeleteMailboxWithRetry(ctx context.Context, mailboxID int64, userID int64) error {
	config := retry.BackoffConfig{MaxRetries: 2}
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
			// Assuming db.DeleteMailbox is refactored to accept a transaction.
			return nil, rd.getOperationalDatabaseForOperation(true).DeleteMailbox(writeCtx, tx, mailboxID, userID)
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
	}, config)
}

func (rd *ResilientDatabase) RenameMailboxWithRetry(ctx context.Context, mailboxID int64, userID int64, newName string, newParentID *int64) error {
	config := retry.BackoffConfig{MaxRetries: 2}
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
			// Assuming db.RenameMailbox is refactored to accept a transaction.
			return nil, rd.getOperationalDatabaseForOperation(true).RenameMailbox(writeCtx, tx, mailboxID, userID, newName, newParentID)
		})
		if cbErr != nil {
			if errors.Is(cbErr, consts.ErrMailboxAlreadyExists) || errors.Is(cbErr, consts.ErrMailboxInvalidName) {
				return retry.Stop(cbErr)
			}
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}

		if err := tx.Commit(ctx); err != nil {
			return err // Let retry logic handle commit errors
		}

		return nil
	}, config)
}

func (rd *ResilientDatabase) SetMailboxSubscribedWithRetry(ctx context.Context, mailboxID int64, userID int64, subscribed bool) error {
	config := retry.BackoffConfig{MaxRetries: 2}
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
			return nil, rd.getOperationalDatabaseForOperation(true).SetMailboxSubscribed(writeCtx, tx, mailboxID, userID, subscribed)
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
}

func (rd *ResilientDatabase) CountMessagesGreaterThanUIDWithRetry(ctx context.Context, mailboxID int64, minUID imap.UID) (uint32, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var count uint32
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).CountMessagesGreaterThanUID(readCtx, mailboxID, minUID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		count = result.(uint32)
		return nil
	}, config)
	return count, err
}

func (rd *ResilientDatabase) GetUniqueCustomFlagsForMailboxWithRetry(ctx context.Context, mailboxID int64) ([]string, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var flags []string
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetUniqueCustomFlagsForMailbox(readCtx, mailboxID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		flags = result.([]string)
		return nil
	}, config)
	return flags, err
}
