package resilient

import (
	"context"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server"
)

// --- Mailbox and Message Wrappers ---

func (rd *ResilientDatabase) GetMailboxByNameWithRetry(ctx context.Context, userID int64, name string) (*db.DBMailbox, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetMailboxByName(ctx, userID, name)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op, consts.ErrMailboxNotFound)
	if err != nil {
		return nil, err
	}
	return result.(*db.DBMailbox), nil
}

func (rd *ResilientDatabase) InsertMessageWithRetry(ctx context.Context, options *db.InsertMessageOptions, upload db.PendingUpload) (messageID int64, uid int64, err error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		id, u, opErr := rd.getOperationalDatabaseForOperation(true).InsertMessage(ctx, tx, options, upload)
		if opErr != nil {
			return nil, opErr
		}
		return []int64{id, u}, nil
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, 0, err
	}
	resSlice := result.([]int64)
	return resSlice[0], resSlice[1], nil
}

func (rd *ResilientDatabase) GetMessagesByNumSetWithRetry(ctx context.Context, mailboxID int64, numSet imap.NumSet) ([]db.Message, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetMessagesByNumSet(ctx, mailboxID, numSet)
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

func (rd *ResilientDatabase) GetMailboxSummaryWithRetry(ctx context.Context, mailboxID int64) (*db.MailboxSummary, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetMailboxSummary(ctx, mailboxID)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.(*db.MailboxSummary), nil
}

func (rd *ResilientDatabase) GetMailboxesWithRetry(ctx context.Context, userID int64, subscribed bool) ([]*db.DBMailbox, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetMailboxes(ctx, userID, subscribed)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []*db.DBMailbox{}, nil
	}
	return result.([]*db.DBMailbox), nil
}

func (rd *ResilientDatabase) GetAccountIDByAddressWithRetry(ctx context.Context, address string) (int64, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetAccountIDByAddress(ctx, address)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op, consts.ErrUserNotFound)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) CreateDefaultMailboxesWithRetry(ctx context.Context, userID int64) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).CreateDefaultMailboxes(ctx, tx, userID)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	return err
}

func (rd *ResilientDatabase) PollMailboxWithRetry(ctx context.Context, mailboxID int64, sinceModSeq uint64) (*db.MailboxPoll, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).PollMailbox(ctx, mailboxID, sinceModSeq)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.(*db.MailboxPoll), nil
}

func (rd *ResilientDatabase) GetMessagesByFlagWithRetry(ctx context.Context, mailboxID int64, flag imap.Flag) ([]db.Message, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetMessagesByFlag(ctx, mailboxID, flag)
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

func (rd *ResilientDatabase) ExpungeMessageUIDsWithRetry(ctx context.Context, mailboxID int64, uids ...imap.UID) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).ExpungeMessageUIDs(ctx, tx, mailboxID, uids...)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) GetPrimaryEmailForAccountWithRetry(ctx context.Context, accountID int64) (server.Address, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetPrimaryEmailForAccount(ctx, accountID)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op, consts.ErrUserNotFound)
	if err != nil {
		return server.Address{}, err
	}
	return result.(server.Address), nil
}

// --- Mailbox Management Wrappers ---

func (rd *ResilientDatabase) CopyMessagesWithRetry(ctx context.Context, uids *[]imap.UID, srcMailboxID, destMailboxID int64, userID int64) (map[imap.UID]imap.UID, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).CopyMessages(ctx, tx, uids, srcMailboxID, destMailboxID, userID)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, err
	}
	return result.(map[imap.UID]imap.UID), nil
}

func (rd *ResilientDatabase) CreateMailboxWithRetry(ctx context.Context, userID int64, name string, parentID *int64) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).CreateMailbox(ctx, tx, userID, name, parentID)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op, consts.ErrDBUniqueViolation, consts.ErrMailboxInvalidName)
	return err
}

func (rd *ResilientDatabase) DeleteMailboxWithRetry(ctx context.Context, mailboxID int64, userID int64) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).DeleteMailbox(ctx, tx, mailboxID, userID)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	return err
}

func (rd *ResilientDatabase) RenameMailboxWithRetry(ctx context.Context, mailboxID int64, userID int64, newName string, newParentID *int64) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).RenameMailbox(ctx, tx, mailboxID, userID, newName, newParentID)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op, consts.ErrMailboxAlreadyExists, consts.ErrMailboxInvalidName)
	return err
}

func (rd *ResilientDatabase) SetMailboxSubscribedWithRetry(ctx context.Context, mailboxID int64, userID int64, subscribed bool) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).SetMailboxSubscribed(ctx, tx, mailboxID, userID, subscribed)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	return err
}

func (rd *ResilientDatabase) CountMessagesGreaterThanUIDWithRetry(ctx context.Context, mailboxID int64, minUID imap.UID) (uint32, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).CountMessagesGreaterThanUID(ctx, mailboxID, minUID)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return 0, err
	}
	return result.(uint32), nil
}

func (rd *ResilientDatabase) GetUniqueCustomFlagsForMailboxWithRetry(ctx context.Context, mailboxID int64) ([]string, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetUniqueCustomFlagsForMailbox(ctx, mailboxID)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []string{}, nil
	}
	return result.([]string), nil
}
