package resilient

import (
	"context"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
)

// --- Flag Management Wrappers ---

func (rd *ResilientDatabase) AddMessageFlagsWithRetry(ctx context.Context, messageUID imap.UID, mailboxID int64, newFlags []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	type flagUpdateResult struct {
		flags  []imap.Flag
		modSeq int64
	}
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		flags, modSeq, err := rd.getOperationalDatabaseForOperation(true).AddMessageFlags(ctx, tx, messageUID, mailboxID, newFlags)
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
		flags, modSeq, err := rd.getOperationalDatabaseForOperation(true).RemoveMessageFlags(ctx, tx, messageUID, mailboxID, flagsToRemove)
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
		flags, modSeq, err := rd.getOperationalDatabaseForOperation(true).SetMessageFlags(ctx, tx, messageUID, mailboxID, newFlags)
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

func (rd *ResilientDatabase) GetMessageEnvelopeWithRetry(ctx context.Context, UID imap.UID, mailboxID int64) (*imap.Envelope, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).GetMessageEnvelope(ctx, UID, mailboxID)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.(*imap.Envelope), nil
}

func (rd *ResilientDatabase) GetMessageHeadersWithRetry(ctx context.Context, messageUID imap.UID, mailboxID int64) (string, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).GetMessageHeaders(ctx, messageUID, mailboxID)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return "", err
	}
	return result.(string), nil
}

func (rd *ResilientDatabase) GetMessageTextBodyWithRetry(ctx context.Context, uid imap.UID, mailboxID int64) (string, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).GetMessageTextBody(ctx, uid, mailboxID)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return "", err
	}
	return result.(string), nil
}

func (rd *ResilientDatabase) GetMessagesSorted(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, sortCriteria []imap.SortCriterion, limit int) ([]db.Message, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).GetMessagesSorted(ctx, mailboxID, criteria, sortCriteria, limit)
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

func (rd *ResilientDatabase) MoveMessagesWithRetry(ctx context.Context, ids *[]imap.UID, srcMailboxID, destMailboxID int64, AccountID int64) (map[imap.UID]imap.UID, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(true).MoveMessages(ctx, tx, ids, srcMailboxID, destMailboxID, AccountID)
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
		c, s, err := rd.getOperationalDatabaseForOperation(false).GetMailboxMessageCountAndSizeSum(ctx, mailboxID)
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
		return rd.getOperationalDatabaseForOperation(false).ListMessages(ctx, mailboxID)
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

func (rd *ResilientDatabase) GetMessagesWithCriteriaWithRetry(ctx context.Context, mailboxID int64, criteria *imap.SearchCriteria, limit int) ([]db.Message, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).GetMessagesWithCriteria(ctx, mailboxID, criteria, limit)
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

// --- Message Restoration Wrappers ---

func (rd *ResilientDatabase) ListDeletedMessagesWithRetry(ctx context.Context, params db.ListDeletedMessagesParams) ([]db.DeletedMessage, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(false).ListDeletedMessages(ctx, params)
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

func (rd *ResilientDatabase) RestoreMessagesWithRetry(ctx context.Context, params db.RestoreMessagesParams) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(true).RestoreMessages(ctx, tx, params)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}
