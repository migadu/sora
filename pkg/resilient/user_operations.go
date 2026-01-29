package resilient

import (
	"context"

	"github.com/migadu/sora/db"
)

// GetAccountIDByEmailWithRetry retrieves account ID from email address with retry logic
func (rdb *ResilientDatabase) GetAccountIDByEmailWithRetry(ctx context.Context, email string) (int64, error) {
	config := readRetryConfig

	op := func(ctx context.Context) (any, error) {
		return rdb.getOperationalDatabaseForOperation(false).GetAccountIDByEmail(ctx, email)
	}

	result, err := rdb.executeReadWithRetry(ctx, config, timeoutRead, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

// GetMailboxesForUserWithRetry retrieves all mailboxes for an account with retry logic
func (rdb *ResilientDatabase) GetMailboxesForUserWithRetry(ctx context.Context, accountID int64, subscribed bool) ([]*db.DBMailbox, error) {
	config := readRetryConfig

	op := func(ctx context.Context) (any, error) {
		return rdb.getOperationalDatabaseForOperation(false).GetMailboxesForUser(ctx, accountID, subscribed)
	}

	result, err := rdb.executeReadWithRetry(ctx, config, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.([]*db.DBMailbox), nil
}

// GetMessageCountForMailboxWithRetry retrieves total message count with retry logic
func (rdb *ResilientDatabase) GetMessageCountForMailboxWithRetry(ctx context.Context, accountID int64, mailboxPath string) (int, error) {
	config := readRetryConfig

	op := func(ctx context.Context) (any, error) {
		return rdb.getOperationalDatabaseForOperation(false).GetMessageCountForMailbox(ctx, accountID, mailboxPath)
	}

	result, err := rdb.executeReadWithRetry(ctx, config, timeoutRead, op)
	if err != nil {
		return 0, err
	}
	return result.(int), nil
}

// GetUnseenCountForMailboxWithRetry retrieves unseen message count with retry logic
func (rdb *ResilientDatabase) GetUnseenCountForMailboxWithRetry(ctx context.Context, accountID int64, mailboxPath string) (int, error) {
	config := readRetryConfig

	op := func(ctx context.Context) (any, error) {
		return rdb.getOperationalDatabaseForOperation(false).GetUnseenCountForMailbox(ctx, accountID, mailboxPath)
	}

	result, err := rdb.executeReadWithRetry(ctx, config, timeoutRead, op)
	if err != nil {
		return 0, err
	}
	return result.(int), nil
}

// GetMessagesForMailboxWithRetry retrieves messages with pagination and retry logic
func (rdb *ResilientDatabase) GetMessagesForMailboxWithRetry(ctx context.Context, accountID int64, mailboxPath string, limit, offset int, unseenOnly bool) ([]*db.DBMessage, error) {
	config := readRetryConfig

	op := func(ctx context.Context) (any, error) {
		return rdb.getOperationalDatabaseForOperation(false).GetMessagesForMailbox(ctx, accountID, mailboxPath, limit, offset, unseenOnly)
	}

	result, err := rdb.executeReadWithRetry(ctx, config, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.([]*db.DBMessage), nil
}

// SearchMessagesInMailboxWithRetry performs full-text search with retry logic
func (rdb *ResilientDatabase) SearchMessagesInMailboxWithRetry(ctx context.Context, accountID int64, mailboxPath string, query string) ([]*db.DBMessage, error) {
	config := readRetryConfig

	op := func(ctx context.Context) (any, error) {
		return rdb.getOperationalDatabaseForOperation(false).SearchMessagesInMailbox(ctx, accountID, mailboxPath, query)
	}

	result, err := rdb.executeReadWithRetry(ctx, config, timeoutSearch, op)
	if err != nil {
		return nil, err
	}
	return result.([]*db.DBMessage), nil
}

// GetMessageByIDWithRetry retrieves a single message with retry logic
func (rdb *ResilientDatabase) GetMessageByIDWithRetry(ctx context.Context, accountID int64, messageID int64) (*db.DBMessage, error) {
	config := readRetryConfig

	op := func(ctx context.Context) (any, error) {
		return rdb.getOperationalDatabaseForOperation(false).GetMessageByID(ctx, accountID, messageID)
	}

	result, err := rdb.executeReadWithRetry(ctx, config, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.(*db.DBMessage), nil
}

// UpdateMessageFlagsWithRetry updates message flags with retry logic
func (rdb *ResilientDatabase) UpdateMessageFlagsWithRetry(ctx context.Context, accountID int64, messageID int64, addFlags, removeFlags []string) error {
	config := writeRetryConfig

	op := func(ctx context.Context) (any, error) {
		// UpdateMessageFlags handles its own transaction internally
		return nil, rdb.getOperationalDatabaseForOperation(true).UpdateMessageFlags(ctx, accountID, messageID, addFlags, removeFlags)
	}

	_, err := rdb.executeReadWithRetry(ctx, config, timeoutWrite, op)
	return err
}

// CreateMailboxForUserWithRetry creates a new mailbox with retry logic
func (rdb *ResilientDatabase) CreateMailboxForUserWithRetry(ctx context.Context, accountID int64, mailboxPath string) error {
	config := writeRetryConfig

	op := func(ctx context.Context) (any, error) {
		// CreateMailboxForUser handles its own transaction internally
		return nil, rdb.getOperationalDatabaseForOperation(true).CreateMailboxForUser(ctx, accountID, mailboxPath)
	}

	_, err := rdb.executeReadWithRetry(ctx, config, timeoutWrite, op)
	return err
}

// DeleteMailboxForUserWithRetry deletes a mailbox with retry logic
func (rdb *ResilientDatabase) DeleteMailboxForUserWithRetry(ctx context.Context, accountID int64, mailboxPath string) error {
	config := writeRetryConfig

	op := func(ctx context.Context) (any, error) {
		// DeleteMailboxForUser handles its own transaction internally
		return nil, rdb.getOperationalDatabaseForOperation(true).DeleteMailboxForUser(ctx, accountID, mailboxPath)
	}

	_, err := rdb.executeReadWithRetry(ctx, config, timeoutWrite, op)
	return err
}

// SubscribeToMailboxWithRetry marks mailbox as subscribed with retry logic
func (rdb *ResilientDatabase) SubscribeToMailboxWithRetry(ctx context.Context, accountID int64, mailboxPath string) error {
	config := writeRetryConfig

	op := func(ctx context.Context) (any, error) {
		// SubscribeToMailbox handles its own transaction internally
		return nil, rdb.getOperationalDatabaseForOperation(true).SubscribeToMailbox(ctx, accountID, mailboxPath)
	}

	_, err := rdb.executeReadWithRetry(ctx, config, timeoutWrite, op)
	return err
}

// UnsubscribeFromMailboxWithRetry marks mailbox as unsubscribed with retry logic
func (rdb *ResilientDatabase) UnsubscribeFromMailboxWithRetry(ctx context.Context, accountID int64, mailboxPath string) error {
	config := writeRetryConfig

	op := func(ctx context.Context) (any, error) {
		// UnsubscribeFromMailbox handles its own transaction internally
		return nil, rdb.getOperationalDatabaseForOperation(true).UnsubscribeFromMailbox(ctx, accountID, mailboxPath)
	}

	_, err := rdb.executeReadWithRetry(ctx, config, timeoutWrite, op)
	return err
}

// GetAllMessagesForUserVerificationWithRetry retrieves S3 info for all messages with retry logic
func (rdb *ResilientDatabase) GetAllMessagesForUserVerificationWithRetry(ctx context.Context, accountID int64) ([]db.MessageS3Info, error) {
	config := readRetryConfig

	op := func(ctx context.Context) (any, error) {
		return rdb.getOperationalDatabaseForOperation(false).GetAllMessagesForUserVerification(ctx, accountID)
	}

	result, err := rdb.executeReadWithRetry(ctx, config, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.([]db.MessageS3Info), nil
}

// GetMessagesByContentHashWithRetry retrieves all messages with a specific content hash with retry logic
func (rdb *ResilientDatabase) GetMessagesByContentHashWithRetry(ctx context.Context, accountID int64, contentHash string) ([]db.MessageHashInfo, error) {
	config := readRetryConfig

	op := func(ctx context.Context) (any, error) {
		return rdb.getOperationalDatabaseForOperation(false).GetMessagesByContentHash(ctx, accountID, contentHash)
	}

	result, err := rdb.executeReadWithRetry(ctx, config, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.([]db.MessageHashInfo), nil
}

// MarkMessagesAsNotUploadedWithRetry marks messages as not uploaded with retry logic
func (rdb *ResilientDatabase) MarkMessagesAsNotUploadedWithRetry(ctx context.Context, s3Keys []string) (int64, error) {
	config := writeRetryConfig

	op := func(ctx context.Context) (any, error) {
		return rdb.getOperationalDatabaseForOperation(true).MarkMessagesAsNotUploaded(ctx, s3Keys)
	}

	result, err := rdb.executeReadWithRetry(ctx, config, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}
