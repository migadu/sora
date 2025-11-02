package resilient

import (
	"context"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
)

// GetMetadataWithRetry retrieves metadata entries with retry logic.
func (rd *ResilientDatabase) GetMetadataWithRetry(ctx context.Context, AccountID int64, mailboxID *int64, entries []string, options *imap.GetMetadataOptions) (*imap.GetMetadataData, error) {
	type result struct {
		data *imap.GetMetadataData
	}

	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		data, err := rd.getOperationalDatabaseForOperation(false).GetMetadata(ctx, tx, AccountID, mailboxID, entries, options)
		if err != nil {
			return nil, err
		}
		return &result{data: data}, nil
	}

	res, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, err
	}

	return res.(*result).data, nil
}

// SetMetadataWithRetry sets metadata entries with retry logic and enforces configured limits.
func (rd *ResilientDatabase) SetMetadataWithRetry(ctx context.Context, AccountID int64, mailboxID *int64, entries map[string]*[]byte, limits *db.MetadataLimits) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		err := rd.getOperationalDatabaseForOperation(true).SetMetadata(ctx, tx, AccountID, mailboxID, entries, limits)
		return nil, err
	}

	_, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	return err
}
