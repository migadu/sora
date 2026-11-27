package resilient

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// GetAccountQuotaWithRetry is db.GetAccountQuota for IMAP sessions (GETQUOTA,
// GETQUOTAROOT): a session read, with the session read budget.
func (rd *ResilientDatabase) GetAccountQuotaWithRetry(ctx context.Context, accountID int64) (*db.AccountQuota, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetAccountQuota(ctx, accountID)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op, consts.ErrUserNotFound)
	if err != nil {
		return nil, err
	}
	return result.(*db.AccountQuota), nil
}

// GetAccountQuotaByEmailWithRetry is db.GetAccountQuotaByEmail for the Admin API.
func (rd *ResilientDatabase) GetAccountQuotaByEmailWithRetry(ctx context.Context, email string) (*db.AccountQuota, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetAccountQuotaByEmail(ctx, email)
	}
	result, err := rd.executeReadWithRetry(ctx, adminRetryConfig, timeoutAdmin, op, consts.ErrUserNotFound)
	if err != nil {
		return nil, err
	}
	return result.(*db.AccountQuota), nil
}

// SetAccountStorageQuotaWithRetry is db.SetAccountStorageQuota for the Admin API.
func (rd *ResilientDatabase) SetAccountStorageQuotaWithRetry(ctx context.Context, email string, quota *int64) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).SetAccountStorageQuota(ctx, tx, email, quota)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, adminRetryConfig, timeoutAdmin, op)
	return err
}
