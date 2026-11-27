package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/server"
)

// AccountQuota is an account's storage limit and what it uses of it.
type AccountQuota struct {
	// StorageQuota is the limit in bytes (accounts.storage_quota); nil is unlimited.
	StorageQuota *int64 `json:"storage_quota"`
	// StorageUsed is the size in bytes of the messages in the account's live mailboxes,
	// summed from the mailbox_stats cache as the account listings sum it, so IMAP QUOTA
	// and /admin/usage/accounts report the same figure.
	StorageUsed int64 `json:"storage_used"`
}

// ValidateStorageQuota checks a storage limit: nil (unlimited) or more than 0 bytes,
// as the accounts_storage_quota_positive constraint requires.
func ValidateStorageQuota(quota *int64) error {
	if quota != nil && *quota <= 0 {
		return fmt.Errorf("storage quota must be more than 0 bytes, or null for unlimited (got %d)", *quota)
	}
	return nil
}

// accountQuotaQuery reads one account's limit and usage; $1 is the account ID. The
// usage comes from accountUsage, the same mailbox_stats sum the account listings use:
// cheap enough for clients that ask GETQUOTAROOT on every SELECT, which a live
// SUM(messages.size) over a large account is not.
const accountQuotaQuery = `
	SELECT a.storage_quota, s.storage_used
	FROM accounts a` + accountUsage + `
	WHERE a.id = $1`

// GetAccountQuota returns the storage limit and usage of an account, or
// consts.ErrUserNotFound when there is no such account.
func (db *Database) GetAccountQuota(ctx context.Context, accountID int64) (*AccountQuota, error) {
	var q AccountQuota
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, accountQuotaQuery, accountID).Scan(&q.StorageQuota, &q.StorageUsed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, consts.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get account quota: %w", err)
	}
	return &q, nil
}

// GetAccountQuotaByEmail returns the storage limit and usage of the account that
// owns the address (any of its credentials), soft-deleted or not. An unknown address
// is consts.ErrUserNotFound; a malformed one wraps server.ErrInvalidAddress.
func (db *Database) GetAccountQuotaByEmail(ctx context.Context, email string) (*AccountQuota, error) {
	address, err := server.NewAddress(email)
	if err != nil {
		return nil, fmt.Errorf("invalid email address: %w", err)
	}
	var accountID int64
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx,
		"SELECT account_id FROM credentials WHERE LOWER(address) = $1", address.FullAddress()).Scan(&accountID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, consts.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find account: %w", err)
	}
	return db.GetAccountQuota(ctx, accountID)
}

// SetAccountStorageQuota sets the storage limit, in bytes, of the account that owns
// the address; nil makes it unlimited. A limit of 0 or less is ErrInvalidAccountRequest,
// an unknown address consts.ErrUserNotFound.
func (db *Database) SetAccountStorageQuota(ctx context.Context, tx pgx.Tx, email string, quota *int64) error {
	address, err := server.NewAddress(email)
	if err != nil {
		return fmt.Errorf("%w: invalid email address: %w", ErrInvalidAccountRequest, err)
	}
	if err := ValidateStorageQuota(quota); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAccountRequest, err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE accounts SET storage_quota = $2
		WHERE id = (SELECT account_id FROM credentials WHERE LOWER(address) = $1)
	`, address.FullAddress(), quota)
	if err != nil {
		return fmt.Errorf("failed to set storage quota: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: account with email %s does not exist", consts.ErrUserNotFound, address.FullAddress())
	}
	return nil
}
