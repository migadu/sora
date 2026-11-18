package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// RecordRedirect records that a redirect action was performed for the given account.
func (db *Database) RecordRedirect(ctx context.Context, tx pgx.Tx, accountID int64) error {
	now := time.Now()
	_, err := tx.Exec(ctx, `
		INSERT INTO redirect_log (account_id, redirect_date, created_at)
		VALUES ($1, $2, $3)
	`, accountID, now, now)

	return err
}

// CountRedirectsSince returns the number of redirects performed by the given account within the specified duration window.
func (db *Database) CountRedirectsSince(ctx context.Context, accountID int64, window time.Duration) (int, error) {
	cutoffTime := time.Now().Add(-window)

	var count int
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT COUNT(*) FROM redirect_log 
		WHERE account_id = $1 
		AND redirect_date > $2
	`, accountID, cutoffTime).Scan(&count)

	return count, err
}

// RedirectedTargets returns the redirect targets the account's delivery of the message
// identified by deliveryHash (see InsertMessageOptions.DeliveryHash) has already handed to
// the relay queue. It reads the primary: the retry of a delivery can follow it within
// seconds, before a replica has the row.
func (db *Database) RedirectedTargets(ctx context.Context, accountID int64, deliveryHash string) ([]string, error) {
	rows, err := db.GetWritePool().Query(ctx, `
		SELECT redirect_to FROM redirect_deliveries
		WHERE account_id = $1 AND delivery_hash = $2
	`, accountID, deliveryHash)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// RecordRedirectDelivery records that the account's delivery of the message identified by
// deliveryHash has handed its redirect to redirectTo to the relay queue, so a retry of that
// delivery does not queue it again.
func (db *Database) RecordRedirectDelivery(ctx context.Context, tx pgx.Tx, accountID int64, deliveryHash, redirectTo string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO redirect_deliveries (account_id, delivery_hash, redirect_to)
		VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING
	`, accountID, deliveryHash, redirectTo)
	return err
}

// CleanupOldRedirects removes redirect log records, and the records of which deliveries
// were redirected (RecordRedirectDelivery), older than the specified duration.
func (db *Database) CleanupOldRedirects(ctx context.Context, tx pgx.Tx, olderThan time.Duration) (int64, error) {
	cutoffTime := time.Now().Add(-olderThan)

	result, err := tx.Exec(ctx, `
		DELETE FROM redirect_log
		WHERE redirect_date < $1
	`, cutoffTime)

	if err != nil {
		return 0, err
	}

	deliveries, err := tx.Exec(ctx, `
		DELETE FROM redirect_deliveries
		WHERE created_at < $1
	`, cutoffTime)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected() + deliveries.RowsAffected(), nil
}
