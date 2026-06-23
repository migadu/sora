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
	err := db.GetReadPool().QueryRow(ctx, `
		SELECT COUNT(*) FROM redirect_log 
		WHERE account_id = $1 
		AND redirect_date > $2
	`, accountID, cutoffTime).Scan(&count)

	return count, err
}

// CleanupOldRedirects removes redirect log records older than the specified duration.
func (db *Database) CleanupOldRedirects(ctx context.Context, tx pgx.Tx, olderThan time.Duration) (int64, error) {
	cutoffTime := time.Now().Add(-olderThan)

	result, err := tx.Exec(ctx, `
		DELETE FROM redirect_log
		WHERE redirect_date < $1
	`, cutoffTime)

	if err != nil {
		return 0, err
	}

	return result.RowsAffected(), nil
}
