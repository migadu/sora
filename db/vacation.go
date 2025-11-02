package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// VacationResponse represents a record of a vacation auto-response sent to a sender
type VacationResponse struct {
	ID            int64
	AccountID     int64
	SenderAddress string
	ResponseDate  time.Time
	CreatedAt     time.Time
}

// RecordVacationResponse records that a vacation response was sent to a specific sender
func (db *Database) RecordVacationResponse(ctx context.Context, tx pgx.Tx, AccountID int64, senderAddress string) error {
	now := time.Now()
	_, err := tx.Exec(ctx, `
		INSERT INTO vacation_responses (account_id, sender_address, response_date, created_at)
		VALUES ($1, $2, $3, $4)
	`, AccountID, senderAddress, now, now)

	return err
}

// HasRecentVacationResponse checks if a vacation response was sent to this sender within the specified duration
func (db *Database) HasRecentVacationResponse(ctx context.Context, AccountID int64, senderAddress string, duration time.Duration) (bool, error) {
	cutoffTime := time.Now().Add(-duration)

	var exists bool
	err := db.GetReadPool().QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM vacation_responses 
			WHERE account_id = $1 
			AND sender_address = $2 
			AND response_date > $3
		)
	`, AccountID, senderAddress, cutoffTime).Scan(&exists)

	return exists, err
}

// CleanupOldVacationResponses removes vacation response records older than the specified duration
func (db *Database) CleanupOldVacationResponses(ctx context.Context, tx pgx.Tx, olderThan time.Duration) (int64, error) {
	cutoffTime := time.Now().Add(-olderThan)

	result, err := tx.Exec(ctx, `
		DELETE FROM vacation_responses
		WHERE response_date < $1
	`, cutoffTime)

	if err != nil {
		return 0, err
	}

	return result.RowsAffected(), nil
}
