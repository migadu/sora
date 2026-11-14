package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
)

// VacationResponse represents a record of a vacation auto-response sent to a sender
type VacationResponse struct {
	ID               int64
	AccountID        int64
	SenderAddress    string
	ResponseIdentity string
	ResponseDate     time.Time
	CreatedAt        time.Time
}

// ClaimVacationResponse atomically consumes a response's suppression period. It
// must run in a fresh write transaction, committed before a winning reply is sent.
// A losing caller writes no history. Evaluation-time allowance checks are only
// an optimization: other deliveries may have passed them before this claim.
func (db *Database) ClaimVacationResponse(ctx context.Context, tx pgx.Tx, accountID int64, senderAddress, responseIdentity string, duration time.Duration) (bool, error) {
	// Each statement after waiting for the lock must see the preceding winner's
	// commit, even if the connection's default isolation is REPEATABLE READ.
	// Call this before any snapshot-taking statement in the transaction.
	if _, err := tx.Exec(ctx, `SET TRANSACTION ISOLATION LEVEL READ COMMITTED`); err != nil {
		return false, fmt.Errorf("set vacation claim isolation: %w", err)
	}
	// Length prefixes make the tuple unambiguous. Hash collisions only serialize
	// unrelated claims; the full tuple below always decides suppression.
	key := fmt.Sprintf("%d:%d:%s%d:%s", accountID, len(senderAddress), senderAddress, len(responseIdentity), responseIdentity)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`, consts.SoraVacationClaimLockClassID, key); err != nil {
		return false, fmt.Errorf("lock vacation response claim: %w", err)
	}
	// Keep this separate from the lock statement: a statement snapshot taken
	// before waiting for its lock would miss a winner that committed during it.
	var recent bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM vacation_responses
			WHERE account_id = $1 AND sender_address = $2 AND response_identity = $3
			  AND response_date > clock_timestamp() - $4::interval
		)
	`, accountID, senderAddress, responseIdentity, duration).Scan(&recent); err != nil {
		return false, fmt.Errorf("check vacation response claim: %w", err)
	}
	if recent {
		return false, nil
	}
	// The new period supersedes the key's older history: a later claim needs only the
	// most recent response, and the history is kept for the longest :days, so the
	// older rows would only make the table grow. Deleting them in the INSERT's own
	// statement costs no extra round trip; none of them can clash with the new row's
	// response_date, since the check above found every one outside the period.
	if _, err := tx.Exec(ctx, `
		WITH superseded AS (
			DELETE FROM vacation_responses
			WHERE account_id = $1 AND sender_address = $2 AND response_identity = $3
		)
		INSERT INTO vacation_responses (account_id, sender_address, response_identity, response_date, created_at)
		VALUES ($1, $2, $3, clock_timestamp(), clock_timestamp())
	`, accountID, senderAddress, responseIdentity); err != nil {
		return false, fmt.Errorf("record vacation response claim: %w", err)
	}
	return true, nil
}

// HasRecentVacationResponse checks if a vacation response was sent to this sender within the specified duration
func (db *Database) HasRecentVacationResponse(ctx context.Context, AccountID int64, senderAddress, responseIdentity string, duration time.Duration) (bool, error) {
	cutoffTime := time.Now().Add(-duration)

	var exists bool
	err := db.GetReadPool().QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM vacation_responses 
			WHERE account_id = $1 
			AND sender_address = $2 
			AND response_identity = $3
			AND response_date > $4
		)
	`, AccountID, senderAddress, responseIdentity, cutoffTime).Scan(&exists)

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
