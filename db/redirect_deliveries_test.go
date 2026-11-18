package db

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// The record of which redirects a delivery queued (#1912): keyed by account, delivery
// and target, idempotent, and aged out by the redirect_log cleanup.
func TestRedirectDeliveries_RecordLookupCleanup(t *testing.T) {
	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	var accountID int64
	require.NoError(t, database.GetWritePool().QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&accountID))
	defer database.GetWritePool().Exec(ctx, `DELETE FROM redirect_deliveries WHERE account_id = $1`, accountID)
	defer database.GetWritePool().Exec(ctx, `DELETE FROM accounts WHERE id = $1`, accountID)

	inTx := func(f func(tx pgx.Tx) error) {
		t.Helper()
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, f(tx))
		require.NoError(t, tx.Commit(ctx))
	}
	const hash, oldHash = "hash-current", "hash-old"
	for _, to := range []string{"one@example.com", "two@example.org", "one@example.com"} {
		inTx(func(tx pgx.Tx) error { return database.RecordRedirectDelivery(ctx, tx, accountID, hash, to) })
	}
	inTx(func(tx pgx.Tx) error {
		return database.RecordRedirectDelivery(ctx, tx, accountID, oldHash, "one@example.com")
	})
	_, err := database.GetWritePool().Exec(ctx,
		`UPDATE redirect_deliveries SET created_at = now() - interval '2 hours' WHERE account_id = $1 AND delivery_hash = $2`, accountID, oldHash)
	require.NoError(t, err)

	got, err := database.RedirectedTargets(ctx, accountID, hash)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"one@example.com", "two@example.org"}, got)
	got, err = database.RedirectedTargets(ctx, accountID, "hash-other")
	require.NoError(t, err)
	require.Empty(t, got)
	got, err = database.RedirectedTargets(ctx, accountID+1, hash)
	require.NoError(t, err)
	require.Empty(t, got, "another account's delivery of the same bytes is not this one")

	inTx(func(tx pgx.Tx) error {
		_, err := database.CleanupOldRedirects(ctx, tx, time.Hour)
		return err
	})
	got, err = database.RedirectedTargets(ctx, accountID, oldHash)
	require.NoError(t, err)
	require.Empty(t, got, "a record older than the retention is deleted")
	got, err = database.RedirectedTargets(ctx, accountID, hash)
	require.NoError(t, err)
	require.Len(t, got, 2, "a record within the retention is kept")
}
