package db

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// A redirect_log row is kept until the window it was charged under has passed, whatever
// retention the cleaning node computes from its own config (#1959). A row without that
// window, written before migration 75 or by an older binary, goes at the retention.
func TestCleanupOldRedirects_KeepsRowsUntilTheirWindowEnds(t *testing.T) {
	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	var accountID int64
	require.NoError(t, database.GetWritePool().QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&accountID))
	defer database.GetWritePool().Exec(ctx, `DELETE FROM redirect_log WHERE account_id = $1`, accountID)
	defer database.GetWritePool().Exec(ctx, `DELETE FROM accounts WHERE id = $1`, accountID)

	inTx := func(f func(tx pgx.Tx) error) {
		t.Helper()
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, f(tx))
		require.NoError(t, tx.Commit(ctx))
	}
	// Three redirects, all 2h old: one charged under a 24h window, one under a 1h window,
	// and one with no window recorded (an older binary).
	for _, window := range []time.Duration{24 * time.Hour, time.Hour, 0} {
		inTx(func(tx pgx.Tx) error { return database.RecordRedirect(ctx, tx, accountID, window) })
	}
	_, err := database.GetWritePool().Exec(ctx, `
		UPDATE redirect_log SET redirect_date = redirect_date - interval '2 hours',
			created_at = created_at - interval '2 hours', expires_at = expires_at - interval '2 hours'
		WHERE account_id = $1`, accountID)
	require.NoError(t, err)

	inTx(func(tx pgx.Tx) error {
		_, err := database.CleanupOldRedirects(ctx, tx, time.Hour)
		return err
	})
	rows, err := database.GetWritePool().Query(ctx, `
		SELECT EXTRACT(EPOCH FROM expires_at - redirect_date)::float8 FROM redirect_log WHERE account_id = $1`, accountID)
	require.NoError(t, err)
	windows, err := pgx.CollectRows(rows, pgx.RowTo[*float64])
	require.NoError(t, err)
	require.Len(t, windows, 1, "only the row inside its own 24h window survives a 1h retention")
	require.NotNil(t, windows[0])
	require.Equal(t, (24 * time.Hour).Seconds(), *windows[0])

	n, err := database.CountRedirectsSince(ctx, accountID, 24*time.Hour)
	require.NoError(t, err)
	require.Equal(t, 1, n)
}
