package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Every redirect_log row keeps the window that charged it (expires_at - redirect_date), so
// a node can see redirects charged under a redirect_rate_window other than its own (#1994):
// windows of rows still inside their window, other than the node's, rounded to the second.
func TestRedirectRateWindowsOtherThan(t *testing.T) {
	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	var accountID int64
	require.NoError(t, database.GetWritePool().QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&accountID))
	defer database.GetWritePool().Exec(ctx, `DELETE FROM redirect_log WHERE account_id = $1`, accountID)
	defer database.GetWritePool().Exec(ctx, `DELETE FROM accounts WHERE id = $1`, accountID)
	// Other packages share the database and its redirect_log: the windows below are ones
	// no other test uses, and the assertions are about them alone.
	const local, shorter, longer, passed = 61 * time.Minute, 7*time.Hour + 7*time.Minute, 23*time.Hour + 23*time.Minute, 37 * time.Minute

	record := func(window time.Duration) {
		t.Helper()
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, database.RecordRedirect(ctx, tx, accountID, window, 100))
		require.NoError(t, tx.Commit(ctx))
	}
	for _, window := range []time.Duration{local, longer, shorter, 0, passed} {
		record(window)
	}
	// The redirect charged under the 37m window was charged an hour ago: its window has passed.
	_, err := database.GetWritePool().Exec(ctx, `
		UPDATE redirect_log SET redirect_date = redirect_date - interval '1 hour',
			created_at = created_at - interval '1 hour', expires_at = expires_at - interval '1 hour'
		WHERE account_id = $1 AND expires_at - redirect_date = interval '37 minutes'`, accountID)
	require.NoError(t, err)

	other, err := database.RedirectRateWindowsOtherThan(ctx, []time.Duration{local})
	require.NoError(t, err)
	require.Contains(t, other, shorter)
	require.Contains(t, other, longer)
	require.NotContains(t, other, local, "the node's own window")
	require.NotContains(t, other, passed, "a redirect whose window has passed no longer counts on any node")

	other, err = database.RedirectRateWindowsOtherThan(ctx, []time.Duration{local, shorter, longer})
	require.NoError(t, err)
	require.NotContains(t, other, shorter)
	require.NotContains(t, other, longer)
}
