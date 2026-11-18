package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Every redirect_log row keeps the redirect_rate_limit that charged it, so a node can see
// redirects charged under a limit other than its own (#2020): limits of rows still inside
// their window, other than the node's.
func TestRedirectRateLimitsOtherThan(t *testing.T) {
	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	var accountID int64
	require.NoError(t, database.GetWritePool().QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&accountID))
	defer database.GetWritePool().Exec(ctx, `DELETE FROM redirect_log WHERE account_id = $1`, accountID)
	defer database.GetWritePool().Exec(ctx, `DELETE FROM accounts WHERE id = $1`, accountID)
	// Other packages share the database and its redirect_log: the limits below are ones no
	// other test uses, and the assertions are about them alone.
	const local, smaller, larger, passed = 7101, 7103, 7107, 7109

	record := func(window time.Duration, limit int) {
		t.Helper()
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, database.RecordRedirect(ctx, tx, accountID, window, limit))
		require.NoError(t, tx.Commit(ctx))
	}
	record(time.Hour, local)
	record(time.Hour, larger)
	record(time.Hour, smaller)
	record(time.Hour, passed)
	// The redirect charged under limit 7109 was charged two hours ago: its window has passed.
	_, err := database.GetWritePool().Exec(ctx, `
		UPDATE redirect_log SET redirect_date = redirect_date - interval '2 hours',
			created_at = created_at - interval '2 hours', expires_at = expires_at - interval '2 hours'
		WHERE account_id = $1 AND rate_limit = $2`, accountID, passed)
	require.NoError(t, err)

	other, err := database.RedirectRateLimitsOtherThan(ctx, []int{local})
	require.NoError(t, err)
	require.Contains(t, other, smaller)
	require.Contains(t, other, larger)
	require.NotContains(t, other, local, "the node's own limit")
	require.NotContains(t, other, passed, "a redirect whose window has passed no longer counts on any node")

	other, err = database.RedirectRateLimitsOtherThan(ctx, []int{local, smaller, larger})
	require.NoError(t, err)
	require.NotContains(t, other, smaller)
	require.NotContains(t, other, larger)
}
