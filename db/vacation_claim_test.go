package db

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The loser starts its transaction before the winner commits. Its SELECT must
// nevertheless see that commit after waiting for the per-response lock, even
// when the connection normally uses a transaction-wide snapshot.
func TestVacationClaim_UsesFreshSnapshotAfterLock(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()
	var accountID int64
	require.NoError(t, database.GetWritePool().QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&accountID))
	defer database.GetWritePool().Exec(ctx, `DELETE FROM accounts WHERE id = $1`, accountID)

	for _, tc := range []struct {
		name         string
		period, hold time.Duration
		want         bool
	}{
		{"winner is visible", time.Hour, 0, false},
		{"period expires while waiting", 50 * time.Millisecond, 100 * time.Millisecond, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			winner, err := database.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer winner.Rollback(ctx)
			claimed, err := database.ClaimVacationResponse(ctx, winner, accountID, "sender@example.net", tc.name, tc.period)
			require.NoError(t, err)
			require.True(t, claimed)

			waiter, err := database.GetWritePool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
			require.NoError(t, err)
			defer waiter.Rollback(ctx)
			claimCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			type outcome struct {
				claimed bool
				err     error
			}
			done := make(chan outcome, 1)
			go func() {
				claimed, err := database.ClaimVacationResponse(claimCtx, waiter, accountID, "sender@example.net", tc.name, tc.period)
				done <- outcome{claimed, err}
			}()
			assert.Eventually(t, func() bool {
				var blocked bool
				err := database.GetWritePool().QueryRow(ctx, `SELECT EXISTS (
					SELECT 1 FROM pg_locks WHERE pid = $1 AND locktype = 'advisory' AND NOT granted
				)`, waiter.Conn().PgConn().PID()).Scan(&blocked)
				return err == nil && blocked
			}, time.Second, 5*time.Millisecond, "the second transaction must wait for the first claim")
			time.Sleep(tc.hold)
			require.NoError(t, winner.Commit(ctx))
			result := <-done
			require.NoError(t, result.err)
			require.Equal(t, tc.want, result.claimed)
			require.NoError(t, waiter.Commit(ctx))
		})
	}
}
