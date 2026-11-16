package db

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Two activations of different scripts of one account, the second starting while the
// first is uncommitted. The second read which script was active before the first
// committed, so it cleared nothing and then set its own script active next to the
// first one's, failing on idx_sieve_scripts_account_id_one_active (23505). In either
// serial order both succeed, and the later one leaves its script active.
func TestSetScriptActive_ConcurrentActivationsOfDifferentScripts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	database := setupTestDatabase(t)

	type activateFunc func(ctx context.Context, tx pgx.Tx, accountID int64, s *SieveScript) error
	byID := activateFunc(func(ctx context.Context, tx pgx.Tx, accountID int64, s *SieveScript) error {
		return database.SetScriptActive(ctx, tx, s.ID, accountID, true)
	})
	byName := activateFunc(func(ctx context.Context, tx pgx.Tx, accountID int64, s *SieveScript) error {
		return database.SetScriptActiveByName(ctx, tx, accountID, s.Name, true)
	})

	for _, tc := range []struct {
		name          string
		first, second activateFunc
	}{
		{"by ID then by ID", byID, byID},
		{"by name then by name", byName, byName},
		{"by ID then by name", byID, byName},
		{"by name then by ID", byName, byID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			accountID := createTestAccountForSieve(t, database, ctx)

			var f, g *SieveScript
			require.NoError(t, inSieveTx(t, database, ctx, func(tx pgx.Tx) error {
				h, err := database.CreateScript(ctx, tx, accountID, "h", "keep;")
				if err != nil {
					return err
				}
				if err := database.SetScriptActive(ctx, tx, h.ID, accountID, true); err != nil {
					return err
				}
				if f, err = database.CreateScript(ctx, tx, accountID, "f", "keep;"); err != nil {
					return err
				}
				g, err = database.CreateScript(ctx, tx, accountID, "g", "keep;")
				return err
			}))

			// The first activation has run and is not committed yet.
			first, err := database.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer first.Rollback(context.Background())
			require.NoError(t, tc.first(ctx, first, accountID, f), "first activation")

			pidCh := make(chan uint32, 1)
			secondErr := make(chan error, 1)
			go func() {
				tx, err := database.GetWritePool().Begin(ctx)
				if err != nil {
					secondErr <- err
					return
				}
				defer tx.Rollback(context.Background())
				var pid uint32
				if err := tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
					secondErr <- err
					return
				}
				pidCh <- pid
				if err := tc.second(ctx, tx, accountID, g); err != nil {
					secondErr <- err
					return
				}
				secondErr <- tx.Commit(ctx)
			}()

			var pid uint32
			select {
			case pid = <-pidCh:
			case err := <-secondErr:
				t.Fatalf("second activation failed to start: %v", err)
			}
			for {
				var waitType *string
				require.NoError(t, database.GetWritePool().QueryRow(ctx,
					"SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1", pid).Scan(&waitType))
				if waitType != nil && *waitType == "Lock" {
					break
				}
				select {
				case err := <-secondErr:
					t.Fatalf("second activation finished while the first was open: %v", err)
				case <-ctx.Done():
					t.Fatal("timed out waiting for the second activation to block")
				case <-time.After(10 * time.Millisecond):
				}
			}

			require.NoError(t, first.Commit(ctx), "first activation")
			require.NoError(t, <-secondErr, "second activation")

			rows, err := database.GetWritePool().Query(ctx,
				"SELECT name FROM sieve_scripts WHERE account_id = $1 AND active", accountID)
			require.NoError(t, err)
			active, err := pgx.CollectRows(rows, pgx.RowTo[string])
			require.NoError(t, err)
			require.Equal(t, []string{"g"}, active)
		})
	}
}
