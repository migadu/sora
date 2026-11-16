//go:build integration

package db

import (
	"context"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

// A catalog check can race a documented out-of-band add/drop after it has
// chosen the ALTER branch. Observe the actual lock wait before changing schema.
func TestRestoredAtMigrationToleratesConcurrentOutOfBandDDL(t *testing.T) {
	d := setupTestDatabase(t)
	defer d.Close()
	base := context.Background()
	up, e := os.ReadFile("migrations/000067_messages_restored_at.up.sql")
	require.NoError(t, e)
	down, e := os.ReadFile("migrations/000067_messages_restored_at.down.sql")
	require.NoError(t, e)
	defer d.GetWritePool().Exec(base, string(up))
	for _, tc := range []struct {
		name         string
		prepare, sql []byte
		external     string
	}{
		{"add", down, up, "ALTER TABLE messages ADD COLUMN IF NOT EXISTS restored_at TIMESTAMPTZ"},
		{"drop", up, down, "ALTER TABLE messages DROP COLUMN IF EXISTS restored_at"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, e := d.GetWritePool().Exec(base, string(tc.prepare))
			require.NoError(t, e)
			ctx, cancel := context.WithTimeout(base, 10*time.Second)
			defer cancel()
			block, e := d.GetWritePool().Begin(ctx)
			require.NoError(t, e)
			defer block.Rollback(base)
			_, e = block.Exec(ctx, "LOCK TABLE messages IN ACCESS EXCLUSIVE MODE")
			require.NoError(t, e)
			blockerPID := backendPID(t, block)
			conn, e := d.GetWritePool().Acquire(ctx)
			require.NoError(t, e)
			var pid int
			require.NoError(t, conn.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid))
			done := make(chan error, 1)
			finished := false
			defer func() {
				cancel()
				_ = block.Rollback(base)
				if !finished {
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("DDL waiter did not stop")
					}
				}
				conn.Release()
			}()
			go func() { _, e := conn.Exec(ctx, string(tc.sql)); done <- e }()
			require.Eventually(t, func() bool {
				var waited bool
				e := d.GetWritePool().QueryRow(base, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND $2=ANY(pg_blocking_pids(pid)))", pid, blockerPID).Scan(&waited)
				return e == nil && waited
			}, 3*time.Second, 5*time.Millisecond)
			_, e = block.Exec(ctx, tc.external)
			require.NoError(t, e)
			require.NoError(t, block.Commit(ctx))
			select {
			case e = <-done:
				finished = true
			case <-time.After(5 * time.Second):
				t.Fatal("DDL waiter did not finish")
			}
			require.NoError(t, e, "catalog branch must tolerate out-of-band DDL winning while ALTER waited")
		})
	}
}
