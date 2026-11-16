package db

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// TestSentDateUnknownIndexMigration runs migration 000062 in isolated schemas: the index
// it builds on a small database, its refusal to build one with a blocking CREATE INDEX on
// a large one, its refusal of an INVALID index left by a failed CREATE INDEX CONCURRENTLY,
// and the catalog-only fast path once the index was built out-of-band, which must not
// wait for a lock on messages. The down file drops the index and is re-runnable.
func TestSentDateUnknownIndexMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	database := setupTestDatabase(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	up, err := os.ReadFile("migrations/000062_messages_sent_date_unknown_index.up.sql")
	require.NoError(t, err)
	down, err := os.ReadFile("migrations/000062_messages_sent_date_unknown_index.down.sql")
	require.NoError(t, err)
	const index = "idx_messages_mailbox_sent_date_unknown"

	open := func(t *testing.T, large bool) (*pgxpool.Conn, string) {
		t.Helper()
		conn, err := database.GetWritePool().Acquire(ctx)
		require.NoError(t, err)
		schema := fmt.Sprintf("sent_date_unknown_migration_%d", time.Now().UnixNano())
		quoted := pgx.Identifier{schema}.Sanitize()
		_, err = conn.Exec(ctx, "CREATE SCHEMA "+quoted)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, _ = conn.Exec(ctx, "RESET search_path")
			_, _ = conn.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE")
			conn.Release()
		})
		_, err = conn.Exec(ctx, "SET search_path = "+quoted)
		require.NoError(t, err)
		_, err = conn.Exec(ctx, `CREATE TABLE messages (
			id bigint, mailbox_id bigint, sent_date_unknown boolean, expunged_at timestamptz)`)
		require.NoError(t, err)
		if large {
			_, err = conn.Exec(ctx, `INSERT INTO messages(id, mailbox_id) SELECT g, 1 FROM generate_series(1, 25001) g`)
			require.NoError(t, err)
		}
		return conn, schema
	}
	indexState := func(t *testing.T, conn *pgxpool.Conn) (exists, valid bool) {
		t.Helper()
		require.NoError(t, conn.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL,
			COALESCE((SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid = to_regclass($1)), false)`,
			index).Scan(&exists, &valid))
		return exists, valid
	}

	t.Run("small database builds the partial index", func(t *testing.T) {
		conn, _ := open(t, false)
		_, err := conn.Exec(ctx, string(up))
		require.NoError(t, err)
		exists, valid := indexState(t, conn)
		require.True(t, exists && valid, "the migration must build a valid %s", index)
		var def string
		require.NoError(t, conn.QueryRow(ctx, `SELECT pg_get_indexdef(to_regclass($1))`, index).Scan(&def))
		require.Contains(t, def, "(mailbox_id, id)")
		require.Contains(t, def, "WHERE (sent_date_unknown AND (expunged_at IS NULL))")

		_, err = conn.Exec(ctx, string(down))
		require.NoError(t, err)
		exists, _ = indexState(t, conn)
		require.False(t, exists, "the down file must drop %s", index)
		_, err = conn.Exec(ctx, string(down))
		require.NoError(t, err, "the down file must be re-runnable")
	})

	t.Run("large database without the index refuses before DDL", func(t *testing.T) {
		conn, _ := open(t, true)
		_, err := conn.Exec(ctx, string(up))
		require.ErrorContains(t, err, "more than 25000")
		require.ErrorContains(t, err, "force 61")
		exists, _ := indexState(t, conn)
		require.False(t, exists)
	})

	t.Run("invalid index is refused", func(t *testing.T) {
		conn, _ := open(t, false)
		_, err := conn.Exec(ctx, `INSERT INTO messages(id) VALUES (1), (1)`)
		require.NoError(t, err)
		_, err = conn.Exec(ctx, `CREATE UNIQUE INDEX CONCURRENTLY `+index+` ON messages (id)`)
		require.Error(t, err, "duplicate ids must leave an invalid concurrent index")
		_, err = conn.Exec(ctx, string(up))
		require.Error(t, err)
		require.Contains(t, strings.ToUpper(err.Error()), "INVALID")
		require.ErrorContains(t, err, "force 61")
	})

	t.Run("index built out-of-band: only the catalog is read", func(t *testing.T) {
		conn, schema := open(t, true)
		_, err := conn.Exec(ctx, `CREATE INDEX CONCURRENTLY IF NOT EXISTS `+index+`
			ON messages (mailbox_id, id) WHERE sent_date_unknown AND expunged_at IS NULL`)
		require.NoError(t, err)

		locker, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer locker.Rollback(ctx)
		_, err = locker.Exec(ctx, "LOCK TABLE "+pgx.Identifier{schema, "messages"}.Sanitize()+" IN ACCESS EXCLUSIVE MODE")
		require.NoError(t, err)
		_, err = conn.Exec(ctx, "SET lock_timeout = '200ms'")
		require.NoError(t, err)
		defer conn.Exec(ctx, "RESET lock_timeout")
		_, err = conn.Exec(ctx, string(up))
		require.NoError(t, err, "a prepared database must only be inspected, even with messages exclusively locked")
	})
}
