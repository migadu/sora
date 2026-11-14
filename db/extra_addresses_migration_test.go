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

// Run the exact migration in isolated schemas, including its large-table refusal
// and catalog-only fast path, without modifying this database's real messages.
func TestExtraAddressesMigrationPreparation(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	database := setupTestDatabase(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	up, err := os.ReadFile("migrations/000059_messages_extra_addresses.up.sql")
	require.NoError(t, err)
	open := func(t *testing.T, large bool) (*pgxpool.Conn, string) {
		t.Helper()
		conn, err := database.GetWritePool().Acquire(ctx)
		require.NoError(t, err)
		schema := fmt.Sprintf("extra_migration_%d", time.Now().UnixNano())
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
			id bigint, uid bigint, mailbox_id bigint, content_hash text,
			created_modseq bigint, expunged_modseq bigint, internal_date timestamptz,
			sent_date timestamptz, size integer, subject text, subject_sort text,
			from_email_sort text, from_name_sort text, to_email_sort text,
			to_name_sort text, cc_email_sort text, expunged_at timestamptz);
			CREATE INDEX idx_messages_mailbox_headers ON messages(mailbox_id)`)
		require.NoError(t, err)
		if large {
			_, err = conn.Exec(ctx, `INSERT INTO messages(id) SELECT generate_series(1,25001)`)
			require.NoError(t, err)
		}
		return conn, schema
	}

	t.Run("small database migrates", func(t *testing.T) {
		conn, _ := open(t, false)
		_, err := conn.Exec(ctx, string(up))
		require.NoError(t, err)
		var ready bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT indisvalid AND indisready
			FROM pg_index WHERE indexrelid = 'idx_messages_mailbox_headers_v2'::regclass`).Scan(&ready))
		require.True(t, ready)
		var oldExists bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT to_regclass('idx_messages_mailbox_headers') IS NOT NULL`).Scan(&oldExists))
		require.False(t, oldExists)
	})

	t.Run("large unprepared database refuses before DDL", func(t *testing.T) {
		conn, _ := open(t, true)
		_, err := conn.Exec(ctx, string(up))
		require.ErrorContains(t, err, "more than 25000")
		require.ErrorContains(t, err, "force 58")
		var hasColumn bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_attribute
			WHERE attrelid = 'messages'::regclass AND attname = 'extra_addresses' AND NOT attisdropped)`).Scan(&hasColumn))
		require.False(t, hasColumn)
	})

	t.Run("prepared large database never locks messages", func(t *testing.T) {
		conn, schema := open(t, false)
		_, err := conn.Exec(ctx, string(up))
		require.NoError(t, err)
		_, err = conn.Exec(ctx, `INSERT INTO messages(id) SELECT generate_series(1,25001)`)
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
		require.NoError(t, err, "the prepared migration must only inspect catalogs, even with messages exclusively locked")
	})

	t.Run("invalid concurrent index preserves old index", func(t *testing.T) {
		conn, _ := open(t, false)
		_, err := conn.Exec(ctx, `INSERT INTO messages(id) VALUES (1),(1)`)
		require.NoError(t, err)
		_, err = conn.Exec(ctx, `CREATE UNIQUE INDEX CONCURRENTLY idx_messages_mailbox_headers_v2 ON messages(id)`)
		require.Error(t, err, "duplicate ids must leave an invalid concurrent index")
		_, err = conn.Exec(ctx, string(up))
		require.Error(t, err)
		require.Contains(t, strings.ToUpper(err.Error()), "INVALID")
		var oldExists bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT to_regclass('idx_messages_mailbox_headers') IS NOT NULL`).Scan(&oldExists))
		require.True(t, oldExists)
	})
}
