package db

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestMessageIDRawMigrationPreparation(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	database := setupTestDatabase(t)
	t.Cleanup(database.Close)
	ctx := context.Background()

	up, err := os.ReadFile("migrations/000073_messages_message_id_raw.up.sql")
	require.NoError(t, err)
	down, err := os.ReadFile("migrations/000073_messages_message_id_raw.down.sql")
	require.NoError(t, err)

	open := func(t *testing.T, large bool) *pgxpool.Conn {
		t.Helper()
		conn, err := database.GetWritePool().Acquire(ctx)
		require.NoError(t, err)
		schema := fmt.Sprintf("msgid_raw_mig_%d", time.Now().UnixNano())
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
			id bigint, mailbox_id bigint, expunged_at timestamptz
		)`)
		require.NoError(t, err)
		if large {
			_, err = conn.Exec(ctx, `INSERT INTO messages(id, mailbox_id) SELECT g, 1 FROM generate_series(1, 25001) g`)
			require.NoError(t, err)
		}
		return conn
	}

	t.Run("small database migrates up and down cleanly", func(t *testing.T) {
		conn := open(t, false)
		_, err := conn.Exec(ctx, string(up))
		require.NoError(t, err)

		var ready bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT indisvalid AND indisready
			FROM pg_index WHERE indexrelid = 'idx_messages_mailbox_message_id_raw'::regclass`).Scan(&ready))
		require.True(t, ready)

		_, err = conn.Exec(ctx, string(down))
		require.NoError(t, err)

		var hasCol, hasIdx bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_attribute
			WHERE attrelid = 'messages'::regclass AND attname = 'message_id_raw' AND NOT attisdropped)`).Scan(&hasCol))
		require.NoError(t, conn.QueryRow(ctx, `SELECT to_regclass('idx_messages_mailbox_message_id_raw') IS NOT NULL`).Scan(&hasIdx))
		require.False(t, hasCol)
		require.False(t, hasIdx)
	})

	t.Run("large unprepared database refuses up and down before blocking DDL", func(t *testing.T) {
		conn := open(t, true)
		_, err := conn.Exec(ctx, string(up))
		require.ErrorContains(t, err, "Migration 73: messages has more than 25000 rows")

		// Prepare out of band, then up is catalog-only and succeeds.
		_, err = conn.Exec(ctx, `
			ALTER TABLE messages ADD COLUMN message_id_raw TEXT;
			CREATE INDEX idx_messages_mailbox_message_id_raw ON messages (mailbox_id, id)
				WHERE message_id_raw IS NOT NULL AND expunged_at IS NULL`)
		require.NoError(t, err)
		_, err = conn.Exec(ctx, string(up))
		require.NoError(t, err)

		// Unprepared down on > 25,000 rows refuses blocking DDL.
		_, err = conn.Exec(ctx, string(down))
		require.ErrorContains(t, err, "Migration 73 down: messages has more than 25000 rows")

		// Prepare rollback out of band, then down is catalog-only and succeeds.
		_, err = conn.Exec(ctx, `
			DROP INDEX idx_messages_mailbox_message_id_raw;
			ALTER TABLE messages DROP COLUMN message_id_raw`)
		require.NoError(t, err)
		_, err = conn.Exec(ctx, string(down))
		require.NoError(t, err)
	})
}
