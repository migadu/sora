package db

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Migration 000050 must never leave messages_fts_v2 empty while messages_fts holds vectors:
// the new binary answers every body search from v2 alone, so an empty v2 means body search
// silently returns nothing for all existing mail. A small database is populated in the
// migration itself; a large one that skipped the out-of-band backfill is refused.
//
// Runs against the dedicated migration test database (see migrationTestDBName), rolled back
// to version 49, because it needs the pre-000050 schema.
func TestFTSv2MigrationNeverLeavesSearchEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	upSQL, err := os.ReadFile(filepath.Join(moduleRoot(t), "db", "migrations", "000050_messages_fts_v2.up.sql"))
	require.NoError(t, err)

	open := func(t *testing.T) *Database {
		t.Helper()
		resetMigrationState(t, 49)
		database, err := NewDatabaseFromConfig(context.Background(), makeTestDBConfig(t), false)
		require.NoError(t, err)
		t.Cleanup(database.Close)
		return database
	}

	t.Run("small database is populated under the mailbox owner", func(t *testing.T) {
		database := open(t)
		ctx := context.Background()
		pool := database.GetWritePool()

		var owner, appender, mailboxID int64
		require.NoError(t, pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&owner))
		require.NoError(t, pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&appender))
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO mailboxes (account_id, name, uid_validity, path, highest_uid)
			VALUES ($1, 'Shared/Team', 1, '0000000000000001', 0) RETURNING id`, owner).Scan(&mailboxID))

		insertMessage := func(accountID int64, mailbox any, uid int, hash string) {
			t.Helper()
			_, err := pool.Exec(ctx, `
				INSERT INTO messages (account_id, mailbox_id, uid, content_hash, subject, sent_date,
				                      internal_date, size, uploaded, s3_domain, s3_localpart,
				                      message_id, body_structure, recipients_json, created_modseq)
				VALUES ($1, $2, $3, $4, 'subject', now(), now(), 100, TRUE, 'domain', 'part',
				        $5, 'body', '[]', nextval('messages_modseq'))`, accountID, mailbox, uid, hash, "<"+hash+"@example.com>")
			require.NoError(t, err)
		}
		// Added to the owner's shared mailbox by someone else before June 2026.
		insertMessage(appender, mailboxID, 1, "hash_legacy")
		// Its mailbox was purged: only messages.account_id is left.
		insertMessage(appender, nil, 2, "hash_detached")
		for _, h := range []string{"hash_legacy", "hash_detached", "hash_orphan"} {
			_, err := pool.Exec(ctx, `
				INSERT INTO messages_fts (content_hash, text_body_tsv, sent_date)
				VALUES ($1, to_tsvector('simple', 'needle'), now())`, h)
			require.NoError(t, err)
		}

		_, err := pool.Exec(ctx, string(upSQL))
		require.NoError(t, err)

		keys := map[string]int64{}
		rows, err := pool.Query(ctx, `SELECT content_hash, account_id FROM messages_fts_v2 WHERE text_body_tsv IS NOT NULL`)
		require.NoError(t, err)
		for rows.Next() {
			var h string
			var a int64
			require.NoError(t, rows.Scan(&h, &a))
			keys[h] = a
		}
		require.NoError(t, rows.Err())
		rows.Close()

		assert.Equal(t, owner, keys["hash_legacy"], "a shared-mailbox message is keyed on the mailbox owner, who is who searches it")
		assert.Equal(t, appender, keys["hash_detached"], "a message with no mailbox falls back to messages.account_id")
		assert.NotContains(t, keys, "hash_orphan", "a vector no message references is not copied")
		assert.Len(t, keys, 2)
	})

	// fillLarge puts more rows in messages_fts than the migration populates itself.
	fillLarge := func(t *testing.T, database *Database) {
		t.Helper()
		_, err := database.GetWritePool().Exec(context.Background(), `
			INSERT INTO messages_fts (content_hash, text_body_tsv, sent_date)
			SELECT 'bulk_' || g, ''::tsvector, now() FROM generate_series(1, 25001) g`)
		require.NoError(t, err)
	}
	loadBackfillScript := func(t *testing.T, database *Database) {
		t.Helper()
		script, err := os.ReadFile(filepath.Join(moduleRoot(t), "scripts", "fts_v2_backfill.sql"))
		require.NoError(t, err)
		_, err = database.GetWritePool().Exec(context.Background(), string(script))
		require.NoError(t, err)
	}

	t.Run("large database without the backfill is refused", func(t *testing.T) {
		database := open(t)
		fillLarge(t, database)
		_, err := database.GetWritePool().Exec(context.Background(), string(upSQL))
		require.Error(t, err, "migrating a large database with an empty messages_fts_v2 must fail, not silently empty body search")
		assert.Contains(t, err.Error(), "docs/fts-v2-rollout.md")
	})

	t.Run("large database with a partial backfill is refused", func(t *testing.T) {
		// An interrupted or recent-only pass leaves the table non-empty. That is not a
		// completed backfill, and older mail would silently be missing from body search.
		database := open(t)
		ctx := context.Background()
		fillLarge(t, database)
		loadBackfillScript(t, database)
		_, err := database.GetWritePool().Exec(ctx, `
			CREATE TABLE IF NOT EXISTS messages_fts_v2 (
				content_hash VARCHAR(64) NOT NULL, account_id BIGINT NOT NULL, text_body TEXT,
				text_body_tsv tsvector, sent_date TIMESTAMPTZ,
				created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (content_hash, account_id));
			INSERT INTO messages_fts_v2 (content_hash, account_id) VALUES ('bulk_1', 1);
			INSERT INTO fts_v2_backfill_state (step, lo) VALUES ('recent', now() - interval '24 months');`)
		require.NoError(t, err)

		_, err = database.GetWritePool().Exec(ctx, string(upSQL))
		require.Error(t, err, "a non-empty but partial messages_fts_v2 must not pass for a completed backfill")
		assert.Contains(t, err.Error(), "fts_v2_backfill_state")
	})

	for _, step := range []string{"rest", "accept_partial"} {
		t.Run("large database proceeds once the backfill recorded "+step, func(t *testing.T) {
			database := open(t)
			fillLarge(t, database)
			loadBackfillScript(t, database)
			_, err := database.GetWritePool().Exec(context.Background(),
				`INSERT INTO fts_v2_backfill_state (step) VALUES ($1)`, step)
			require.NoError(t, err)
			_, err = database.GetWritePool().Exec(context.Background(), string(upSQL))
			require.NoError(t, err)
		})
	}

	t.Run("re-running on an indexed table does not queue behind writers", func(t *testing.T) {
		// On production the table and its indexes exist before the migration runs, while
		// the catch-up is inserting. A no-op CREATE INDEX IF NOT EXISTS still takes a
		// ShareLock, and ALTER INDEX ... SET an AccessExclusiveLock, so the migration would
		// wait behind every writer.
		database := open(t)
		ctx := context.Background()
		_, err := database.GetWritePool().Exec(ctx, string(upSQL))
		require.NoError(t, err)

		writer, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer writer.Rollback(context.Background())
		_, err = writer.Exec(ctx, `INSERT INTO messages_fts_v2 (content_hash, account_id) VALUES ('writer_row', 1)`)
		require.NoError(t, err)

		conn, err := database.GetWritePool().Acquire(ctx)
		require.NoError(t, err)
		defer conn.Release()
		_, err = conn.Exec(ctx, `SET lock_timeout = '1s'`)
		require.NoError(t, err)
		defer conn.Exec(context.Background(), `RESET lock_timeout`)
		_, err = conn.Exec(ctx, string(upSQL))
		require.NoError(t, err, "the migration must not need a lock that conflicts with an in-flight insert")
	})

	t.Run("keyword purge from 000049 is re-applied", func(t *testing.T) {
		// This migration was numbered 000049 on its branch before #84 took the number, so a
		// database that ran the branch recorded 49 without running #84's purge.
		database := open(t)
		ctx := context.Background()
		pool := database.GetWritePool()

		var owner, mailboxID, messageID int64
		require.NoError(t, pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&owner))
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO mailboxes (account_id, name, uid_validity, path, highest_uid)
			VALUES ($1, 'INBOX', 1, '0000000000000002', 0) RETURNING id`, owner).Scan(&mailboxID))
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, subject, sent_date,
			                      internal_date, size, uploaded, s3_domain, s3_localpart,
			                      message_id, body_structure, recipients_json, created_modseq)
			VALUES ($1, $2, 1, 'hash_kw', 'subject', now(), now(), 100, TRUE, 'domain', 'part',
			        '<kw@example.com>', 'body', '[]', nextval('messages_modseq'))
			RETURNING id`, owner, mailboxID).Scan(&messageID))
		_, err := pool.Exec(ctx, `
			INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags)
			VALUES ($1, $2, 0, '["НЕОБРАБОТЕНО", "$Label1"]'::jsonb)`, messageID, mailboxID)
		require.NoError(t, err)
		tag, err := pool.Exec(ctx, `
			UPDATE mailbox_stats SET custom_flags_cache = '["НЕОБРАБОТЕНО", "$Label1"]'::jsonb
			WHERE mailbox_id = $1`, mailboxID)
		require.NoError(t, err)
		require.Equal(t, int64(1), tag.RowsAffected(), "fixture: the mailbox must have a stats row")

		_, err = pool.Exec(ctx, string(upSQL))
		require.NoError(t, err)

		var stateFlags, cache string
		require.NoError(t, pool.QueryRow(ctx, `SELECT custom_flags::text FROM message_state WHERE message_id = $1`, messageID).Scan(&stateFlags))
		require.NoError(t, pool.QueryRow(ctx, `SELECT COALESCE(custom_flags_cache::text, '') FROM mailbox_stats WHERE mailbox_id = $1`, mailboxID).Scan(&cache))
		assert.Equal(t, `["$Label1"]`, stateFlags, "the non-atom keyword is removed from the message")
		assert.NotContains(t, cache, "НЕОБРАБОТЕНО", "and from the mailbox's keyword registry")
	})
}
