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

	t.Run("large database without the backfill is refused", func(t *testing.T) {
		database := open(t)
		ctx := context.Background()
		_, err := database.GetWritePool().Exec(ctx, `
			INSERT INTO messages_fts (content_hash, text_body_tsv, sent_date)
			SELECT 'bulk_' || g, ''::tsvector, now() FROM generate_series(1, 250001) g`)
		require.NoError(t, err)

		_, err = database.GetWritePool().Exec(ctx, string(upSQL))
		require.Error(t, err, "migrating a large database with an empty messages_fts_v2 must fail, not silently empty body search")
		assert.Contains(t, err.Error(), "docs/fts-v2-rollout.md")
	})
}
