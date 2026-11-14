package db

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Migration 000022 moves every message's flags from messages into message_state and
// drops the old columns. A database upgraded from below 22 must come out with the
// flags and keywords it went in with, and with the mailbox keyword registry
// (custom_flags_cache) listing them: a message without a message_state row reads as
// unseen and keyword-less, and STORE on it fails.
//
// Runs against the dedicated migration test database (see migrationTestDBName).
func TestMessageStateMigrationKeepsFlags(t *testing.T) {
	skipDatabaseTestInShortMode(t)
	ctx := context.Background()

	// migrateTo rebuilds the schema from scratch up to version, through golang-migrate
	// as `sora-admin migrate up` does.
	migrateTo := func(t *testing.T, version uint) *migrate.Migrate {
		t.Helper()
		database, err := NewDatabaseFromConfig(ctx, makeTestDBConfig(t), false)
		require.NoError(t, err)
		_, err = database.WritePool.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
		database.Close()
		require.NoError(t, err)

		migrations, err := fs.Sub(MigrationsFS, "migrations")
		require.NoError(t, err)
		source, err := iofs.New(migrations, ".")
		require.NoError(t, err)
		m, err := migrate.NewWithSourceInstance("iofs", source, migrationTestConnStr(t))
		require.NoError(t, err)
		t.Cleanup(func() { m.Close() })
		require.NoError(t, m.Migrate(version))
		return m
	}

	type seeded struct {
		mailboxID, seenID, unseenID int64
		seenModSeq                  int64
	}
	// seed stores, in the pre-22 schema, one \Seen message carrying a keyword and one
	// unseen message without keywords.
	seed := func(t *testing.T) seeded {
		t.Helper()
		database, err := NewDatabaseFromConfig(ctx, makeTestDBConfig(t), false)
		require.NoError(t, err)
		defer database.Close()
		pool := database.GetWritePool()

		var s seeded
		var accountID int64
		require.NoError(t, pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&accountID))
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO mailboxes (account_id, name, uid_validity, highest_uid)
			VALUES ($1, 'INBOX', 1, 2) RETURNING id`, accountID).Scan(&s.mailboxID))
		insert := func(uid, flags int, keywords string) (id, updatedModSeq int64) {
			t.Helper()
			require.NoError(t, pool.QueryRow(ctx, `
				INSERT INTO messages (account_id, mailbox_id, uid, s3_domain, s3_localpart, content_hash,
				                      recipients_json, message_id, sent_date, internal_date, size,
				                      body_structure, flags, custom_flags, flags_changed_at,
				                      created_modseq, updated_modseq)
				VALUES ($1, $2, $3, 'example.com', 'user', $6, '[]', $7,
				        now(), now(), 100, 'body', $4, $5::jsonb,
				        now(), nextval('messages_modseq'), nextval('messages_modseq'))
				RETURNING id, updated_modseq`,
				accountID, s.mailboxID, uid, flags, keywords,
				fmt.Sprintf("hash_%d", uid), fmt.Sprintf("<%d@example.com>", uid)).Scan(&id, &updatedModSeq))
			return id, updatedModSeq
		}
		s.seenID, s.seenModSeq = insert(1, FlagSeen, `["$Work"]`)
		s.unseenID, _ = insert(2, 0, `[]`)
		return s
	}

	// assertKept checks the migrated database through the queries the server runs.
	assertKept := func(t *testing.T, s seeded) {
		t.Helper()
		database, err := NewDatabaseFromConfig(ctx, makeTestDBConfig(t), false)
		require.NoError(t, err)
		defer database.Close()
		pool := database.GetWritePool()

		var flags int
		var keywords []byte
		var modSeq *int64
		err = pool.QueryRow(ctx, `SELECT flags, custom_flags, updated_modseq FROM message_state WHERE message_id = $1`,
			s.seenID).Scan(&flags, &keywords, &modSeq)
		if assert.NoError(t, err, "the \\Seen message must have a message_state row") {
			assert.Equal(t, FlagSeen, flags)
			assert.JSONEq(t, `["$Work"]`, string(keywords))
			if assert.NotNil(t, modSeq) {
				assert.Equal(t, s.seenModSeq, *modSeq)
			}
		}
		err = pool.QueryRow(ctx, `SELECT flags FROM message_state WHERE message_id = $1`, s.unseenID).Scan(&flags)
		if assert.NoError(t, err, "the unseen message must have a message_state row") {
			assert.Equal(t, 0, flags)
		}

		var messageCount, unseenCount int
		require.NoError(t, pool.QueryRow(ctx, `SELECT message_count, unseen_count FROM mailbox_stats WHERE mailbox_id = $1`,
			s.mailboxID).Scan(&messageCount, &unseenCount))
		assert.Equal(t, 2, messageCount)
		assert.Equal(t, 1, unseenCount, "copying the flags must not count the messages' unseen state twice")

		// The mailbox's FLAGS list, read from custom_flags_cache.
		keywordsInUse, err := database.GetUniqueCustomFlagsForMailbox(ctx, s.mailboxID)
		require.NoError(t, err)
		assert.Equal(t, []string{"$Work"}, keywordsInUse, "the mailbox keyword registry must list the copied keyword")

		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		updated, _, err := database.AddMessageFlags(ctx, tx, imap.UID(1), s.mailboxID, []imap.Flag{imap.FlagAnswered})
		if assert.NoError(t, err, "STORE on a message that existed before the upgrade must work") {
			assert.ElementsMatch(t, []imap.Flag{imap.FlagSeen, imap.FlagAnswered, "$Work"}, updated)
		}
	}

	upgrade := func(t *testing.T, m *migrate.Migrate) {
		t.Helper()
		err := m.Up()
		if !errors.Is(err, migrate.ErrNoChange) {
			require.NoError(t, err)
		}
	}

	// 21 is the last version with the flag columns; 8 is the last before 000009 added
	// custom_flags_cache, so its caches start NULL.
	for _, from := range []uint{21, 8} {
		t.Run(fmt.Sprintf("upgrade from %d", from), func(t *testing.T) {
			m := migrateTo(t, from)
			s := seed(t)
			upgrade(t, m)
			assertKept(t, s)
		})
	}

	// A large database may copy the flags ahead of the upgrade. The columns stay
	// authoritative until 000022 drops them, so a row copied before the flags last
	// changed is brought up to date rather than kept.
	t.Run("stale pre-copied row is refreshed", func(t *testing.T) {
		m := migrateTo(t, 21)
		s := seed(t)
		database, err := NewDatabaseFromConfig(ctx, makeTestDBConfig(t), false)
		require.NoError(t, err)
		_, err = database.GetWritePool().Exec(ctx, `
			CREATE TABLE message_state (
				message_id BIGINT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
				mailbox_id BIGINT REFERENCES mailboxes(id) ON DELETE CASCADE,
				flags INTEGER NOT NULL DEFAULT 0,
				custom_flags JSONB NOT NULL DEFAULT '[]'::jsonb,
				flags_changed_at TIMESTAMPTZ,
				updated_modseq BIGINT,
				CONSTRAINT max_custom_flags_check CHECK (jsonb_array_length(custom_flags) <= 50))`)
		require.NoError(t, err)
		_, err = database.GetWritePool().Exec(ctx,
			`INSERT INTO message_state (message_id, mailbox_id) VALUES ($1, $2)`, s.seenID, s.mailboxID)
		require.NoError(t, err)
		_, err = database.GetWritePool().Exec(ctx, `
			INSERT INTO message_state
			SELECT id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq
			FROM messages WHERE id = $1`, s.unseenID)
		require.NoError(t, err)
		var before, after string
		require.NoError(t, database.GetWritePool().QueryRow(ctx,
			`SELECT xmin::text FROM message_state WHERE message_id = $1`, s.unseenID).Scan(&before))
		require.NoError(t, m.Migrate(22))
		require.NoError(t, database.GetWritePool().QueryRow(ctx,
			`SELECT xmin::text FROM message_state WHERE message_id = $1`, s.unseenID).Scan(&after))
		assert.Equal(t, before, after, "an identical pre-copied row should not be rewritten")
		database.Close()
		upgrade(t, m)
		assertKept(t, s)
	})

	t.Run("all legacy flag bits and nullable metadata survive down and up", func(t *testing.T) {
		m := migrateTo(t, 21)
		s := seed(t)
		database, err := NewDatabaseFromConfig(ctx, makeTestDBConfig(t), false)
		require.NoError(t, err)
		defer database.Close()
		pool := database.GetWritePool()
		// Include the old stored Recent bit, all flag combinations, empty and
		// multi-keyword arrays, nullable metadata, and expunged/detached rows.
		_, err = pool.Exec(ctx, `
			INSERT INTO messages (account_id, mailbox_id, uid, s3_domain, s3_localpart, content_hash,
			                      recipients_json, message_id, sent_date, internal_date, size,
			                      body_structure, flags, custom_flags, flags_changed_at,
			                      created_modseq, updated_modseq, expunged_at)
			SELECT account_id, CASE WHEN n % 7 = 0 THEN NULL ELSE mailbox_id END, n + 3,
			       s3_domain, s3_localpart, 'flags_' || n, recipients_json, '<flags_' || n || '@example.com>',
			       sent_date, internal_date, size, body_structure, n,
			       CASE WHEN n % 2 = 0 THEN '[]'::jsonb ELSE '["$Work", "$Other"]'::jsonb END,
			       CASE WHEN n % 3 = 0 THEN NULL ELSE '2026-01-02 03:04:05.123456+00'::timestamptz END,
			       nextval('messages_modseq'), CASE WHEN n % 5 = 0 THEN NULL ELSE nextval('messages_modseq') END,
			       CASE WHEN n % 11 = 0 THEN now() ELSE NULL END
			FROM messages CROSS JOIN generate_series(0, 63) AS n WHERE id = $1`, s.seenID)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `CREATE TABLE expected_message_state AS
			SELECT id AS message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq
			FROM messages`)
		require.NoError(t, err)
		assertState := func(table, idColumn string) {
			t.Helper()
			var differences int
			err := pool.QueryRow(ctx, fmt.Sprintf(`
				SELECT count(*) FROM expected_message_state e FULL JOIN %s actual ON actual.%s = e.message_id
				WHERE (e.message_id, e.mailbox_id, e.flags, e.custom_flags, e.flags_changed_at, e.updated_modseq)
				IS DISTINCT FROM (actual.%s, actual.mailbox_id, actual.flags, actual.custom_flags,
				                  actual.flags_changed_at, actual.updated_modseq)`, table, idColumn, idColumn)).Scan(&differences)
			require.NoError(t, err)
			assert.Zero(t, differences, "all source state must survive in %s", table)
		}
		require.NoError(t, m.Migrate(22))
		assertState("message_state", "message_id")
		require.NoError(t, m.Migrate(21))
		assertState("messages", "id")
		require.NoError(t, m.Migrate(22))
		assertState("message_state", "message_id")
	})

	for _, existingCache := range []string{"null", `["$Reserved"]`} {
		t.Run("keyword cache "+existingCache, func(t *testing.T) {
			m := migrateTo(t, 21)
			s := seed(t)
			database, err := NewDatabaseFromConfig(ctx, makeTestDBConfig(t), false)
			require.NoError(t, err)
			defer database.Close()
			pool := database.GetWritePool()
			_, err = pool.Exec(ctx, `UPDATE mailbox_stats SET custom_flags_cache = NULLIF($1::jsonb, 'null'::jsonb)
				WHERE mailbox_id = $2`, existingCache, s.mailboxID)
			require.NoError(t, err)
			require.NoError(t, m.Migrate(24))
			var cache []byte
			require.NoError(t, pool.QueryRow(ctx, `SELECT custom_flags_cache FROM mailbox_stats WHERE mailbox_id = $1`,
				s.mailboxID).Scan(&cache))
			expected := existingCache
			if existingCache == "null" {
				expected = `["$Work"]`
			}
			assert.JSONEq(t, expected, string(cache), "only an uninitialized cache should be filled")
		})
	}
}
