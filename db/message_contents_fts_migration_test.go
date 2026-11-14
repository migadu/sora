package db

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Up to migration 000022 a body's search vector lives in message_contents, and since 000016
// its trigger nulls text_body once the vector is computed, so the vector is the only copy of
// the body's searchable text. 000023 moves full-text search to messages_fts, which 000050
// carries into messages_fts_v2, the table every body search reads. A database upgraded from
// below 23 must come out with its existing mail still found by body search.
//
// Runs against the dedicated migration test database (see migrationTestDBName).
func TestMessageContentsFTSSurvivesUpgrade(t *testing.T) {
	skipDatabaseTestInShortMode(t)
	ctx := context.Background()

	m := migrateMessageContentsTestDB(t, 22)
	database, err := NewDatabaseFromConfig(ctx, makeTestDBConfig(t), false)
	require.NoError(t, err)
	defer database.Close()
	pool := database.GetWritePool()

	f := seedMessageContentsFixture(t, database)
	// A body the trigger has tokenised: text_body is nulled, the vector is all that is left.
	_, err = pool.Exec(ctx, `INSERT INTO message_contents (content_hash, text_body, headers, sent_date)
		VALUES ('hash_indexed', 'quarterly invoice zebra', 'Subject: x', now())`)
	require.NoError(t, err)
	// A body whose text was stored without a vector: it must reach the FTS worker's queue.
	_, err = pool.Exec(ctx, `
		ALTER TABLE message_contents DISABLE TRIGGER message_contents_tsvector_update;
		INSERT INTO message_contents (content_hash, text_body, headers, sent_date)
		VALUES ('hash_queued', 'pending walrus', 'Subject: y', now());
		ALTER TABLE message_contents ENABLE TRIGGER message_contents_tsvector_update;`)
	require.NoError(t, err)
	var indexed, bodyNulled bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT text_body_tsv @@ 'zebra'::tsquery, text_body IS NULL
		FROM message_contents WHERE content_hash = 'hash_indexed'`).Scan(&indexed, &bodyNulled))
	require.True(t, indexed && bodyNulled, "fixture: the 000016 trigger keeps only the vector")

	err = m.Up()
	if !errors.Is(err, migrate.ErrNoChange) {
		require.NoError(t, err)
	}

	var rows int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM messages_fts_v2 WHERE account_id = $1`,
		f.accountID).Scan(&rows))
	assert.Equal(t, 2, rows, "each body that existed before the upgrade must have a messages_fts_v2 row")

	assertBodySearchFinds(t, database, f, map[string]imap.UID{"zebra": 1, "walrus": 2})
}

// A database that ran 000023 before it copied anything still has its old vectors in
// message_contents and none in messages_fts_v2. scripts/fts_recover_message_contents.sql
// copies them across, once per (body, mailbox owner), leaving rows that already exist alone.
func TestFTSRecoverMessageContentsScript(t *testing.T) {
	skipDatabaseTestInShortMode(t)
	ctx := context.Background()

	script, err := os.ReadFile(filepath.Join(moduleRoot(t), "scripts", "fts_recover_message_contents.sql"))
	require.NoError(t, err)

	m := migrateMessageContentsTestDB(t, 22)
	err = m.Up()
	if !errors.Is(err, migrate.ErrNoChange) {
		require.NoError(t, err)
	}
	database, err := NewDatabaseFromConfig(ctx, makeTestDBConfig(t), false)
	require.NoError(t, err)
	defer database.Close()
	pool := database.GetWritePool()

	f := seedMessageContentsFixture(t, database)
	// What an affected database holds: the vectors (and any text an older binary stored after
	// the trigger was dropped) only in message_contents. hash_known already has its row,
	// hash_orphan belongs to no message.
	_, err = pool.Exec(ctx, `
		INSERT INTO message_contents (content_hash, text_body, text_body_tsv, headers, sent_date) VALUES
			('hash_indexed', NULL, strip(to_tsvector('simple', 'quarterly invoice zebra')), 'Subject: x', now()),
			('hash_queued', 'pending walrus', NULL, 'Subject: y', now()),
			('hash_known', NULL, strip(to_tsvector('simple', 'stale words')), '', now()),
			('hash_orphan', NULL, strip(to_tsvector('simple', 'nobody')), '', now())`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO messages_fts_v2 (content_hash, account_id, text_body_tsv, sent_date)
		VALUES ('hash_known', $1, strip(to_tsvector('simple', 'current yak')), now())`, f.accountID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, string(script))
	require.NoError(t, err)
	// Batches of one, so the run crosses several batch boundaries.
	_, err = pool.Exec(ctx, `CALL sora_fts_recover_message_contents(NULL, 1, 0)`)
	require.NoError(t, err)
	// Running it again finds nothing more to do.
	_, err = pool.Exec(ctx, `CALL sora_fts_recover_message_contents(NULL, 1000, 0)`)
	require.NoError(t, err)

	keys := map[string]int64{}
	rs, err := pool.Query(ctx, `SELECT content_hash, account_id FROM messages_fts_v2`)
	require.NoError(t, err)
	for rs.Next() {
		var h string
		var a int64
		require.NoError(t, rs.Scan(&h, &a))
		keys[h] = a
	}
	require.NoError(t, rs.Err())
	rs.Close()
	assert.Equal(t, map[string]int64{"hash_indexed": f.accountID, "hash_queued": f.accountID, "hash_known": f.accountID}, keys,
		"one row per body a message holds, none for a body no message holds")

	assertBodySearchFinds(t, database, f, map[string]imap.UID{"zebra": 1, "walrus": 2, "yak": 3})
	results, err := database.SearchMessagesWithCriteria(ctx, f.mailboxID, f.accountID,
		&imap.SearchCriteria{Body: []string{"stale"}}, 100, 3)
	require.NoError(t, err)
	assert.Empty(t, results, "a row that already exists is left as it is")
}

// An interrupted online recovery retains committed batches. Restarting from the beginning
// picks up late claims behind its cursor and keys legacy shared messages by mailbox owner.
func TestFTSRecoverMessageContentsRestartAndOwners(t *testing.T) {
	skipDatabaseTestInShortMode(t)
	ctx := context.Background()
	m := migrateMessageContentsTestDB(t, 22)
	require.NoError(t, m.Up())
	database, err := NewDatabaseFromConfig(ctx, makeTestDBConfig(t), false)
	require.NoError(t, err)
	defer database.Close()
	pool := database.GetWritePool()
	f := seedMessageContentsFixture(t, database)
	_, err = pool.Exec(ctx, `INSERT INTO message_contents (content_hash, text_body_tsv, sent_date)
		VALUES ('hash_indexed', to_tsvector('simple', 'zebra'), NULL),
		       ('hash_queued', to_tsvector('simple', 'walrus'), now()),
		       ('hash_known', to_tsvector('simple', 'yak'), now())`)
	require.NoError(t, err)
	script, err := os.ReadFile(filepath.Join(moduleRoot(t), "scripts", "fts_recover_message_contents.sql"))
	require.NoError(t, err)
	_, err = pool.Exec(ctx, string(script))
	require.NoError(t, err)

	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := pool.Exec(callCtx, `CALL sora_fts_recover_message_contents(NULL, 1, 30000)`)
		done <- err
	}()
	// hash_indexed sorts first. The sleep after COMMIT leaves a deterministic cancellation
	// point, and proves the first batch survives a canceled procedure call.
	require.Eventually(t, func() bool {
		var n int
		return pool.QueryRow(ctx, `SELECT count(*) FROM messages_fts_v2`).Scan(&n) == nil && n == 1
	}, 5*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("canceled recovery did not return")
	}

	var owner, mailbox int64
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&owner))
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO mailboxes (account_id, name, uid_validity, path)
		VALUES ($1, 'INBOX', 1, 'owner') RETURNING id`, owner).Scan(&mailbox))
	// A legacy shared-mailbox row keeps the writer in messages.account_id. The recovery
	// must use its mailbox's owner, including a claim made after that hash was passed.
	_, err = pool.Exec(ctx, `INSERT INTO messages
		(account_id, mailbox_id, uid, content_hash, subject, sent_date, internal_date, size,
		 uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq)
		VALUES ($1, $2, 1, 'hash_indexed', 'shared', now(), now(), 100, TRUE, 'example.com',
		        'user', 'shared@example.com', 'body', '[]', nextval('messages_modseq'))`, f.accountID, mailbox)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `CALL sora_fts_recover_message_contents(NULL, 1, 0)`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `CALL sora_fts_recover_message_contents(NULL, 1, 0)`)
	require.NoError(t, err)
	var rows, owners int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*), count(DISTINCT account_id)
		FROM messages_fts_v2 WHERE content_hash = 'hash_indexed' AND sent_date IS NULL`).Scan(&rows, &owners))
	require.Equal(t, 2, rows)
	require.Equal(t, 2, owners)
	assertBodySearchFinds(t, database, f, map[string]imap.UID{"zebra": 1, "walrus": 2, "yak": 3})
	results, err := database.SearchMessagesWithCriteria(ctx, mailbox, owner,
		&imap.SearchCriteria{Body: []string{"zebra"}}, 100, 1)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, imap.UID(1), results[0].UID)
}

func TestMessageContentsMigrationLocksAndRollback(t *testing.T) {
	for _, dropTrigger := range []bool{false, true} {
		t.Run(map[bool]string{false: "trigger present", true: "trigger already absent"}[dropTrigger], func(t *testing.T) {
			skipDatabaseTestInShortMode(t)
			ctx := context.Background()
			migrateMessageContentsTestDB(t, 22)
			database, err := NewDatabaseFromConfig(ctx, makeTestDBConfig(t), false)
			require.NoError(t, err)
			defer database.Close()
			pool := database.GetWritePool()
			if dropTrigger {
				_, err = pool.Exec(ctx, `DROP TRIGGER message_contents_tsvector_update ON message_contents`)
				require.NoError(t, err)
			}
			migration, err := MigrationsFS.ReadFile("migrations/000023_messages_fts.up.sql")
			require.NoError(t, err)
			tx, err := pool.Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)
			_, err = tx.Exec(ctx, string(migration))
			require.NoError(t, err)
			var locked bool
			require.NoError(t, tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks
				WHERE pid = pg_backend_pid() AND relation = 'message_contents'::regclass
				AND mode = 'ShareLock' AND granted)`).Scan(&locked))
			require.True(t, locked, "copy must retain its explicit table lock through commit")
			writeCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			_, err = pool.Exec(writeCtx, `INSERT INTO message_contents (content_hash, text_body)
				VALUES ('during_migration', 'must wait')`)
			cancel()
			require.Error(t, err, "an old writer must not commit behind the copy")
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.NoError(t, tx.Rollback(ctx))
			var absent bool
			require.NoError(t, pool.QueryRow(ctx, `SELECT to_regclass('messages_fts') IS NULL`).Scan(&absent))
			require.True(t, absent, "failed migration must roll back its DDL and copy")
			// The rolled-back migration can be run again without leaving a partial table.
			_, err = pool.Exec(ctx, string(migration))
			require.NoError(t, err)
			_, err = pool.Exec(ctx, string(migration))
			require.NoError(t, err)
		})
	}
}

func TestMessageContentsMigrationDoesNotDeadlockOldWriter(t *testing.T) {
	skipDatabaseTestInShortMode(t)
	ctx := context.Background()
	migrateMessageContentsTestDB(t, 22)
	database, err := NewDatabaseFromConfig(ctx, makeTestDBConfig(t), false)
	require.NoError(t, err)
	defer database.Close()
	pool := database.GetWritePool()
	writer, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer writer.Rollback(ctx)
	// Old delivery reads before it writes. Its ACCESS SHARE lock must be able to
	// upgrade to ROW EXCLUSIVE while DROP TRIGGER waits for ACCESS EXCLUSIVE.
	_, err = writer.Exec(ctx, `SELECT 1 FROM message_contents LIMIT 1`)
	require.NoError(t, err)
	migration, err := MigrationsFS.ReadFile("migrations/000023_messages_fts.up.sql")
	require.NoError(t, err)
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	pid := conn.Conn().PgConn().PID()
	migrationCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := conn.Exec(migrationCtx, string(migration))
		done <- err
	}()
	require.Eventually(t, func() bool {
		var waiting bool
		return pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid = $1
			AND relation = 'message_contents'::regclass AND mode = 'AccessExclusiveLock'
			AND NOT granted)`, pid).Scan(&waiting) == nil && waiting
	}, 5*time.Second, 10*time.Millisecond)
	writeCtx, cancelWrite := context.WithTimeout(ctx, 2*time.Second)
	_, err = writer.Exec(writeCtx, `INSERT INTO message_contents (content_hash, text_body)
		VALUES ('last_old_writer', 'zebra')`)
	cancelWrite()
	require.NoError(t, err, "the older writer must finish without a SHARE/EXCLUSIVE upgrade deadlock")
	require.NoError(t, writer.Commit(ctx))
	require.NoError(t, <-done)
	var copied bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT text_body_tsv @@ 'zebra'::tsquery
		FROM messages_fts WHERE content_hash = 'last_old_writer'`).Scan(&copied))
	require.True(t, copied, "migration must include the last writer that committed ahead of its lock")
}

type messageContentsFixture struct {
	accountID, mailboxID int64
}

// migrateMessageContentsTestDB rebuilds the migration test database's schema up to version,
// through golang-migrate as `sora-admin migrate up` does.
func migrateMessageContentsTestDB(t *testing.T, version uint) *migrate.Migrate {
	t.Helper()
	ctx := context.Background()
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

// seedMessageContentsFixture stores one account and mailbox holding messages UID 1..3 with
// bodies hash_indexed, hash_queued and hash_known, in columns every version since 000022 has.
func seedMessageContentsFixture(t *testing.T, database *Database) messageContentsFixture {
	t.Helper()
	ctx := context.Background()
	pool := database.GetWritePool()

	var f messageContentsFixture
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&f.accountID))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO mailboxes (account_id, name, uid_validity, path, highest_uid)
		VALUES ($1, 'INBOX', 1, '0000000000000001', 3) RETURNING id`, f.accountID).Scan(&f.mailboxID))
	for uid, hash := range []string{"hash_indexed", "hash_queued", "hash_known"} {
		var messageID int64
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, subject, sent_date,
			                      internal_date, size, uploaded, s3_domain, s3_localpart, message_id,
			                      body_structure, recipients_json, created_modseq)
			VALUES ($1, $2, $3, $4, 'subject', now(), now(), 100, TRUE, 'example.com', 'user', $5,
			        'body', '[]', nextval('messages_modseq'))
			RETURNING id`,
			f.accountID, f.mailboxID, uid+1, hash, "<"+hash+"@example.com>").Scan(&messageID))
		_, err := pool.Exec(ctx, `INSERT INTO message_state (message_id, mailbox_id) VALUES ($1, $2)`,
			messageID, f.mailboxID)
		require.NoError(t, err)
	}
	return f
}

// assertBodySearchFinds runs the FTS worker until its queue is empty, then checks that a
// BODY search for each word finds exactly the message with the given UID.
func assertBodySearchFinds(t *testing.T, database *Database, f messageContentsFixture, want map[string]imap.UID) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		n, err := database.ProcessFTSBatch(ctx, tx, 100)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		if n == 0 {
			break
		}
	}
	for word, uid := range want {
		results, err := database.SearchMessagesWithCriteria(ctx, f.mailboxID, f.accountID,
			&imap.SearchCriteria{Body: []string{word}}, 100, 3)
		require.NoError(t, err)
		var uids []imap.UID
		for _, r := range results {
			uids = append(uids, r.UID)
		}
		assert.Equal(t, []imap.UID{uid}, uids, "BODY %q must find the message that existed before the upgrade", word)
	}
}
