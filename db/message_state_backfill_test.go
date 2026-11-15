package db

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every live message must have a message_state row (#1151). The readers LEFT JOIN it
// and show a message without one as having no flags, but SEARCH's flag tests,
// mailbox_stats.unseen_count, the first-unseen lookup and every flag writer only see
// messages that have one: SEARCH UNSEEN and STATUS UNSEEN left such a message out, and
// STORE and the User API PATCH changed nothing. Older builds left such messages
// behind, and migration 000063 gives each of them a row with no flags. On a large
// database scripts/message_state_backfill.sql does the bulk of that first.
//
// Runs against the dedicated migration test database (see migrationTestDBName).
func TestMessageStateBackfillMigration(t *testing.T) {
	skipDatabaseTestInShortMode(t)
	ctx := context.Background()

	// open rolls the schema back to 61, the last version without the backfill, and
	// returns a migrate instance that applies the rest.
	open := func(t *testing.T) (*pgxpool.Pool, *Database, *migrate.Migrate) {
		t.Helper()
		resetMigrationState(t, 61)
		database, err := NewDatabaseFromConfig(ctx, makeTestDBConfig(t), false)
		require.NoError(t, err)
		t.Cleanup(database.Close)
		migrations, err := fs.Sub(MigrationsFS, "migrations")
		require.NoError(t, err)
		source, err := iofs.New(migrations, ".")
		require.NoError(t, err)
		m, err := migrate.NewWithSourceInstance("iofs", source, migrationTestConnStr(t))
		require.NoError(t, err)
		t.Cleanup(func() { m.Close() })
		return database.GetWritePool(), database, m
	}
	upgrade := func(t *testing.T, m *migrate.Migrate) {
		t.Helper()
		if err := m.Up(); !errors.Is(err, migrate.ErrNoChange) {
			require.NoError(t, err)
		}
	}

	type mailbox struct{ accountID, id int64 }
	newMailbox := func(t *testing.T, pool *pgxpool.Pool) mailbox {
		t.Helper()
		var mb mailbox
		require.NoError(t, pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&mb.accountID))
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO mailboxes (account_id, name, uid_validity, path, highest_uid)
			VALUES ($1, 'INBOX', 1, '0000000000000001', 10) RETURNING id`, mb.accountID).Scan(&mb.id))
		return mb
	}
	// insertMessage writes a messages row and no message_state row, as an older build
	// left them behind.
	insertMessage := func(t *testing.T, pool *pgxpool.Pool, mb mailbox, uid int, expunged bool) int64 {
		t.Helper()
		hash := fmt.Sprintf("state_backfill_%d_%d", mb.id, uid)
		var id int64
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, subject, sent_date,
			                      internal_date, size, uploaded, s3_domain, s3_localpart,
			                      message_id, body_structure, recipients_json, created_modseq,
			                      expunged_at, expunged_modseq)
			VALUES ($1, $2, $3, $4, 'subject', now(), now(), 100, TRUE, 'example.com', 'user',
			        $5, 'body', '[]', nextval('messages_modseq'),
			        CASE WHEN $6 THEN now() END, CASE WHEN $6 THEN nextval('messages_modseq') END)
			RETURNING id`, mb.accountID, mb.id, uid, hash, "<"+hash+"@example.com>", expunged).Scan(&id))
		return id
	}
	addState := func(t *testing.T, pool *pgxpool.Pool, mb mailbox, id int64, flags int) {
		t.Helper()
		_, err := pool.Exec(ctx, `
			INSERT INTO message_state (message_id, mailbox_id, flags, flags_changed_at, updated_modseq)
			VALUES ($1, $2, $3, now(), nextval('messages_modseq'))`, id, mb.id, flags)
		require.NoError(t, err)
	}
	hasState := func(t *testing.T, pool *pgxpool.Pool, id int64) bool {
		t.Helper()
		var exists bool
		require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM message_state WHERE message_id = $1)`, id).Scan(&exists))
		return exists
	}
	loadScript := func(t *testing.T, pool *pgxpool.Pool) {
		t.Helper()
		script, err := os.ReadFile(filepath.Join(moduleRoot(t), "scripts", "message_state_backfill.sql"))
		require.NoError(t, err)
		_, err = pool.Exec(ctx, string(script))
		require.NoError(t, err)
	}
	// makeLarge moves the message ids past the span the migration checks by itself.
	makeLarge := func(t *testing.T, pool *pgxpool.Pool) {
		t.Helper()
		_, err := pool.Exec(ctx, `SELECT setval('messages_id_seq', 2000000)`)
		require.NoError(t, err)
	}

	t.Run("live messages without a row get one with no flags", func(t *testing.T) {
		pool, database, m := open(t)
		mb := newMailbox(t, pool)
		legacy := insertMessage(t, pool, mb, 1, false)
		seen := insertMessage(t, pool, mb, 2, false)
		addState(t, pool, mb, seen, FlagSeen)
		unseen := insertMessage(t, pool, mb, 3, false)
		addState(t, pool, mb, unseen, 0)
		expunged := insertMessage(t, pool, mb, 4, true)

		var seenXmin string
		require.NoError(t, pool.QueryRow(ctx, `SELECT xmin::text FROM message_state WHERE message_id = $1`, seen).Scan(&seenXmin))
		before, err := database.GetMailboxSummary(ctx, mb.id)
		require.NoError(t, err)
		require.Equal(t, 1, before.UnseenCount)

		upgrade(t, m)

		var flags int
		var keywords []byte
		var modSeq *int64
		err = pool.QueryRow(ctx, `SELECT flags, custom_flags, updated_modseq FROM message_state WHERE message_id = $1 AND mailbox_id = $2`,
			legacy, mb.id).Scan(&flags, &keywords, &modSeq)
		if assert.NoError(t, err, "a live message must have a message_state row") {
			assert.Equal(t, 0, flags)
			assert.JSONEq(t, `[]`, string(keywords))
			assert.Nil(t, modSeq, "the row holds the flags every reader already showed, so nothing changed for CONDSTORE")
		}
		assert.False(t, hasState(t, pool, expunged), "an expunged message is left to restore, which writes its row")
		var xmin string
		require.NoError(t, pool.QueryRow(ctx, `SELECT xmin::text FROM message_state WHERE message_id = $1`, seen).Scan(&xmin))
		assert.Equal(t, seenXmin, xmin, "an existing row must not be rewritten")

		// RFC 9051 §6.3.11: UNSEEN is "the number of messages that do not have the \Seen flag set".
		summary, err := database.GetMailboxSummary(ctx, mb.id)
		require.NoError(t, err)
		assert.Equal(t, 3, summary.NumMessages)
		assert.Equal(t, 2, summary.UnseenCount)
		assert.Equal(t, before.HighestModSeq, summary.HighestModSeq)
		first, err := database.GetFirstUnseenSeqNum(ctx, mb.id)
		require.NoError(t, err)
		assert.Equal(t, uint32(1), first)

		// RFC 9051 §6.4.4: UNSEEN matches "messages that do not have the \Seen flag set".
		for name, criteria := range map[string]*imap.SearchCriteria{
			"UNSEEN":   {NotFlag: []imap.Flag{imap.FlagSeen}},
			"NOT SEEN": {Not: []imap.SearchCriteria{{Flag: []imap.Flag{imap.FlagSeen}}}},
		} {
			results, err := database.SearchMessagesWithCriteria(ctx, mb.id, mb.accountID, criteria, 100, 3)
			require.NoError(t, err)
			var uids []imap.UID
			for _, r := range results {
				uids = append(uids, r.UID)
			}
			assert.ElementsMatch(t, []imap.UID{1, 3}, uids, "SEARCH %s", name)
		}

		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		stored, err := database.AddMessageFlagsBatch(ctx, tx, []imap.UID{1}, mb.id, []imap.Flag{imap.FlagSeen})
		require.NoError(t, err)
		require.Len(t, stored, 1, "STORE +FLAGS (\\Seen) must change the message")
		assert.Contains(t, stored[0].Flags, imap.FlagSeen)
		require.NoError(t, tx.Commit(ctx))

		require.NoError(t, database.UpdateMessageFlags(ctx, mb.accountID, legacy, []string{`\Flagged`}, nil),
			"the User API must find the message's flags")
		err = pool.QueryRow(ctx, `SELECT flags FROM message_state WHERE message_id = $1`, legacy).Scan(&flags)
		require.NoError(t, err)
		assert.Equal(t, FlagSeen|FlagFlagged, flags)
		summary, err = database.GetMailboxSummary(ctx, mb.id)
		require.NoError(t, err)
		assert.Equal(t, 1, summary.UnseenCount)
	})

	// A message without a row can already be in unseen_count, so the repair must count
	// the mailbox again rather than add the message to it. The messages trigger reads a
	// missing row as no flags: a restore by an older build un-expunged a message whose
	// mailbox had been purged, wrote no row, and the trigger counted the message as an
	// unseen arrival (see the recompute at the end of RestoreMessages). Migration 000022
	// run without its copy (#613) likewise left unseen_count counting the flags it dropped.
	for _, viaScript := range []bool{false, true} {
		name := "a restored message already counted as unseen is counted once"
		if viaScript {
			name += ", through the script"
		}
		t.Run(name, func(t *testing.T) {
			pool, database, m := open(t)
			if viaScript {
				makeLarge(t, pool)
			}
			mb := newMailbox(t, pool)
			restored := insertMessage(t, pool, mb, 1, true)
			seen := insertMessage(t, pool, mb, 2, false)
			addState(t, pool, mb, seen, FlagSeen)
			_, err := pool.Exec(ctx, `UPDATE messages SET expunged_at = NULL, expunged_modseq = NULL WHERE id = $1`, restored)
			require.NoError(t, err)
			before, err := database.GetMailboxSummary(ctx, mb.id)
			require.NoError(t, err)
			require.Equal(t, 1, before.UnseenCount, "the messages trigger counted the restored message as unseen")

			if viaScript {
				loadScript(t, pool)
				_, err = pool.Exec(ctx, `CALL sora_backfill_message_state(500000, 0)`)
				require.NoError(t, err)
			}
			upgrade(t, m)
			require.True(t, hasState(t, pool, restored))
			// RFC 9051 §6.3.11: UNSEEN is "the number of messages that do not have the \Seen flag set".
			summary, err := database.GetMailboxSummary(ctx, mb.id)
			require.NoError(t, err)
			assert.Equal(t, 2, summary.NumMessages)
			assert.Equal(t, 1, summary.UnseenCount)
			assert.Equal(t, before.HighestModSeq, summary.HighestModSeq)
		})
	}

	t.Run("large database without the backfill is refused", func(t *testing.T) {
		pool, _, m := open(t)
		makeLarge(t, pool)
		legacy := insertMessage(t, pool, newMailbox(t, pool), 1, false)
		err := m.Up()
		require.Error(t, err, "a database too large to check inside a migration must be backfilled first")
		assert.Contains(t, err.Error(), "scripts/message_state_backfill.sql")
		assert.False(t, hasState(t, pool, legacy))
	})

	t.Run("large database: the script backfills and the migration catches up", func(t *testing.T) {
		pool, database, m := open(t)
		makeLarge(t, pool)
		mb := newMailbox(t, pool)
		legacy := insertMessage(t, pool, mb, 1, false)
		expunged := insertMessage(t, pool, mb, 2, true)
		loadScript(t, pool)

		for _, args := range []string{"0, 0", "-1, 0", "NULL, 0", "1000, -1", "1000, NULL"} {
			_, err := pool.Exec(ctx, "CALL sora_backfill_message_state("+args+")")
			require.Error(t, err, "CALL sora_backfill_message_state(%s) must be refused", args)
		}
		_, err := pool.Exec(ctx, `CALL sora_backfill_message_state(500000, 0)`)
		require.NoError(t, err)
		assert.True(t, hasState(t, pool, legacy))
		assert.False(t, hasState(t, pool, expunged))

		// Mail written after the script finished is checked by the migration.
		later := insertMessage(t, pool, mb, 3, false)
		upgrade(t, m)
		assert.True(t, hasState(t, pool, later), "the migration must check the ids above the script's progress")
		var progress *string
		require.NoError(t, pool.QueryRow(ctx, `SELECT to_regclass('message_state_backfill')::text`).Scan(&progress))
		assert.Nil(t, progress, "the migration drops the script's progress table")
		summary, err := database.GetMailboxSummary(ctx, mb.id)
		require.NoError(t, err)
		assert.Equal(t, 2, summary.UnseenCount)
	})

	// The migration reads the script's progress table and drops it as Sora's database
	// user, the owner of messages (docs/DATABASE.md, Privileges), while an operator may
	// well run the script as a superuser. A table belongs to the role that creates it, so
	// a superuser's table would stop the migration with "permission denied" and leave the
	// version dirty.
	t.Run("the script's progress table belongs to the owner of messages", func(t *testing.T) {
		pool, _, _ := open(t)
		owner := fmt.Sprintf("sora_backfill_owner_%d", time.Now().UnixNano())
		if _, err := pool.Exec(ctx, "CREATE ROLE "+owner+" NOLOGIN"); err != nil {
			t.Skipf("cannot create a role to own messages: %v", err)
		}
		t.Cleanup(func() {
			for _, stmt := range []string{"REASSIGN OWNED BY " + owner + " TO CURRENT_USER", "DROP OWNED BY " + owner, "DROP ROLE " + owner} {
				if _, err := pool.Exec(ctx, stmt); err != nil {
					t.Logf("%s: %v", stmt, err)
				}
			}
		})
		_, err := pool.Exec(ctx, "GRANT USAGE ON SCHEMA public TO "+owner+"; ALTER TABLE messages OWNER TO "+owner)
		require.NoError(t, err)

		loadScript(t, pool) // as the test's superuser
		_, err = pool.Exec(ctx, `CALL sora_backfill_message_state(500000, 0)`)
		require.NoError(t, err)

		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, "SET LOCAL ROLE "+owner)
		require.NoError(t, err)
		var checked *int64
		require.NoError(t, tx.QueryRow(ctx, `SELECT max(checked_through) FROM message_state_backfill`).Scan(&checked),
			"the owner of messages must be able to read the progress")
		_, err = tx.Exec(ctx, `DROP TABLE message_state_backfill`)
		require.NoError(t, err, "the owner of messages must be able to drop the progress table")
	})
}

// COPY and MOVE give the new message its source's flags. A source without a
// message_state row has none, so the new message gets a row with none, not a missing
// row of its own (#1151).
func TestCopyMoveOfMessageWithoutStateWritesState(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, inboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	archiveID := createTestMailbox(t, db, accountID, "Archive")

	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100}
	base := time.Now().UnixNano()
	insert := func(n int) imap.UID {
		t.Helper()
		hash := fmt.Sprintf("statelesscopy-%d-%d", base, n)
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		id, uid, err := db.InsertMessage(ctx, tx, &InsertMessageOptions{
			AccountID: accountID, MailboxID: inboxID, MailboxName: "INBOX",
			S3Domain: "example.com", S3Localpart: "statelesscopy", ContentHash: hash,
			MessageID: fmt.Sprintf("<%s@example.com>", hash), InternalDate: time.Now(), SentDate: time.Now(),
			Size: 100, Subject: fmt.Sprintf("message %d", n), BodyStructure: &bs,
		}, PendingUpload{InstanceID: "test", ContentHash: hash, Size: 100, AccountID: accountID})
		require.NoError(t, err)
		// The message as an older build left it.
		_, err = tx.Exec(ctx, `DELETE FROM message_state WHERE message_id = $1`, id)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return imap.UID(uid)
	}
	copySrc, moveSrc, sameSrc := insert(1), insert(2), insert(3)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	copied, _, err := db.CopyMessages(ctx, tx, &[]imap.UID{copySrc}, inboxID, archiveID, accountID, "example.com", "statelesscopy", "test", nil, nil)
	require.NoError(t, err)
	moved, err := db.MoveMessages(ctx, tx, &[]imap.UID{moveSrc}, inboxID, archiveID, accountID, "example.com", "statelesscopy", "test", nil, nil)
	require.NoError(t, err)
	sameMoved, err := db.MoveMessages(ctx, tx, &[]imap.UID{sameSrc}, inboxID, inboxID, accountID, "example.com", "statelesscopy", "test", nil, nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	for _, p := range []struct {
		name      string
		mailboxID int64
		uid       imap.UID
	}{
		{"COPY", archiveID, copied[copySrc]},
		{"MOVE", archiveID, moved[moveSrc]},
		{"MOVE within the mailbox", inboxID, sameMoved[sameSrc]},
	} {
		t.Run(p.name, func(t *testing.T) {
			require.NotZero(t, p.uid)
			var flags int
			var keywords []byte
			err := db.GetReadPool().QueryRow(ctx, `
				SELECT ms.flags, ms.custom_flags
				FROM messages m
				JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
				WHERE m.mailbox_id = $1 AND m.uid = $2 AND m.expunged_at IS NULL`, p.mailboxID, p.uid).Scan(&flags, &keywords)
			require.NoError(t, err, "the new message must have a message_state row")
			assert.Equal(t, 0, flags)
			assert.JSONEq(t, `[]`, string(keywords))
		})
	}
	summary, err := db.GetMailboxSummary(ctx, archiveID)
	require.NoError(t, err)
	assert.Equal(t, 2, summary.UnseenCount, "the copy and the moved message are unseen in the destination")
}
