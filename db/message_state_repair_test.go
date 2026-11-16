package db

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

func TestMissingMessageStateRepair(t *testing.T) {
	db := setupTestDatabaseWithSuffix(t, "_message_state")
	defer db.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	var accountID int64
	inTx(t, db, func(tx pgx.Tx) {
		var err error
		accountID, err = db.CreateAccount(ctx, tx, CreateAccountRequest{
			Email:    fmt.Sprintf("message_state_repair_%d@example.com", ts),
			Password: "password", IsPrimary: true, HashType: "bcrypt",
		})
		require.NoError(t, err)
		for _, name := range []string{"INBOX", "Archive", "RestoredNoStats"} {
			require.NoError(t, db.CreateMailbox(ctx, tx, accountID, name, nil))
		}
	})
	inbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	archive, err := db.GetMailboxByName(ctx, accountID, "Archive")
	require.NoError(t, err)
	noStatsMbox, err := db.GetMailboxByName(ctx, accountID, "RestoredNoStats")
	require.NoError(t, err)

	n := 0
	insert := func(mbox *DBMailbox, flags ...imap.Flag) (id int64) {
		t.Helper()
		n++
		hash := fmt.Sprintf("state-repair-%d-%d", ts, n)
		inTx(t, db, func(tx pgx.Tx) {
			id, _, err = db.InsertMessage(ctx, tx, &InsertMessageOptions{
				AccountID: accountID, MailboxID: mbox.ID, MailboxName: mbox.Name,
				S3Domain: "example.com", S3Localpart: "user",
				ContentHash: hash, MessageID: "<" + hash + "@example.com>",
				Flags: append([]imap.Flag{}, flags...), InternalDate: time.Now(), Size: 1024,
				Subject: "state", PlaintextBody: "test", SentDate: time.Now(),
			}, PendingUpload{AccountID: accountID, ContentHash: hash})
			require.NoError(t, err)
		})
		return id
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := db.GetWritePool().Exec(ctx, sql, args...)
		require.NoError(t, err)
	}
	dropState := func(id int64) { exec(`DELETE FROM message_state WHERE message_id = $1`, id) }
	expunge := func(id int64) {
		exec(`UPDATE messages SET expunged_at = now(), expunged_modseq = nextval('messages_modseq') WHERE id = $1`, id)
	}

	kept := insert(inbox, imap.FlagSeen, "Work")
	_ = insert(inbox)
	upgraded := insert(inbox, imap.FlagSeen)
	dropState(upgraded)
	copied := insert(archive)
	dropState(copied)
	restored := insert(archive)
	expunge(restored)
	dropState(restored)
	exec(`UPDATE messages SET expunged_at = NULL, expunged_modseq = NULL WHERE id = $1`, restored)
	gone := insert(archive)
	expunge(gone)
	dropState(gone)

	// Pre-000037 restore into a recreated mailbox that had no mailbox_stats row yet.
	restoredNoStats := insert(noStatsMbox)
	dropState(restoredNoStats)
	exec(`DELETE FROM mailbox_stats WHERE mailbox_id = $1`, noStatsMbox.ID)

	first := kept - 1

	summary := func(mbox *DBMailbox) *MailboxSummary {
		t.Helper()
		s, err := db.GetMailboxSummary(ctx, mbox.ID)
		require.NoError(t, err)
		return s
	}
	inboxBefore, archiveBefore, noStatsBefore := summary(inbox), summary(archive), summary(noStatsMbox)
	require.Equal(t, 1, inboxBefore.UnseenCount)
	require.Equal(t, 1, archiveBefore.UnseenCount)

	type state struct {
		flags         int
		customFlags   string
		updatedModSeq *int64
	}
	stateOf := func(id int64) *state {
		t.Helper()
		var s state
		err := db.GetWritePool().QueryRow(ctx, `
			SELECT ms.flags, ms.custom_flags::text, ms.updated_modseq
			FROM message_state ms JOIN messages m ON m.id = ms.message_id AND m.mailbox_id = ms.mailbox_id
			WHERE ms.message_id = $1`, id).Scan(&s.flags, &s.customFlags, &s.updatedModSeq)
		if err == pgx.ErrNoRows {
			return nil
		}
		require.NoError(t, err)
		return &s
	}
	keptState := stateOf(kept)
	require.NotNil(t, keptState)

	type totals struct {
		scanned   int
		missing   []MessageWithoutState
		added     int64
		mailboxes []int64
	}
	scan := func(after int64, limit, maxBatches int, apply bool) (totals, int64) {
		t.Helper()
		var got totals
		for b := 0; maxBatches <= 0 || b < maxBatches; b++ {
			batch, err := db.FindMissingMessageState(ctx, after, limit)
			require.NoError(t, err)
			require.LessOrEqual(t, batch.Scanned, limit)
			if batch.Scanned == 0 {
				break
			}
			require.Greater(t, batch.LastID, after)
			after = batch.LastID
			got.scanned += batch.Scanned
			got.missing = append(got.missing, batch.Missing...)
			if apply && len(batch.Missing) > 0 {
				ids := make([]int64, len(batch.Missing))
				for i, m := range batch.Missing {
					ids[i] = m.ID
				}
				inTx(t, db, func(tx pgx.Tx) {
					repair, err := db.AddMissingMessageState(ctx, tx, ids)
					require.NoError(t, err)
					got.added += repair.Added
					got.mailboxes = append(got.mailboxes, repair.Mailboxes...)
				})
			}
		}
		return got, after
	}
	allMissing := []MessageWithoutState{
		{ID: upgraded, MailboxID: inbox.ID},
		{ID: copied, MailboxID: archive.ID},
		{ID: restored, MailboxID: archive.ID},
		{ID: restoredNoStats, MailboxID: noStatsMbox.ID},
	}

	t.Run("dry run", func(t *testing.T) {
		got, _ := scan(first, 100, 0, false)
		require.Equal(t, totals{scanned: 7, missing: allMissing}, got)
		got, _ = scan(first, 1, 0, false)
		require.Equal(t, totals{scanned: 7, missing: allMissing}, got)
		for _, id := range []int64{upgraded, copied, restored, restoredNoStats, gone} {
			require.Nil(t, stateOf(id))
		}
		require.Equal(t, inboxBefore, summary(inbox))
		require.Equal(t, archiveBefore, summary(archive))
		require.Equal(t, noStatsBefore, summary(noStatsMbox))
	})

	t.Run("resumable", func(t *testing.T) {
		got, cursor := scan(first, 1, 3, true)
		require.Equal(t, upgraded, cursor)
		require.Equal(t, totals{scanned: 3, missing: allMissing[:1], added: 1, mailboxes: []int64{inbox.ID}}, got)
		require.Nil(t, stateOf(copied))
		require.Equal(t, 2, summary(inbox).UnseenCount)
		require.Equal(t, 1, summary(archive).UnseenCount)

		got, _ = scan(cursor, 2, 0, true)
		require.Equal(t, totals{scanned: 4, missing: allMissing[1:], added: 3, mailboxes: []int64{archive.ID, noStatsMbox.ID}}, got)
	})

	t.Run("repaired", func(t *testing.T) {
		for _, id := range []int64{upgraded, copied, restored, restoredNoStats} {
			require.Equal(t, &state{flags: 0, customFlags: "[]"}, stateOf(id), "message %d", id)
		}
		require.Equal(t, keptState, stateOf(kept))
		require.Nil(t, stateOf(gone))

		inboxAfter, archiveAfter, noStatsAfter := summary(inbox), summary(archive), summary(noStatsMbox)
		require.Equal(t, 2, inboxAfter.UnseenCount)
		require.Equal(t, 2, archiveAfter.UnseenCount)
		require.Equal(t, 1, noStatsAfter.UnseenCount)
		require.Equal(t, 1, noStatsAfter.NumMessages, "seeding mailbox_stats preserves live message_count")
		require.GreaterOrEqual(t, noStatsAfter.HighestModSeq, uint64(1), "seeding mailbox_stats preserves positive highest_modseq")
		require.Equal(t, inboxBefore.HighestModSeq, inboxAfter.HighestModSeq)
		require.Equal(t, archiveBefore.HighestModSeq, archiveAfter.HighestModSeq)

		poll, err := db.PollMailbox(ctx, noStatsMbox.ID, 0)
		require.NoError(t, err)
		require.Equal(t, uint32(1), poll.NumMessages, "PollMailbox must still see live messages on a seeded mailbox")

		seq, err := db.GetFirstUnseenSeqNum(ctx, archive.ID)
		require.NoError(t, err)
		require.Equal(t, uint32(1), seq)
	})

	t.Run("run again", func(t *testing.T) {
		got, _ := scan(first, 100, 0, true)
		require.Equal(t, totals{scanned: 7}, got)
	})
}

func TestMissingMessageStateBatchUsesIndexes(t *testing.T) {
	db := setupTestDatabaseWithSuffix(t, "_message_state")
	defer db.Close()
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	var mboxID int64
	err = tx.QueryRow(ctx, `SELECT id FROM mailboxes LIMIT 1`).Scan(&mboxID)
	if err == pgx.ErrNoRows {
		accID, createErr := db.CreateAccount(ctx, tx, CreateAccountRequest{
			Email: fmt.Sprintf("plan_%d@example.com", time.Now().UnixNano()), Password: "password", IsPrimary: true, HashType: "bcrypt",
		})
		require.NoError(t, createErr)
		require.NoError(t, db.CreateMailbox(ctx, tx, accID, "INBOX", nil))
		require.NoError(t, tx.QueryRow(ctx, `SELECT id FROM mailboxes WHERE account_id = $1`, accID).Scan(&mboxID))
	} else {
		require.NoError(t, err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO messages (mailbox_id, uid, s3_domain, s3_localpart, content_hash, recipients_json, message_id,
		                      sent_date, internal_date, size, body_structure, created_modseq)
		SELECT $1, 100000 + g, 'example.com', 'user', md5(g::text), '[]', '<' || g || '@example.com>',
		       now(), now(), 100, '\x00', g
		FROM generate_series(1, 5000) g`, mboxID)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO message_state (message_id) SELECT id FROM messages WHERE id % 2 = 0 ON CONFLICT (message_id) DO NOTHING`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `ANALYZE messages, message_state`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `SET LOCAL enable_seqscan = off`)
	require.NoError(t, err)
	explain := func(sql string, args ...any) string {
		t.Helper()
		rows, err := tx.Query(ctx, "EXPLAIN "+sql, append([]any{pgx.QueryExecModeExec}, args...)...)
		require.NoError(t, err)
		var plan []string
		for rows.Next() {
			var line string
			require.NoError(t, rows.Scan(&line))
			plan = append(plan, line)
		}
		require.NoError(t, rows.Err())
		text := strings.Join(plan, "\n")
		t.Log(text)
		require.NotContains(t, text, "Seq Scan")
		return text
	}

	text := explain(missingMessageStateBatchSQL, int64(0), 1000)
	require.Regexp(t, `Index (Only )?Scan using messages_pkey on messages`, text)
	require.Regexp(t, `Index (Only )?Scan using message_state_pkey on message_state`, text)

	ids, mailboxes := []int64{1, 2}, []int64{1}
	for _, sql := range []string{missingMessageStateMailboxesSQL, addMissingMessageStateSQL} {
		args := []any{ids}
		if sql == addMissingMessageStateSQL {
			args = append(args, mailboxes)
		}
		require.Regexp(t, `Index Scan using messages_pkey on messages m\b`, explain(sql, args...))
	}
	require.Regexp(t, `Index Scan using mailboxes_pkey on mailboxes`, explain(lockMailboxesSQL, mailboxes))
	require.Regexp(t, `idx_message_state_first_unseen`, explain(recountMailboxUnseenSQL, mailboxes))
}
