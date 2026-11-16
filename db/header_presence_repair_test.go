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

func TestNullHeaderPresenceRepair(t *testing.T) {
	db := setupTestDatabaseWithSuffix(t, "_header_presence")
	defer db.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	var accountID int64
	inTx(t, db, func(tx pgx.Tx) {
		var err error
		accountID, err = db.CreateAccount(ctx, tx, CreateAccountRequest{
			Email:    fmt.Sprintf("header_presence_repair_%d@example.com", ts),
			Password: "password", IsPrimary: true, HashType: "bcrypt",
		})
		require.NoError(t, err)
		for _, name := range []string{"INBOX", "Copies"} {
			require.NoError(t, db.CreateMailbox(ctx, tx, accountID, name, nil))
		}
	})
	inbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	copies, err := db.GetMailboxByName(ctx, accountID, "Copies")
	require.NoError(t, err)

	insert := func(mbox *DBMailbox, hash string, mask *int16) (id int64) {
		t.Helper()
		inTx(t, db, func(tx pgx.Tx) {
			id, _, err = db.InsertMessage(ctx, tx, &InsertMessageOptions{
				AccountID: accountID, MailboxID: mbox.ID, MailboxName: mbox.Name,
				S3Domain: "example.com", S3Localpart: "user",
				ContentHash: hash, MessageID: "<" + hash + "@example.com>",
				HeaderPresence: mask, Flags: []imap.Flag{},
				InternalDate: time.Now(), Size: 1024,
				Subject: "Presence", PlaintextBody: "test", SentDate: time.Now(),
			}, PendingUpload{AccountID: accountID, ContentHash: hash})
			require.NoError(t, err)
		})
		return id
	}
	presence := func(id int64) *int16 {
		t.Helper()
		var v *int16
		require.NoError(t, db.GetWritePool().QueryRow(ctx, `SELECT header_presence FROM messages WHERE id = $1`, id).Scan(&v))
		return v
	}
	maskPtr := func(v int16) *int16 { return &v }

	withCc := fmt.Sprintf("hp-repair-cc-%d", ts)
	bare := fmt.Sprintf("hp-repair-bare-%d", ts)
	lonely := fmt.Sprintf("hp-repair-lonely-%d", ts)

	donor := insert(inbox, withCc, maskPtr(1|4)) // From + Cc
	copyMissing := insert(copies, withCc, nil)
	expungedMissing := insert(copies, withCc+"-exp", nil)
	bareDonor := insert(inbox, bare, maskPtr(0)) // all tracked headers absent -> mask 0, NOT NULL
	bareCopy := insert(copies, bare, nil)
	orphan := insert(copies, lonely, nil)
	first := donor - 1

	_, err = db.GetWritePool().Exec(ctx, `UPDATE messages SET content_hash = $1, expunged_at = now() WHERE id = $2`,
		withCc, expungedMissing)
	require.NoError(t, err)
	// Expunging donor still allows it to donate to bareCopy if needed; verify expunged donor works too.
	_, err = db.GetWritePool().Exec(ctx, `UPDATE messages SET expunged_at = now() WHERE id = $1`, bareDonor)
	require.NoError(t, err)

	// Policy check: FillNullHeaderPresence must NOT touch uid, created_modseq, "references",
	// message_state, highest_uid, highest_modseq, or message_count.
	snapshot := func(id int64) string {
		var s string
		require.NoError(t, db.GetWritePool().QueryRow(ctx,
			`SELECT jsonb_build_array(m.uid, m.created_modseq, m."references",
			        (SELECT count(*) FROM message_state WHERE message_id = m.id),
			        b.highest_uid, st.highest_modseq, st.message_count)::text
			 FROM messages m
			 JOIN mailboxes b ON b.id = m.mailbox_id
			 LEFT JOIN mailbox_stats st ON st.mailbox_id = b.id
			 WHERE m.id = $1`, id).Scan(&s))
		return s
	}
	beforeCopySnap := snapshot(copyMissing)

	type totals struct{ scanned, missing, dbFillable, needsS3, filled int }
	scan := func(after int64, limit, maxBatches int, fill bool) (totals, int64) {
		t.Helper()
		var got totals
		for n := 0; maxBatches <= 0 || n < maxBatches; n++ {
			batch, err := db.FindNullHeaderPresence(ctx, after, limit)
			require.NoError(t, err)
			require.LessOrEqual(t, batch.Scanned, limit)
			if batch.Scanned == 0 {
				break
			}
			require.Greater(t, batch.LastID, after)
			after = batch.LastID
			got.scanned += batch.Scanned
			got.missing += batch.Missing
			got.dbFillable += len(batch.Fills)
			got.needsS3 += len(batch.NeedsS3)
			if fill && len(batch.Fills) > 0 {
				inTx(t, db, func(tx pgx.Tx) {
					n, err := db.FillNullHeaderPresence(ctx, tx, batch.Fills)
					require.NoError(t, err)
					got.filled += int(n)
				})
			}
		}
		return got, after
	}

	t.Run("dry run", func(t *testing.T) {
		got, _ := scan(first, 100, 0, false)
		require.Equal(t, totals{scanned: 6, missing: 3, dbFillable: 2, needsS3: 1}, got)
		got, _ = scan(first, 1, 0, false)
		require.Equal(t, totals{scanned: 6, missing: 3, dbFillable: 2, needsS3: 1}, got)
		require.Nil(t, presence(copyMissing))
		require.Nil(t, presence(bareCopy))
		require.Nil(t, presence(orphan))
	})

	t.Run("resumable and preserves other metadata", func(t *testing.T) {
		got, cursor := scan(first, 1, 2, true)
		require.Equal(t, copyMissing, cursor)
		require.Equal(t, totals{scanned: 2, missing: 1, dbFillable: 1, filled: 1}, got)
		require.Equal(t, maskPtr(5), presence(copyMissing))
		require.Equal(t, beforeCopySnap, snapshot(copyMissing), "only header_presence may change")
		require.Nil(t, presence(bareCopy))

		got, _ = scan(cursor, 2, 0, true)
		require.Equal(t, totals{scanned: 4, missing: 2, dbFillable: 1, needsS3: 1, filled: 1}, got)
		require.Equal(t, maskPtr(0), presence(bareCopy), "expunged donor with mask 0 fills bareCopy")
		require.Nil(t, presence(orphan))
		require.Nil(t, presence(expungedMissing))
	})

	t.Run("fill skips changed or expunged rows", func(t *testing.T) {
		_, err := db.GetWritePool().Exec(ctx, `UPDATE messages SET expunged_at = now() WHERE id = $1`, orphan)
		require.NoError(t, err)
		inTx(t, db, func(tx pgx.Tx) {
			filled, err := db.FillNullHeaderPresence(ctx, tx, []HeaderPresenceFill{
				{ID: orphan, HeaderPresence: 7},
				{ID: donor, HeaderPresence: 0},
			})
			require.NoError(t, err)
			require.Zero(t, filled)
		})
		require.Nil(t, presence(orphan))
		require.Equal(t, maskPtr(5), presence(donor))
	})
}

func TestNullHeaderPresenceBatchUsesIndexes(t *testing.T) {
	db := setupTestDatabaseWithSuffix(t, "_header_presence")
	defer db.Close()
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO messages (uid, s3_domain, s3_localpart, content_hash, recipients_json, message_id,
		                      sent_date, internal_date, size, body_structure, created_modseq, header_presence)
		SELECT g, 'example.com', 'user', md5(g::text), '[]', '<' || g || '@example.com>',
		       now(), now(), 100, '\x00', g, CASE WHEN g % 2 = 0 THEN 1::smallint END
		FROM generate_series(1, 5000) g`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `ANALYZE messages`)
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

	fill := explain(fillNullHeaderPresenceSQL, []int64{1, 2}, []int16{1, 0})
	require.Regexp(t, `Index Scan using messages_pkey on messages`, fill)

	text := explain(nullHeaderPresenceBatchSQL, int64(0), 1000)
	require.Regexp(t, `Index Scan using messages_pkey on messages`, text)
	var donorIndex string
	require.NoError(t, tx.QueryRow(ctx, `
		SELECT indexrelid::regclass::text FROM pg_index
		WHERE indrelid = 'messages'::regclass
		  AND indkey[0] = (SELECT attnum FROM pg_attribute WHERE attrelid = 'messages'::regclass AND attname = 'content_hash')
		  AND position(indexrelid::regclass::text IN $1) > 0
		LIMIT 1`, text).Scan(&donorIndex))
	require.NotEmpty(t, donorIndex)
}
