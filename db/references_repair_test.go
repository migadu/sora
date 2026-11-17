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

// TestNullReferencesRepair covers the rows that kept a NULL "references": rows copied or
// moved before #837 and rows stored before migration 000036. A live row is filled from
// another row with the same body (content_hash) whose value is stored, even when that
// value is the empty string (no References header). A live row whose body no other row
// holds a value for is counted and stays NULL, an expunged row is left alone, a dry run
// changes nothing, and the scan pages forward by id, so an interrupted run resumes where
// it stopped.
func TestNullReferencesRepair(t *testing.T) {
	// Its own database: the scan reads every row after its cursor, and the counts below
	// must see only this test's rows.
	db := setupTestDatabaseWithSuffix(t, "_references")
	defer db.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	var accountID int64
	inTx(t, db, func(tx pgx.Tx) {
		var err error
		accountID, err = db.CreateAccount(ctx, tx, CreateAccountRequest{
			Email:    fmt.Sprintf("references_repair_%d@example.com", ts),
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

	insert := func(mbox *DBMailbox, hash string, references []string) (id int64) {
		t.Helper()
		inTx(t, db, func(tx pgx.Tx) {
			id, _, err = db.InsertMessage(ctx, tx, &InsertMessageOptions{
				AccountID: accountID, MailboxID: mbox.ID, MailboxName: mbox.Name,
				S3Domain: "example.com", S3Localpart: "user",
				ContentHash: hash, MessageID: "<" + hash + "@example.com>", References: references,
				Flags: []imap.Flag{}, InternalDate: time.Now(), Size: 1024,
				Subject: "References", PlaintextBody: "test", SentDate: time.Now(),
			}, PendingUpload{AccountID: accountID, ContentHash: hash})
			require.NoError(t, err)
		})
		return id
	}
	references := func(id int64) *string {
		t.Helper()
		var v *string
		require.NoError(t, db.GetWritePool().QueryRow(ctx, `SELECT "references" FROM messages WHERE id = $1`, id).Scan(&v))
		return v
	}
	str := func(s string) *string { return &s }

	threaded := fmt.Sprintf("refs-repair-threaded-%d", ts)
	plain := fmt.Sprintf("refs-repair-plain-%d", ts)
	lonely := fmt.Sprintf("refs-repair-lonely-%d", ts)

	// The originals hold the value delivery stored: the IDs, or '' for a message without
	// a References header. The copies hold NULL, as COPY and MOVE wrote it before #837.
	original := insert(inbox, threaded, []string{"q@example.com", "r@example.com"})
	copied := insert(copies, threaded, []string{"q@example.com", "r@example.com"})
	expunged := insert(copies, threaded+"-x", nil)
	plainOriginal := insert(inbox, plain, nil)
	plainCopy := insert(copies, plain, nil)
	orphan := insert(copies, lonely, []string{"s@example.com"})
	first := original - 1
	_, err = db.GetWritePool().Exec(ctx, `UPDATE messages SET "references" = NULL WHERE id = ANY($1)`,
		[]int64{copied, expunged, plainCopy, orphan})
	require.NoError(t, err)
	// An expunged copy of the threaded body: not live, so it is neither counted nor filled.
	_, err = db.GetWritePool().Exec(ctx, `UPDATE messages SET content_hash = $1, expunged_at = now() WHERE id = $2`,
		threaded, expunged)
	require.NoError(t, err)
	require.Equal(t, str("q@example.com r@example.com"), references(original))
	require.Equal(t, str(""), references(plainOriginal))

	// scan pages through the rows after the cursor limit at a time, like the command, and
	// with fill writes each batch's fills; it stops after maxBatches batches when that is
	// positive. It returns the totals and the cursor it stopped at.
	type totals struct{ scanned, missing, fillable, filled int }
	scan := func(after int64, limit, maxBatches int, fill bool) (totals, int64) {
		t.Helper()
		var got totals
		for n := 0; maxBatches <= 0 || n < maxBatches; n++ {
			batch, err := db.FindNullReferences(ctx, after, limit)
			require.NoError(t, err)
			require.LessOrEqual(t, batch.Scanned, limit)
			if batch.Scanned == 0 {
				break
			}
			require.Greater(t, batch.LastID, after, "the batches move forward")
			after = batch.LastID
			got.scanned += batch.Scanned
			got.missing += batch.Missing
			got.fillable += len(batch.Fills)
			if fill && len(batch.Fills) > 0 {
				inTx(t, db, func(tx pgx.Tx) {
					filled, err := db.FillNullReferences(ctx, tx, batch.Fills)
					require.NoError(t, err)
					got.filled += int(filled)
				})
			}
		}
		return got, after
	}
	unchanged := func() {
		t.Helper()
		for _, id := range []int64{copied, expunged, plainCopy, orphan} {
			require.Nil(t, references(id), "row %d", id)
		}
	}

	t.Run("dry run", func(t *testing.T) {
		got, _ := scan(first, 100, 0, false)
		require.Equal(t, totals{scanned: 6, missing: 3, fillable: 2}, got,
			"the copy and the plain copy have a donor, the orphan has none, the expunged copy is not live")
		got, _ = scan(first, 1, 0, false)
		require.Equal(t, totals{scanned: 6, missing: 3, fillable: 2}, got, "batches of one see the same rows")
		unchanged()
	})

	t.Run("resumable", func(t *testing.T) {
		// Two batches of one row reach the copy and stop: the copy is filled, nothing
		// after the cursor is touched.
		got, cursor := scan(first, 1, 2, true)
		require.Equal(t, copied, cursor)
		require.Equal(t, totals{scanned: 2, missing: 1, fillable: 1, filled: 1}, got)
		require.Equal(t, str("q@example.com r@example.com"), references(copied))
		require.Nil(t, references(plainCopy), "after the cursor")

		// Resumed from the cursor, the run fills the rest.
		got, _ = scan(cursor, 2, 0, true)
		require.Equal(t, totals{scanned: 4, missing: 2, fillable: 1, filled: 1}, got)
		require.Equal(t, str(""), references(plainCopy), "filled with the '' its original holds")
		require.Nil(t, references(orphan), "no other row holds a value for its body")
		require.Nil(t, references(expunged), "expunged rows are left alone")
		require.Equal(t, str("q@example.com r@example.com"), references(original))
	})

	t.Run("run again", func(t *testing.T) {
		got, _ := scan(first, 100, 0, true)
		require.Equal(t, totals{scanned: 6, missing: 1}, got, "only the orphan is left, with no donor")
	})

	t.Run("fill skips a row that changed", func(t *testing.T) {
		// A fill found by the scan is written only while the row is still live and NULL.
		_, err := db.GetWritePool().Exec(ctx, `UPDATE messages SET expunged_at = now() WHERE id = $1`, orphan)
		require.NoError(t, err)
		inTx(t, db, func(tx pgx.Tx) {
			filled, err := db.FillNullReferences(ctx, tx, []ReferencesFill{
				{ID: orphan, References: "s@example.com"},
				{ID: original, References: "overwritten"},
			})
			require.NoError(t, err)
			require.Zero(t, filled)
		})
		require.Nil(t, references(orphan))
		require.Equal(t, str("q@example.com r@example.com"), references(original))
	})
}

// TestNullReferencesBatchUsesIndexes: each batch must read the messages table through
// its primary key from the cursor and find a donor through an index that leads with
// content_hash, and a fill must find its rows by primary key, never by scanning the
// table, which holds hundreds of millions of rows in production. Sequential scans are
// disabled so a small test table cannot hide a predicate that no index can serve.
func TestNullReferencesBatchUsesIndexes(t *testing.T) {
	db := setupTestDatabaseWithSuffix(t, "_references")
	defer db.Close()
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	// On a nearly empty table every index costs the same and the plan says nothing, so
	// the planner is given a table of some size. The rows are rolled back with the
	// transaction.
	_, err = tx.Exec(ctx, `
		INSERT INTO messages (uid, s3_domain, s3_localpart, content_hash, recipients_json, message_id,
		                      sent_date, internal_date, size, body_structure, created_modseq, "references")
		SELECT g, 'example.com', 'user', md5(g::text), '[]', '<' || g || '@example.com>',
		       now(), now(), 100, '\x00', g, CASE WHEN g % 2 = 0 THEN '' END
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

	fill := explain(fillNullReferencesSQL, []int64{1, 2}, []string{"a@example.com", ""})
	require.Regexp(t, `Index Scan using messages_pkey on messages`, fill, "a fill looks each row up by id")

	text := explain(nullReferencesBatchSQL, int64(0), 1000)
	require.Regexp(t, `Index Scan using messages_pkey on messages`, text, "the batch reads messages from the cursor by id")
	var donorIndex string
	require.NoError(t, tx.QueryRow(ctx, `
		SELECT indexrelid::regclass::text FROM pg_index
		WHERE indrelid = 'messages'::regclass
		  AND indkey[0] = (SELECT attnum FROM pg_attribute WHERE attrelid = 'messages'::regclass AND attname = 'content_hash')
		  AND position(indexrelid::regclass::text IN $1) > 0
		LIMIT 1`, text).Scan(&donorIndex))
	require.NotEmpty(t, donorIndex, "the donor is found through an index that leads with content_hash")
}
