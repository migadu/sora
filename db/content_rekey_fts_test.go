package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/require"
)

// rekeyFTSFixture holds two accounts, A and B, each with an S3 path and mailboxes, for the
// tests of what RekeyContentHash does to the search rows of copies of the body it renames.
type rekeyFTSFixture struct {
	t        *testing.T
	ctx      context.Context
	d        *Database
	a, b     int64
	inboxA   int64
	archiveA int64
	inboxB   int64
	sharedB  int64
	hashes   []string
}

const rekeyFTSWord = "rekeyneedle"

func newRekeyFTSFixture(t *testing.T) *rekeyFTSFixture {
	d := setupTestDatabase(t)
	t.Cleanup(d.Close) // registered first, so it runs after every other cleanup
	f := &rekeyFTSFixture{t: t, ctx: context.Background(), d: d}
	f.a, f.inboxA = f.account("a", "INBOX")
	f.archiveA = f.mailbox(f.a, "Archive")
	f.b, f.inboxB = f.account("b", "INBOX")
	f.sharedB = f.mailbox(f.b, "Shared")
	t.Cleanup(func() {
		f.d.GetWritePool().Exec(context.Background(), `DELETE FROM messages_fts_v2 WHERE content_hash = ANY($1)`, f.hashes)
	})
	return f
}

func (f *rekeyFTSFixture) account(name, mailbox string) (int64, int64) {
	f.t.Helper()
	email := fmt.Sprintf("rekey_fts_%s_%d@example.com", name, time.Now().UnixNano())
	tx, err := f.d.GetWritePool().Begin(f.ctx)
	require.NoError(f.t, err)
	defer tx.Rollback(f.ctx)
	id, err := f.d.CreateAccount(f.ctx, tx, CreateAccountRequest{Email: email, Password: "password123", IsPrimary: true, HashType: "bcrypt"})
	require.NoError(f.t, err)
	require.NoError(f.t, tx.Commit(f.ctx))
	return id, f.mailbox(id, mailbox)
}

func (f *rekeyFTSFixture) mailbox(accountID int64, name string) int64 {
	f.t.Helper()
	tx, err := f.d.GetWritePool().Begin(f.ctx)
	require.NoError(f.t, err)
	defer tx.Rollback(f.ctx)
	require.NoError(f.t, f.d.CreateMailbox(f.ctx, tx, accountID, name, nil))
	require.NoError(f.t, tx.Commit(f.ctx))
	mbox, err := f.d.GetMailboxByName(f.ctx, accountID, name)
	require.NoError(f.t, err)
	return mbox.ID
}

// hash returns a fresh 64-hex content hash, removed from messages_fts_v2 at cleanup.
func (f *rekeyFTSFixture) hash(label string) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s %s %d", f.t.Name(), label, time.Now().UnixNano()))
	h := hex.EncodeToString(sum[:])
	f.hashes = append(f.hashes, h)
	return h
}

func (f *rekeyFTSFixture) path(accountID int64) (string, string) {
	return "example.com", fmt.Sprintf("user%d", accountID)
}

// importBody stores an uploaded body for accountID under hash the way the maildir importer
// does, staging its text for the FTS worker, and returns its UID.
func (f *rekeyFTSFixture) importBody(accountID, mailboxID int64, hash string) imap.UID {
	f.t.Helper()
	domain, localpart := f.path(accountID)
	tx, err := f.d.GetWritePool().Begin(f.ctx)
	require.NoError(f.t, err)
	defer tx.Rollback(f.ctx)
	_, uid, err := f.d.InsertMessageFromImporter(f.ctx, tx, &InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   "INBOX",
		S3Domain:      domain,
		S3Localpart:   localpart,
		ContentHash:   hash,
		MessageID:     fmt.Sprintf("<%s@example.com>", hash[:16]),
		InternalDate:  time.Now(),
		Size:          100,
		Subject:       "Imported",
		PlaintextBody: "the " + rekeyFTSWord + " body",
		SentDate:      time.Now(),
	})
	require.NoError(f.t, err)
	require.NoError(f.t, tx.Commit(f.ctx))
	return imap.UID(uid)
}

// copyTo copies uid from src into dest in tx, as IMAP COPY does: a body of another account
// is copied with the hash its object was made available under the owner's key for.
func (f *rekeyFTSFixture) copyTo(tx pgx.Tx, uid imap.UID, src, dest, destAccount int64, hash string) {
	f.t.Helper()
	uids := []imap.UID{uid}
	domain, localpart := f.path(destAccount)
	_, _, err := f.d.CopyMessages(f.ctx, tx, &uids, src, dest, destAccount, domain, localpart, "test",
		map[imap.UID]string{uid: hash}, []string{hash})
	require.NoError(f.t, err)
}

func (f *rekeyFTSFixture) moveTo(tx pgx.Tx, uid imap.UID, src, dest, destAccount int64, hash string) {
	f.t.Helper()
	uids := []imap.UID{uid}
	domain, localpart := f.path(destAccount)
	_, err := f.d.MoveMessages(f.ctx, tx, &uids, src, dest, destAccount, domain, localpart, "test",
		map[imap.UID]string{uid: hash}, []string{hash})
	require.NoError(f.t, err)
}

func (f *rekeyFTSFixture) inTx(fn func(tx pgx.Tx)) {
	f.t.Helper()
	tx, err := f.d.GetWritePool().Begin(f.ctx)
	require.NoError(f.t, err)
	defer tx.Rollback(f.ctx)
	fn(tx)
	require.NoError(f.t, tx.Commit(f.ctx))
}

func (f *rekeyFTSFixture) rekey(tx pgx.Tx, accountID int64, oldHash, newHash string) {
	f.t.Helper()
	domain, localpart := f.path(accountID)
	_, err := f.d.RekeyContentHash(f.ctx, tx, accountID, ContentObject{S3Domain: domain, S3Localpart: localpart, ContentHash: oldHash}, newHash)
	require.NoError(f.t, err)
}

// drainFTS runs the FTS worker until it has resolved every queued row of this test's
// bodies. The rows are moved to the head of the FIFO queue first, so rows other tests left
// queued cannot hold them back.
func (f *rekeyFTSFixture) drainFTS() {
	f.t.Helper()
	for range 10 {
		var queued int
		require.NoError(f.t, f.d.GetWritePool().QueryRow(f.ctx, `
			WITH q AS (
				UPDATE messages_fts_v2 SET created_at = '1900-01-01'
				WHERE content_hash = ANY($1) AND text_body_tsv IS NULL
				RETURNING 1)
			SELECT count(*) FROM q`, f.hashes).Scan(&queued))
		if queued == 0 {
			return
		}
		tx, err := f.d.GetWritePool().Begin(f.ctx)
		require.NoError(f.t, err)
		_, err = f.d.ProcessFTSBatch(f.ctx, tx, 100)
		require.NoError(f.t, err)
		require.NoError(f.t, tx.Commit(f.ctx))
	}
	f.t.Fatal("the FTS worker left rows of this test queued")
}

// requireSearchable fails unless every message row of accountID carrying one of hashes
// finds the body's word through its own FTS row, the row a body search joins it to.
func (f *rekeyFTSFixture) requireSearchable(accountID int64, hashes ...string) {
	f.t.Helper()
	rows, err := f.d.GetWritePool().Query(f.ctx, `
		SELECT m.mailbox_id, m.uid, m.content_hash,
		       EXISTS (SELECT 1 FROM messages_fts_v2 v
		               WHERE v.content_hash = m.content_hash AND v.account_id = m.account_id
		                 AND v.text_body_tsv @@ plainto_tsquery('simple', $3))
		FROM messages m
		WHERE m.account_id = $1 AND m.content_hash = ANY($2) AND m.expunged_at IS NULL
		ORDER BY m.mailbox_id, m.uid`, accountID, hashes, rekeyFTSWord)
	require.NoError(f.t, err)
	defer rows.Close()
	n := 0
	for rows.Next() {
		var mailboxID, uid int64
		var hash string
		var found bool
		require.NoError(f.t, rows.Scan(&mailboxID, &uid, &hash, &found))
		require.True(f.t, found, "message %d/%d of account %d (hash %s…) is not searchable by body", mailboxID, uid, accountID, hash[:8])
		n++
	}
	require.NoError(f.t, rows.Err())
	require.NotZero(f.t, n, "account %d has no live message with these hashes", accountID)
}

// TestRekeyKeepsCopiesSearchable: a copy of a body that sora-admin import rekey renames
// must stay searchable by body. The copy's own FTS row (one per account, see restageFTS)
// waits for a vector from a sibling row of the same hash, and the rekey removes the
// sibling it renames.
func TestRekeyKeepsCopiesSearchable(t *testing.T) {
	t.Run("copy into another account, body indexed", func(t *testing.T) {
		f := newRekeyFTSFixture(t)
		oldHash, newHash := f.hash("old"), f.hash("new")
		uid := f.importBody(f.a, f.inboxA, oldHash)
		f.drainFTS()
		f.inTx(func(tx pgx.Tx) { f.copyTo(tx, uid, f.inboxA, f.sharedB, f.b, oldHash) })
		f.inTx(func(tx pgx.Tx) { f.rekey(tx, f.a, oldHash, newHash) })
		f.drainFTS()
		f.requireSearchable(f.a, oldHash, newHash)
		f.requireSearchable(f.b, oldHash, newHash)
	})

	t.Run("copy into another account, text still pending", func(t *testing.T) {
		f := newRekeyFTSFixture(t)
		oldHash, newHash := f.hash("old"), f.hash("new")
		uid := f.importBody(f.a, f.inboxA, oldHash)
		f.inTx(func(tx pgx.Tx) { f.copyTo(tx, uid, f.inboxA, f.sharedB, f.b, oldHash) })
		f.inTx(func(tx pgx.Tx) { f.rekey(tx, f.a, oldHash, newHash) })
		f.drainFTS()
		f.requireSearchable(f.a, oldHash, newHash)
		f.requireSearchable(f.b, oldHash, newHash)
	})

	t.Run("copy into the re-keyed account", func(t *testing.T) {
		f := newRekeyFTSFixture(t)
		oldHash, newHash := f.hash("old"), f.hash("new")
		uid := f.importBody(f.b, f.inboxB, oldHash)
		f.drainFTS()
		f.inTx(func(tx pgx.Tx) { f.copyTo(tx, uid, f.inboxB, f.archiveA, f.a, oldHash) })
		f.inTx(func(tx pgx.Tx) { f.rekey(tx, f.a, oldHash, newHash) })
		f.drainFTS()
		f.requireSearchable(f.a, oldHash, newHash)
		f.requireSearchable(f.b, oldHash, newHash)
	})
}

// TestRekeyWaitsForCopiesInFlight: a COPY or MOVE that has read the source row under the old
// hash but not committed has rows the rekey cannot see. The rekey must wait for it, or it
// removes the FTS row that the copy, once committed, needs.
func TestRekeyWaitsForCopiesInFlight(t *testing.T) {
	for _, tc := range []struct {
		name string
		op   func(f *rekeyFTSFixture, tx pgx.Tx, uid imap.UID, hash string)
		// The accounts left with live rows of the body, whose rows must be searchable.
		inA, inB bool
	}{
		{"copy within the account", func(f *rekeyFTSFixture, tx pgx.Tx, uid imap.UID, hash string) {
			f.copyTo(tx, uid, f.inboxA, f.archiveA, f.a, hash)
		}, true, false},
		{"copy into another account", func(f *rekeyFTSFixture, tx pgx.Tx, uid imap.UID, hash string) {
			f.copyTo(tx, uid, f.inboxA, f.sharedB, f.b, hash)
		}, true, true},
		{"move into another account", func(f *rekeyFTSFixture, tx pgx.Tx, uid imap.UID, hash string) {
			f.moveTo(tx, uid, f.inboxA, f.sharedB, f.b, hash)
		}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRekeyFTSFixture(t)
			oldHash, newHash := f.hash("old"), f.hash("new")
			uid := f.importBody(f.a, f.inboxA, oldHash)
			f.drainFTS()

			copyTx, err := f.d.GetWritePool().Begin(f.ctx)
			require.NoError(t, err)
			defer copyTx.Rollback(f.ctx)
			tc.op(f, copyTx, uid, oldHash)

			// The rekey runs on its own connection while the copy is uncommitted. It either
			// finishes or waits for a lock; only then does the copy commit.
			conn, err := f.d.GetWritePool().Acquire(f.ctx)
			require.NoError(t, err)
			defer conn.Release()
			var pid int
			require.NoError(t, conn.QueryRow(f.ctx, "SELECT pg_backend_pid()").Scan(&pid))
			done := make(chan error, 1)
			go func() {
				tx, err := conn.Begin(f.ctx)
				if err != nil {
					done <- err
					return
				}
				defer tx.Rollback(f.ctx)
				domain, localpart := f.path(f.a)
				if _, err := f.d.RekeyContentHash(f.ctx, tx, f.a, ContentObject{S3Domain: domain, S3Localpart: localpart, ContentHash: oldHash}, newHash); err != nil {
					done <- err
					return
				}
				done <- tx.Commit(f.ctx)
			}()

			var rekeyErr error
			finished := false
			deadline := time.Now().Add(10 * time.Second)
			for !finished {
				select {
				case rekeyErr = <-done:
					finished = true
				case <-time.After(10 * time.Millisecond):
					var waiting bool
					require.NoError(t, f.d.GetWritePool().QueryRow(f.ctx,
						`SELECT COALESCE(bool_or(wait_event_type = 'Lock'), false) FROM pg_stat_activity WHERE pid = $1`, pid).Scan(&waiting))
					require.False(t, time.Now().After(deadline), "the rekey neither finished nor waited for a lock")
					if waiting {
						require.NoError(t, copyTx.Commit(f.ctx))
						rekeyErr = <-done
						finished = true
					}
				}
			}
			require.NoError(t, rekeyErr)
			_ = copyTx.Commit(f.ctx) // when the rekey did not wait for it

			f.drainFTS()
			if tc.inA {
				f.requireSearchable(f.a, oldHash, newHash)
			}
			if tc.inB {
				f.requireSearchable(f.b, oldHash, newHash)
			}
		})
	}
}
