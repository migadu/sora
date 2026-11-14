package db

import (
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// The tests below retire the FTS rows of account A, the account a body was first delivered
// to, while a copy of the body in account B still waits for the FTS worker. B's row was
// written without text or vector (restageFTS for a COPY into another account, stageFTS for a
// body another account has indexed), so A's row is the only data it can be filled from.
// Each test uses newRekeyFTSFixture: A owns inboxA, B owns sharedB.

// purgeAccountMessages takes accountID out of service and removes its mailboxes and message
// rows, as the purge's hard delete and S3 phase do, leaving its FTS rows: the account is
// then finalizable, and only its search data remains.
func (f *rekeyFTSFixture) purgeAccountMessages(accountID int64) {
	f.t.Helper()
	f.inTx(func(tx pgx.Tx) {
		_, err := tx.Exec(f.ctx, `UPDATE accounts SET deleted_at = now() WHERE id = $1`, accountID)
		require.NoError(f.t, err)
		require.NoError(f.t, f.d.HardDeleteAccounts(f.ctx, tx, []int64{accountID}))
		_, err = tx.Exec(f.ctx, `DELETE FROM messages WHERE account_id = $1`, accountID)
		require.NoError(f.t, err)
	})
}

// drainAccountFTS runs DeleteFTSRowsForAccount until it reports nothing left, as the
// purge and the cleaner do before they finalize an account, and returns the rows deleted.
func (f *rekeyFTSFixture) drainAccountFTS(accountID int64) int64 {
	f.t.Helper()
	var total int64
	for range 100 {
		var n int64
		f.inTx(func(tx pgx.Tx) {
			var err error
			n, err = f.d.DeleteFTSRowsForAccount(f.ctx, tx, accountID, 100)
			require.NoError(f.t, err)
		})
		if n == 0 {
			return total
		}
		total += n
	}
	f.t.Fatal("the FTS drain did not finish")
	return total
}

func (f *rekeyFTSFixture) finalize(accountID int64) int64 {
	f.t.Helper()
	var n int64
	f.inTx(func(tx pgx.Tx) {
		var err error
		n, err = f.d.FinalizeAccountDeletions(f.ctx, tx, []int64{accountID})
		require.NoError(f.t, err)
	})
	return n
}

func (f *rekeyFTSFixture) ftsRowExists(hash string, accountID int64) bool {
	f.t.Helper()
	var exists bool
	require.NoError(f.t, f.d.GetWritePool().QueryRow(f.ctx,
		`SELECT EXISTS (SELECT 1 FROM messages_fts_v2 WHERE content_hash = $1 AND account_id = $2)`,
		hash, accountID).Scan(&exists))
	return exists
}

// TestAccountFTSDrainKeepsCopiesSearchable: the purge of the account a body was copied from,
// run before the FTS worker has filled the copy's row, must leave the copy searchable by
// body (#909).
func TestAccountFTSDrainKeepsCopiesSearchable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		indexed bool // the worker indexed the source before the copy
	}{
		{"body indexed", true},
		{"text still pending", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRekeyFTSFixture(t)
			hash := f.hash("body")
			uid := f.importBody(f.a, f.inboxA, hash)
			if tc.indexed {
				f.drainFTS()
			}
			f.inTx(func(tx pgx.Tx) { f.copyTo(tx, uid, f.inboxA, f.sharedB, f.b, hash) })

			f.purgeAccountMessages(f.a)
			require.EqualValues(t, 1, f.drainAccountFTS(f.a), "the drain deletes the purged account's row")
			require.False(t, f.ftsRowExists(hash, f.a))
			require.EqualValues(t, 1, f.finalize(f.a), "the drained account is finalized")

			f.drainFTS()
			f.requireSearchable(f.b, hash)
		})
	}
}

// TestFinalizeKeepsFTSRowsTheDrainLeft: the finalize deleted every FTS row of the account
// in one statement, whatever other rows needed them. An account whose rows the drain did
// not remove (it failed, or skipped a body being staged) must wait for the next drain.
func TestFinalizeKeepsFTSRowsTheDrainLeft(t *testing.T) {
	f := newRekeyFTSFixture(t)
	hash := f.hash("body")
	uid := f.importBody(f.a, f.inboxA, hash)
	f.drainFTS()
	f.inTx(func(tx pgx.Tx) { f.copyTo(tx, uid, f.inboxA, f.sharedB, f.b, hash) })

	f.purgeAccountMessages(f.a)
	finalized := f.finalize(f.a)
	f.drainFTS()
	f.requireSearchable(f.b, hash)
	require.Zero(t, finalized, "an account with FTS rows left is not finalized")
	require.True(t, f.ftsRowExists(hash, f.a))

	require.EqualValues(t, 1, f.drainAccountFTS(f.a))
	require.EqualValues(t, 1, f.finalize(f.a), "once drained, the account is finalized")
	f.requireSearchable(f.b, hash)
}

// TestAccountFTSDrainWaitsForStagingInFlight: a delivery of the body to B that read A's
// vector, and so staged its row without text, has not committed when A's rows are drained.
// The drain cannot see that row, so it must leave A's row until the delivery has committed.
func TestAccountFTSDrainWaitsForStagingInFlight(t *testing.T) {
	f := newRekeyFTSFixture(t)
	hash := f.hash("body")
	f.importBody(f.a, f.inboxA, hash)
	f.drainFTS()
	f.purgeAccountMessages(f.a)

	delivery, err := f.d.GetWritePool().Begin(f.ctx)
	require.NoError(t, err)
	defer delivery.Rollback(f.ctx)
	domain, localpart := f.path(f.b)
	_, _, err = f.d.InsertMessageFromImporter(f.ctx, delivery, &InsertMessageOptions{
		AccountID:     f.b,
		MailboxID:     f.sharedB,
		MailboxName:   "Shared",
		S3Domain:      domain,
		S3Localpart:   localpart,
		ContentHash:   hash,
		MessageID:     fmt.Sprintf("<%s@example.com>", hash[:16]),
		InternalDate:  time.Now(),
		Size:          100,
		Subject:       "Delivered",
		PlaintextBody: "the " + rekeyFTSWord + " body",
		SentDate:      time.Now(),
	})
	require.NoError(t, err)
	var staged bool
	require.NoError(t, delivery.QueryRow(f.ctx, `SELECT text_body IS NULL AND text_body_tsv IS NULL
		FROM messages_fts_v2 WHERE content_hash = $1 AND account_id = $2`, hash, f.b).Scan(&staged))
	require.True(t, staged, "precondition: the delivery staged its row without text, relying on A's vector")

	f.drainAccountFTS(f.a) // must not block on the delivery
	require.NoError(t, delivery.Commit(f.ctx))
	f.drainAccountFTS(f.a)
	require.False(t, f.ftsRowExists(hash, f.a), "the drain removes A's row once the delivery has committed")

	f.drainFTS()
	f.requireSearchable(f.b, hash)
}

// TestOrphanSweepKeepsCopiesSearchable: once A's last message with the body is deleted, A's
// FTS row is an orphan, and the cleaner's sweep (on any node, during a purge too) deletes it.
// A copy in B still waiting for the worker must stay searchable.
func TestOrphanSweepKeepsCopiesSearchable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		indexed bool
	}{
		{"body indexed", true},
		{"text still pending", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRekeyFTSFixture(t)
			hash := f.hash("body")
			uid := f.importBody(f.a, f.inboxA, hash)
			if tc.indexed {
				f.drainFTS()
			}
			f.inTx(func(tx pgx.Tx) { f.copyTo(tx, uid, f.inboxA, f.sharedB, f.b, hash) })

			_, err := f.d.GetWritePool().Exec(f.ctx, `DELETE FROM messages WHERE account_id = $1 AND content_hash = $2`, f.a, hash)
			require.NoError(t, err)
			f.inTx(func(tx pgx.Tx) {
				n, err := f.d.DeleteMessagesFTSByKeyBatch(f.ctx, tx, []FTSKey{{ContentHash: hash, AccountID: f.a}})
				require.NoError(t, err)
				require.EqualValues(t, 1, n, "the sweep deletes the orphan")
			})

			f.drainFTS()
			f.requireSearchable(f.b, hash)
		})
	}
}
