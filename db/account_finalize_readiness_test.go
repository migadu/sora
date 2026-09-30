package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// finalizeTestMarker returns a deleted_at earlier than any account already in the shared
// test database, so a grace-period window ending just after it selects only the accounts
// the test creates, not whatever soft-deleted accounts other runs left behind.
func finalizeTestMarker(t *testing.T, db *Database) time.Time {
	t.Helper()
	marker := time.Date(1971, 1, 1, 0, 0, 0, 0, time.UTC)
	var earliest *time.Time
	require.NoError(t, db.GetWritePool().QueryRow(context.Background(),
		`SELECT min(deleted_at) FROM accounts`).Scan(&earliest))
	if earliest != nil && earliest.Before(marker) {
		marker = earliest.Add(-24 * time.Hour)
	}
	return marker
}

// softDeletedAccountWithInbox creates an account holding an empty INBOX, as a never-used
// account does, and soft-deletes it with deleted_at pinned to deletedAt. The account is
// removed on cleanup, so db must be closed by a t.Cleanup registered before this call
// (cleanups run last-in first-out; a deferred Close would run first).
func softDeletedAccountWithInbox(t *testing.T, db *Database, deletedAt time.Time) int64 {
	t.Helper()
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	accountID, err := db.CreateAccount(ctx, tx, CreateAccountRequest{
		Email:     fmt.Sprintf("finalize_%d@example.com", time.Now().UnixNano()),
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "INBOX", nil))
	_, err = tx.Exec(ctx, `UPDATE accounts SET deleted_at = $2 WHERE id = $1`, accountID, deletedAt)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	t.Cleanup(func() {
		ctx := context.Background()
		tx, err := db.GetWritePool().Begin(ctx)
		if err != nil {
			t.Errorf("cleanup of account %d: begin: %v", accountID, err)
			return
		}
		defer tx.Rollback(ctx)
		if err := db.HardDeleteAccounts(ctx, tx, []int64{accountID}); err != nil {
			t.Errorf("cleanup of account %d: hard delete: %v", accountID, err)
			return
		}
		if _, err := db.FinalizeAccountDeletions(ctx, tx, []int64{accountID}); err != nil {
			t.Errorf("cleanup of account %d: finalize: %v", accountID, err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			t.Errorf("cleanup of account %d: commit: %v", accountID, err)
		}
	})
	return accountID
}

func hardDeleteAccount(t *testing.T, db *Database, accountID int64) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	require.NoError(t, db.HardDeleteAccounts(ctx, tx, []int64{accountID}))
	require.NoError(t, tx.Commit(ctx))
}

// A soft-deleted account with no messages but still holding mailboxes has not been
// through HardDeleteAccounts yet, and mailboxes.account_id has no ON DELETE action, so
// deleting its accounts row fails with SQLSTATE 23503. It must not be a finalization
// candidate, and if one reaches FinalizeAccountDeletions anyway it must be skipped
// rather than fail the whole batch: otherwise one never-used account blocks every other
// account in the batch from being finalized, cycle after cycle.
func TestAccountFinalizeSkipsAccountsStillHoldingMailboxes(t *testing.T) {
	if testing.Short() {
		t.Skip("database integration test")
	}
	db := setupTestDatabase(t)
	t.Cleanup(db.Close)
	ctx := context.Background()

	marker := finalizeTestMarker(t, db)
	pending := softDeletedAccountWithInbox(t, db, marker)
	ready := softDeletedAccountWithInbox(t, db, marker)
	hardDeleteAccount(t, db, ready)

	ids, err := db.GetDanglingAccountsForFinalDeletion(ctx, 100000, marker.Add(time.Minute))
	require.NoError(t, err)
	require.Contains(t, ids, ready, "a hard-deleted account with no messages is ready for finalization")
	require.NotContains(t, ids, pending, "an account still holding mailboxes has not been hard-deleted yet")

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	n, err := db.FinalizeAccountDeletions(ctx, tx, []int64{pending, ready})
	require.NoError(t, err, "an account that is not ready must not fail the batch")
	require.NoError(t, tx.Commit(ctx))
	require.Equal(t, int64(1), n)

	var readyExists, pendingExists bool
	require.NoError(t, db.GetWritePool().QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM accounts WHERE id = $1), EXISTS(SELECT 1 FROM accounts WHERE id = $2)`,
		ready, pending).Scan(&readyExists, &pendingExists))
	require.False(t, readyExists, "the ready account is finalized")
	require.True(t, pendingExists, "the account still holding mailboxes is left for HardDeleteAccounts")
}

// The hard-delete listing takes the 50 oldest soft-deleted accounts past the grace
// period. An account already hard-deleted stays soft-deleted until its expunged messages
// are reaped (another grace period) and it is finalized, so if it were listed again it
// would hold a slot: 50 such accounts would starve every newer one, including never-used
// accounts that then sit with their mailboxes past the grace period indefinitely.
func TestListSoftDeletedAccountsForHardDeleteSkipsAlreadyHardDeleted(t *testing.T) {
	if testing.Short() {
		t.Skip("database integration test")
	}
	db := setupTestDatabase(t)
	t.Cleanup(db.Close)
	ctx := context.Background()

	marker := finalizeTestMarker(t, db)
	done := softDeletedAccountWithInbox(t, db, marker)
	pending := softDeletedAccountWithInbox(t, db, marker.Add(time.Second))
	hardDeleteAccount(t, db, done)

	ids, err := db.ListSoftDeletedAccountsForHardDelete(ctx, time.Since(marker.Add(time.Minute)), 100000)
	require.NoError(t, err)
	require.Contains(t, ids, pending, "an account still holding mailboxes needs hard-deleting")
	require.NotContains(t, ids, done, "a hard-deleted account is not listed again")
}

// A large account is hard-deleted in bounded steps that each commit, so it drains within
// the write deadline however big it is, and progress survives an interrupted cycle. Every
// statement is bounded, the mailbox row removal included (its cascades used to rewrite
// every message row of the mailbox in one go). The step must also stop cold if the
// account was restored since it was listed.
func TestHardDeleteAccountStepIsBoundedAndHonoursRestore(t *testing.T) {
	if testing.Short() {
		t.Skip("database integration test")
	}
	db, accountID, mailboxID := setupMessageTestDatabase(t)
	t.Cleanup(db.Close)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		insertTestMessage(t, db, accountID, mailboxID, "INBOX", fmt.Sprintf("Message %d", i), fmt.Sprintf("<step-%d-%d@example.com>", accountID, i))
	}
	counts := func() (live, attached, mailboxes int) {
		require.NoError(t, db.GetWritePool().QueryRow(ctx, `
			SELECT (SELECT count(*) FROM messages WHERE account_id = $1 AND expunged_at IS NULL),
			       (SELECT count(*) FROM messages WHERE account_id = $1 AND mailbox_id IS NOT NULL),
			       (SELECT count(*) FROM mailboxes WHERE account_id = $1)`, accountID).Scan(&live, &attached, &mailboxes))
		return
	}
	step := func(limit int) bool {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		done, err := db.HardDeleteAccountStep(ctx, tx, accountID, limit)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return done
	}

	// Not soft-deleted: the step refuses to touch anything and reports done.
	require.True(t, step(2))
	live, _, mailboxes := counts()
	require.Equal(t, 5, live, "a live account is never hard-deleted")
	require.Equal(t, 1, mailboxes)

	_, err := db.GetWritePool().Exec(ctx, `UPDATE accounts SET deleted_at = now() WHERE id = $1`, accountID)
	require.NoError(t, err)

	// Soft-deleted: a step expunges at most limit messages and commits.
	require.False(t, step(2))
	live, _, mailboxes = counts()
	require.Equal(t, 3, live, "a step expunges at most limit messages")
	require.Equal(t, 1, mailboxes, "the mailbox stays until every message is expunged and detached")

	// Restored between steps: the next step stops with what is left intact.
	_, err = db.GetWritePool().Exec(ctx, `UPDATE accounts SET deleted_at = NULL WHERE id = $1`, accountID)
	require.NoError(t, err)
	require.True(t, step(2))
	live, _, mailboxes = counts()
	require.Equal(t, 3, live, "a restored account keeps its remaining messages")
	require.Equal(t, 1, mailboxes)

	// Soft-deleted again: bounded steps drain it. Each one changes at most limit rows of
	// one kind (expunge, detach state, detach messages) or removes the emptied mailbox.
	_, err = db.GetWritePool().Exec(ctx, `UPDATE accounts SET deleted_at = now() WHERE id = $1`, accountID)
	require.NoError(t, err)
	prevLive, prevAttached, _ := counts()
	steps := 0
	for !step(2) {
		steps++
		require.Less(t, steps, 20, "the hard delete must terminate")
		live, attached, _ := counts()
		require.LessOrEqual(t, prevLive-live, 2, "a step expunges at most limit messages")
		require.LessOrEqual(t, prevAttached-attached, 2, "a step detaches at most limit messages")
		prevLive, prevAttached = live, attached
	}
	require.GreaterOrEqual(t, steps, 4, "5 messages at limit 2 cannot drain in fewer steps")
	live, attached, mailboxes := counts()
	require.Equal(t, 0, live)
	require.Equal(t, 0, attached, "every tombstone is detached before the mailbox row goes")
	require.Equal(t, 0, mailboxes)
	require.True(t, step(2), "an account with nothing left is done")
}

// The FTS drain that precedes finalization works from the read-pool candidate list, which
// may be stale: the account may have been restored since, or a lagging replica may have
// misreported it. Its rows are the only copy of the account's search data, so the drain
// must re-check on the primary and leave the rows of an account that is not going away.
func TestFTSDrainKeepsRowsOfAccountNotFinalizable(t *testing.T) {
	if testing.Short() {
		t.Skip("database integration test")
	}
	db := setupTestDatabase(t)
	t.Cleanup(db.Close)
	ctx := context.Background()

	accountID := softDeletedAccountWithInbox(t, db, finalizeTestMarker(t, db))
	_, err := db.GetWritePool().Exec(ctx, `
		INSERT INTO messages_fts_v2 (content_hash, account_id, text_body_tsv)
		VALUES ('finalize-drain-guard', $1, to_tsvector('simple', 'kept'))`, accountID)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.GetWritePool().Exec(context.Background(), `DELETE FROM messages_fts_v2 WHERE account_id = $1`, accountID)
	})

	drain := func() int64 {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		n, err := db.DeleteFTSRowsForAccount(ctx, tx, accountID, 100)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return n
	}
	// The shared test database has no FK from messages_fts_v2 to accounts, so an account
	// id may carry stale rows from earlier runs; only this test's row is looked at.
	rowKept := func() bool {
		var kept bool
		require.NoError(t, db.GetWritePool().QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM messages_fts_v2 WHERE account_id = $1 AND content_hash = 'finalize-drain-guard')`,
			accountID).Scan(&kept))
		return kept
	}

	// Still holding a mailbox: not finalizable, so the drain must not touch the rows.
	require.Equal(t, int64(0), drain(), "the drain reports nothing to do for an account that is not finalizable")
	require.True(t, rowKept(), "the search data of an account that is not going away is kept")

	// Restored: the same, whatever else it holds.
	_, err = db.GetWritePool().Exec(ctx, `UPDATE accounts SET deleted_at = NULL WHERE id = $1`, accountID)
	require.NoError(t, err)
	require.Equal(t, int64(0), drain())
	require.True(t, rowKept(), "a restored account keeps its search data")

	// Soft-deleted again and hard-deleted: finalizable, so the drain proceeds.
	_, err = db.GetWritePool().Exec(ctx, `UPDATE accounts SET deleted_at = now() WHERE id = $1`, accountID)
	require.NoError(t, err)
	hardDeleteAccount(t, db, accountID)
	require.GreaterOrEqual(t, drain(), int64(1))
	require.False(t, rowKept())
}
