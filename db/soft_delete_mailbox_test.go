package db

import (
	"context"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSoftDeleteMailbox_HidesThenPurges covers the two-phase mailbox deletion that
// the IMAP DELETE path uses:
//  1. SoftDeleteMailbox stamps deleted_at — the mailbox vanishes from every read path
//     immediately, BUT its messages are left intact (not yet expunged).
//  2. The name is freed immediately, so a same-name CREATE succeeds while the tombstone
//     still exists (partial unique index on deleted_at IS NULL).
//  3. PurgeSoftDeletedMailboxes (the background sweep) later runs the real hard delete,
//     expunging the messages and removing the tombstone row.
func TestSoftDeleteMailbox_HidesThenPurges(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, testEmail, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Create a mailbox with messages.
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	err = db.CreateMailbox(ctx, tx, accountID, "SoftDel", nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	mailbox, err := db.GetMailboxByName(ctx, accountID, "SoftDel")
	require.NoError(t, err)

	msgID1 := insertTestMessage(t, db, accountID, mailbox.ID, "SoftDel", "M1", "<m1@example.com>")
	msgID2 := insertTestMessage(t, db, accountID, mailbox.ID, "SoftDel", "M2", "<m2@example.com>")

	// Baseline account quota (live count): includes our 2 messages.
	before, err := db.GetAccountDetails(ctx, testEmail)
	require.NoError(t, err)

	// --- Phase 1: soft delete ---
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.SoftDeleteMailbox(ctx, tx, mailbox.ID, accountID))
	require.NoError(t, tx.Commit(ctx))

	// Invisible to lookup by name...
	_, err = db.GetMailboxByName(ctx, accountID, "SoftDel")
	assert.ErrorIs(t, err, consts.ErrMailboxNotFound, "soft-deleted mailbox must not be resolvable by name")

	// ...and to listing.
	mboxes, err := db.GetMailboxes(ctx, accountID, false)
	require.NoError(t, err)
	for _, m := range mboxes {
		assert.NotEqual(t, mailbox.ID, m.ID, "soft-deleted mailbox must not appear in LIST")
	}

	// But the messages are still present and NOT yet expunged (deferred to the sweep).
	var activeCount int
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL",
		mailbox.ID).Scan(&activeCount)
	require.NoError(t, err)
	assert.Equal(t, 2, activeCount, "messages must survive the soft-delete window")

	// Quota is exact IMMEDIATELY (Phase 5): even though the messages aren't expunged yet,
	// the account's live count/size excludes messages in a soft-deleted mailbox.
	after, err := db.GetAccountDetails(ctx, testEmail)
	require.NoError(t, err)
	assert.Equal(t, before.MessageCount-2, after.MessageCount,
		"account message_count must drop by the soft-deleted mailbox's messages immediately")
	assert.Less(t, after.StorageUsed, before.StorageUsed,
		"account storage_used must drop immediately on soft-delete, not after the sweep")
	assert.Equal(t, before.MailboxCount-1, after.MailboxCount,
		"account mailbox_count must exclude the soft-deleted mailbox immediately")

	// --- Phase 2: name reuse works immediately ---
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	err = db.CreateMailbox(ctx, tx, accountID, "SoftDel", nil)
	require.NoError(t, err, "re-creating the name while a tombstone exists must succeed")
	require.NoError(t, tx.Commit(ctx))

	recreated, err := db.GetMailboxByName(ctx, accountID, "SoftDel")
	require.NoError(t, err)
	assert.NotEqual(t, mailbox.ID, recreated.ID, "recreated mailbox must be a fresh row, not the tombstone")

	// --- Phase 3: background sweep hard-deletes the tombstone ---
	drainPurgeUntilGone(t, db, ctx, mailbox.ID)

	// Messages are now expunged with mailbox_path preserved (restorable), same end state
	// as the old synchronous DELETE.
	var expungedCount int
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE id IN ($1, $2) AND expunged_at IS NOT NULL AND mailbox_path = 'SoftDel'",
		msgID1, msgID2).Scan(&expungedCount)
	require.NoError(t, err)
	assert.Equal(t, 2, expungedCount, "sweep should expunge the tombstone's messages with mailbox_path preserved")

	// The recreated live mailbox is untouched by the sweep.
	_, err = db.GetMailboxByName(ctx, accountID, "SoftDel")
	require.NoError(t, err, "recreated mailbox must survive the sweep of the tombstone")
}

// drainPurgeUntilGone repeatedly runs the background sweep until the given mailbox's
// tombstone row is hard-deleted. The sweep is batch-bounded (LIMIT 50, oldest first)
// and the shared test DB accumulates tombstones from other tests (the cleaner doesn't
// run in tests), so a single call may not reach our row — mirroring how the worker
// clears a backlog over successive ticks.
func drainPurgeUntilGone(t *testing.T, db *Database, ctx context.Context, mailboxID int64) {
	t.Helper()
	rowCount := 1
	for i := 0; i < 200 && rowCount > 0; i++ {
		// Mirror the production sweep: list tombstones (fast read), then hard-delete each
		// in its OWN transaction (never batch many under one deadline).
		mboxes, err := db.ListSoftDeletedMailboxes(ctx, 0, 50)
		require.NoError(t, err)
		for _, m := range mboxes {
			tx, err := db.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			if err := db.DeleteMailbox(ctx, tx, m.ID, m.AccountID); err != nil {
				_ = tx.Rollback(ctx)
				require.ErrorIs(t, err, consts.ErrMailboxNotFound, "unexpected purge error")
				continue
			}
			require.NoError(t, tx.Commit(ctx))
		}
		require.NoError(t, db.GetReadPool().QueryRow(ctx,
			"SELECT COUNT(*) FROM mailboxes WHERE id = $1", mailboxID).Scan(&rowCount))
	}
	require.Equal(t, 0, rowCount, "tombstone mailbox row should be purged by the sweep")
}

// TestSoftDeleteMailbox_MessagesRestorableOnlyAfterSweep answers the key semantic
// question: a soft-deleted mailbox is NOT an "undelete" feature. Its messages are
// hidden but NOT yet in the restorable (deleted-messages) set during the window —
// they only become restorable AFTER the background sweep expunges them (preserving
// mailbox_path), at which point the existing message-restore flow works exactly as it
// did before two-phase deletion.
func TestSoftDeleteMailbox_MessagesRestorableOnlyAfterSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, testEmail, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "Reborn", nil))
	require.NoError(t, tx.Commit(ctx))

	mbox, err := db.GetMailboxByName(ctx, accountID, "Reborn")
	require.NoError(t, err)
	insertTestMessage(t, db, accountID, mbox.ID, "Reborn", "R1", "<r1@example.com>")
	insertTestMessage(t, db, accountID, mbox.ID, "Reborn", "R2", "<r2@example.com>")

	// Soft delete the mailbox.
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.SoftDeleteMailbox(ctx, tx, mbox.ID, accountID))
	require.NoError(t, tx.Commit(ctx))

	mp := "Reborn"

	// During the window: the messages are NOT yet restorable — they aren't expunged, so
	// they don't appear in the deleted-messages listing the admin restore tooling uses.
	listed, err := db.ListDeletedMessages(ctx, ListDeletedMessagesParams{Email: testEmail, MailboxPath: &mp, Limit: 100})
	require.NoError(t, err)
	assert.Empty(t, listed, "during the soft-delete window the folder's messages must NOT be in the restorable set")

	// Run the background sweep.
	drainPurgeUntilGone(t, db, ctx, mbox.ID)

	// After the sweep: the messages are expunged with mailbox_path preserved → restorable,
	// exactly like the pre-change synchronous DELETE.
	listed, err = db.ListDeletedMessages(ctx, ListDeletedMessagesParams{Email: testEmail, MailboxPath: &mp, Limit: 100})
	require.NoError(t, err)
	assert.Len(t, listed, 2, "after the sweep the folder's messages enter the restorable set")

	// Restore them: the existing message-restore flow recreates the mailbox and revives the messages.
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	restored, err := db.RestoreMessages(ctx, tx, RestoreMessagesParams{Email: testEmail, MailboxPath: &mp})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	assert.Equal(t, int64(2), restored, "both messages should be restored")

	rebox, err := db.GetMailboxByName(ctx, accountID, "Reborn")
	require.NoError(t, err, "restore recreates the mailbox by its preserved path")
	var live int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL", rebox.ID).Scan(&live))
	assert.Equal(t, 2, live, "restored messages are live again in the recreated mailbox")
}

// TestSoftDeleteMailbox_CaseInsensitiveNameReuse verifies the partial unique index is
// case-insensitive (LOWER(name)): deleting "Folder" frees the name for an immediate
// re-CREATE under a different case ("folder").
func TestSoftDeleteMailbox_CaseInsensitiveNameReuse(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "Folder", nil))
	require.NoError(t, tx.Commit(ctx))

	orig, err := db.GetMailboxByName(ctx, accountID, "Folder")
	require.NoError(t, err)

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.SoftDeleteMailbox(ctx, tx, orig.ID, accountID))
	require.NoError(t, tx.Commit(ctx))

	// Re-create under a different case while the tombstone exists.
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "folder", nil),
		"case-variant re-create must succeed (partial unique index on LOWER(name))")
	require.NoError(t, tx.Commit(ctx))

	got, err := db.GetMailboxByName(ctx, accountID, "folder")
	require.NoError(t, err)
	assert.NotEqual(t, orig.ID, got.ID, "case-variant lookup must resolve to the fresh row, not the tombstone")
}

// TestSoftDeleteMailbox_ChildExistenceIgnoresTombstone verifies that a parent whose
// only child has been soft-deleted is treated as a LEAF again (HasChildren=false), so
// it can itself be deleted/renamed. Tombstone children must not block the parent.
func TestSoftDeleteMailbox_ChildExistenceIgnoresTombstone(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	// Create parent "P" and a child "P/C" under it.
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "P", nil))
	require.NoError(t, tx.Commit(ctx))

	parent, err := db.GetMailboxByName(ctx, accountID, "P")
	require.NoError(t, err)

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "P/C", &parent.ID))
	require.NoError(t, tx.Commit(ctx))

	child, err := db.GetMailboxByName(ctx, accountID, "P/C")
	require.NoError(t, err)

	// Parent currently has a child.
	parent, err = db.GetMailbox(ctx, parent.ID, accountID)
	require.NoError(t, err)
	require.True(t, parent.HasChildren, "parent should report HasChildren while a live child exists")

	// Soft-delete the child.
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.SoftDeleteMailbox(ctx, tx, child.ID, accountID))
	require.NoError(t, tx.Commit(ctx))

	// Parent is a leaf again: the tombstone child must not count.
	parent, err = db.GetMailbox(ctx, parent.ID, accountID)
	require.NoError(t, err)
	assert.False(t, parent.HasChildren, "a soft-deleted child must not make the parent look non-empty")
}

// TestSoftDeleteMailbox_DownMigrationDoesNotOrphanMessages guards the down migration's
// data-preservation logic. messages.mailbox_id is ON DELETE SET NULL, so dropping
// tombstone rows directly would leave their messages active-but-orphaned (mailbox_id
// NULL, expunged_at NULL) — never expunged, never cleaned, permanently inflating quota.
// The down migration expunges them first. This runs that same UPDATE-then-DELETE (scoped
// to the test account for isolation) and asserts no orphans result.
func TestSoftDeleteMailbox_DownMigrationDoesNotOrphanMessages(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "Legacy", nil))
	require.NoError(t, tx.Commit(ctx))

	mbox, err := db.GetMailboxByName(ctx, accountID, "Legacy")
	require.NoError(t, err)
	m1 := insertTestMessage(t, db, accountID, mbox.ID, "Legacy", "L1", "<l1@example.com>")
	m2 := insertTestMessage(t, db, accountID, mbox.ID, "Legacy", "L2", "<l2@example.com>")

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.SoftDeleteMailbox(ctx, tx, mbox.ID, accountID))
	require.NoError(t, tx.Commit(ctx))

	// Replicate the down migration (000042 .down.sql), scoped to this account for isolation.
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		UPDATE messages m
		SET mailbox_path = mb.name, expunged_at = now(), expunged_modseq = nextval('messages_modseq')
		FROM mailboxes mb
		WHERE m.mailbox_id = mb.id AND mb.deleted_at IS NOT NULL AND m.expunged_at IS NULL
		  AND mb.account_id = $1
	`, accountID)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `DELETE FROM mailboxes WHERE deleted_at IS NOT NULL AND account_id = $1`, accountID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	// No active orphans for this account.
	var orphans int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE account_id = $1 AND mailbox_id IS NULL AND expunged_at IS NULL",
		accountID).Scan(&orphans))
	assert.Equal(t, 0, orphans, "down migration must not leave active orphaned messages (quota leak)")

	// Our two messages are expunged with mailbox_path preserved (restorable).
	var preserved int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE id IN ($1, $2) AND expunged_at IS NOT NULL AND mailbox_path = 'Legacy'",
		m1, m2).Scan(&preserved))
	assert.Equal(t, 2, preserved, "down migration must expunge tombstone messages with mailbox_path preserved")
}
