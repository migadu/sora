package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHardDeleteAccounts_WithActiveMessages is a regression test for the FK-violation bug
// where deleting a mailbox row that still references ACTIVE (non-expunged) messages aborts
// the transaction with "mailbox_stats_mailbox_id_fkey".
//
// Root cause: messages.mailbox_id is ON DELETE SET NULL, and maintain_mailbox_stats_messages
// (migration 000037) UPSERTs a mailbox_stats row for any active message detached by that
// SET NULL. If the mailbox row is deleted first, the UPSERT's INSERT path references a
// now-missing mailbox and violates the FK. HardDeleteAccounts previously deleted mailboxes
// BEFORE expunging messages; DeleteAccount only soft-deletes (no expunge), so by the time the
// grace-period worker runs the messages are still active and the purge aborted — silently
// stalling the soft-deleted-account cleanup pipeline forever.
//
// The fix expunges messages before deleting mailboxes (mirroring db.DeleteMailbox).
func TestHardDeleteAccounts_WithActiveMessages(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _, inboxID, sentID := setupRestoreTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Insert ACTIVE (non-expunged) messages — this is the precondition that triggered the bug.
	insertTestMessage(t, db, accountID, inboxID, "INBOX", "Message 1", "<m1@example.com>")
	insertTestMessage(t, db, accountID, inboxID, "INBOX", "Message 2", "<m2@example.com>")
	insertTestMessage(t, db, accountID, sentID, "Sent", "Message 3", "<m3@example.com>")

	var active int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE account_id = $1 AND expunged_at IS NULL", accountID).Scan(&active))
	require.Equal(t, 3, active, "messages should be active before hard delete")

	// Before the fix this aborts with the mailbox_stats FK violation.
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	require.NoError(t, db.HardDeleteAccounts(ctx, tx, []int64{accountID}),
		"HardDeleteAccounts must expunge messages before deleting mailboxes (no FK violation)")

	require.NoError(t, tx.Commit(ctx))

	assertAccountFullyDetached(t, db, ctx, accountID)
}

// TestPurgeMailboxesForAccount_WithActiveMessages guards the hard-delete helper used by the
// admin domain-purge path. Its normal caller expunges first, but the helper must be self-safe
// against a bare DELETE FROM mailboxes when active messages are present.
func TestPurgeMailboxesForAccount_WithActiveMessages(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _, inboxID, _ := setupRestoreTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	insertTestMessage(t, db, accountID, inboxID, "INBOX", "Message 1", "<p1@example.com>")
	insertTestMessage(t, db, accountID, inboxID, "INBOX", "Message 2", "<p2@example.com>")

	require.NoError(t, db.PurgeMailboxesForAccount(ctx, accountID),
		"PurgeMailboxesForAccount must expunge active messages before deleting mailboxes (no FK violation)")

	assertAccountFullyDetached(t, db, ctx, accountID)
}

// assertAccountFullyDetached verifies the post-conditions shared by both hard-delete paths:
// all mailboxes removed, all messages expunged and detached (kept for the later S3 cleanup
// phase), and mailbox_stats rows gone via cascade.
func assertAccountFullyDetached(t *testing.T, db *Database, ctx context.Context, accountID int64) {
	t.Helper()

	var mboxCount int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM mailboxes WHERE account_id = $1", accountID).Scan(&mboxCount))
	assert.Equal(t, 0, mboxCount, "all mailboxes should be deleted")

	var notExpunged int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE account_id = $1 AND expunged_at IS NULL", accountID).Scan(&notExpunged))
	assert.Equal(t, 0, notExpunged, "all messages should be marked expunged")

	var stillAttached int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE account_id = $1 AND mailbox_id IS NOT NULL", accountID).Scan(&stillAttached))
	assert.Equal(t, 0, stillAttached, "all messages should be detached from deleted mailboxes")
}
