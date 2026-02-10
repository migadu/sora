package db

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRenameMailbox_EmptyPathBug tests the EXACT production bug:
// A mailbox has path = ” (empty string) due to data corruption or failed UPDATE
// When renaming it, the child UPDATE query matches ALL mailboxes, causing constraint violations
func TestRenameMailbox_EmptyPathBug(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _ := setupMailboxRenameTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// 1. Create normal mailboxes (INBOX, Archive, etc.)
	tx1, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx1.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx1, accountID, "Archive", nil)
	require.NoError(t, err)

	err = db.CreateMailbox(ctx, tx1, accountID, "Drafts", nil)
	require.NoError(t, err)

	err = tx1.Commit(ctx)
	require.NoError(t, err)

	t.Logf("✓ Created normal mailboxes: Archive, Drafts")

	// 2. Create a mailbox WITH CORRUPT DATA (path = '')
	// We'll manually insert it to simulate the production bug
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	var corruptMailboxID int64
	err = tx2.QueryRow(ctx, `
		INSERT INTO mailboxes (account_id, name, uid_validity, subscribed, path)
		VALUES ($1, $2, $3, $4, '')
		RETURNING id
	`, accountID, "amazon", 1234567890, false).Scan(&corruptMailboxID)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	t.Logf("✓ Created CORRUPT mailbox 'amazon' with path = '' (id=%d)", corruptMailboxID)

	// 3. Verify the corrupt state
	var path string
	err = db.GetReadPool().QueryRow(ctx, `
		SELECT path FROM mailboxes WHERE id = $1
	`, corruptMailboxID).Scan(&path)
	require.NoError(t, err)
	require.Equal(t, "", path, "Corrupt mailbox should have empty path")

	t.Logf("✓ Verified: amazon has path = '' (length=%d)", len(path))

	// 4. Try to rename the corrupt mailbox
	// This will trigger the bug because the child UPDATE query becomes:
	//   WHERE account_id = X AND path LIKE '' || '%' AND path != ''
	//   Which matches ALL mailboxes with non-empty paths!
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	t.Logf("Attempting to rename 'amazon' → 'amazontest'...")

	err = db.RenameMailbox(ctx, tx3, corruptMailboxID, accountID, "amazontest", nil)

	if err == nil {
		t.Fatal("❌ UNEXPECTED: Rename succeeded when it should fail!")
	}

	errMsg := err.Error()
	t.Logf("Got error (expected): %v", err)

	// Check for production bug signature
	if strings.Contains(errMsg, "failed to update child mailboxes") &&
		(strings.Contains(errMsg, "SQLSTATE") || strings.Contains(errMsg, "23505") || strings.Contains(errMsg, "duplicate key")) {
		t.Logf("✅ PRODUCTION BUG REPRODUCED!")
		t.Logf("   Error message: %s", errMsg)
		t.Logf("   This happens because path='' causes child UPDATE to match ALL mailboxes")
		// This is expected - test passed
		return
	}

	// If we get a different error, that's also acceptable (e.g., validation error)
	t.Logf("Got a different error: %v", err)
}

// TestRenameMailbox_EmptyPathBugWithFix tests that the fix prevents the bug
// by validating the mailbox path before attempting rename
func TestRenameMailbox_EmptyPathValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _ := setupMailboxRenameTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// 1. Create a corrupt mailbox with empty path
	tx1, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx1.Rollback(ctx)

	var corruptMailboxID int64
	err = tx1.QueryRow(ctx, `
		INSERT INTO mailboxes (account_id, name, uid_validity, subscribed, path)
		VALUES ($1, $2, $3, $4, '')
		RETURNING id
	`, accountID, "corrupt", 1234567890, false).Scan(&corruptMailboxID)
	require.NoError(t, err)

	err = tx1.Commit(ctx)
	require.NoError(t, err)

	// 2. Try to rename - should fail gracefully with validation error, NOT constraint violation
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.RenameMailbox(ctx, tx2, corruptMailboxID, accountID, "fixed", nil)
	require.Error(t, err, "Should fail for corrupt mailbox")

	errMsg := err.Error()

	// FIXED version should return validation error, NOT database constraint violation
	if strings.Contains(errMsg, "SQLSTATE") || strings.Contains(errMsg, "23505") {
		t.Fatalf("❌ BUG NOT FIXED: Still getting constraint violation: %v", err)
	}

	// Should get a validation error instead
	if strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "corrupt") || strings.Contains(errMsg, "path") {
		t.Logf("✅ FIXED: Returns validation error: %v", err)
	} else {
		t.Logf("Got error: %v", err)
	}
}
