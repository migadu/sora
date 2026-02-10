package db

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRenameMailbox_RenameToExistingEmptyFolder reproduces the production bug:
//
// Production error (2026-02-10T08:35:52):
// "failed to rename mailbox 'amazon' to 'amazontest': failed to update child mailboxes:
// ERROR: duplicate key violates unique constraint mailboxes_account_id_name_unique (SQLSTATE 23505)"
//
// User clarification: "amazontest is empty folder"
//
// Scenario:
//  1. User has "amazon" with children (e.g., "amazon/subfolder")
//  2. User has "amazontest" (EMPTY, no children)
//  3. User tries to rename "amazon" → "amazontest"
//  4. Code should either:
//     a) Fail because "amazontest" already exists (current behavior in 390dcab)
//     b) Or allow it and merge/replace (IMAP RFC allows this)
//
// But something goes wrong with the child updates causing constraint violation.
func TestRenameMailbox_RenameToExistingEmptyFolder(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _ := setupMailboxRenameTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// CREATE THE EXACT SCENARIO:

	// 1. Create "amazon" with child
	tx1, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx1.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx1, accountID, "amazon", nil)
	require.NoError(t, err)

	err = tx1.Commit(ctx)
	require.NoError(t, err)

	amazonMailbox, err := db.GetMailboxByName(ctx, accountID, "amazon")
	require.NoError(t, err)

	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx2, accountID, "amazon/subfolder", nil)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// 2. Create "amazontest" (EMPTY - no children)
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx3, accountID, "amazontest", nil)
	require.NoError(t, err)

	err = tx3.Commit(ctx)
	require.NoError(t, err)

	t.Logf("✓ Created scenario:")
	t.Logf("  - amazon (with children)")
	t.Logf("  - amazon/subfolder")
	t.Logf("  - amazontest (EMPTY)")

	// 3. Try to rename "amazon" → "amazontest"
	tx4, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx4.Rollback(ctx)

	err = db.RenameMailbox(ctx, tx4, amazonMailbox.ID, accountID, "amazontest", nil)

	// The current code (390dcab) should detect "amazontest" exists and return ErrMailboxAlreadyExists
	// But if there's a bug, it might try to proceed and hit constraint violation

	if err == nil {
		t.Fatal("❌ Rename succeeded when it should have failed (target exists)")
	}

	errMsg := err.Error()
	t.Logf("Got error: %v", err)

	// Check for production bug
	if strings.Contains(errMsg, "failed to update child mailboxes") &&
		(strings.Contains(errMsg, "SQLSTATE") || strings.Contains(errMsg, "constraint")) {
		t.Fatalf("❌ PRODUCTION BUG REPRODUCED: %v", err)
	}

	if strings.Contains(errMsg, "SQLSTATE") || strings.Contains(errMsg, "23505") {
		t.Fatalf("❌ BUG: Database constraint violation: %v", err)
	}

	// Good - got a clean error
	t.Logf("✅ Rename properly failed with: %v", err)

	tx4.Rollback(ctx)

	// Verify all mailboxes unchanged
	amazon, _ := db.GetMailboxByName(ctx, accountID, "amazon")
	assert.NotNil(t, amazon)
	assert.Equal(t, "amazon", amazon.Name)

	subfolder, _ := db.GetMailboxByName(ctx, accountID, "amazon/subfolder")
	assert.NotNil(t, subfolder)

	amazontest, _ := db.GetMailboxByName(ctx, accountID, "amazontest")
	assert.NotNil(t, amazontest)
	assert.Equal(t, "amazontest", amazontest.Name)
}
