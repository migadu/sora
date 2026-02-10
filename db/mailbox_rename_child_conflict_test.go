package db

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRenameMailbox_ChildConflictProductionBug reproduces the EXACT production bug:
//
// Production error (2026-02-10T08:35:52 UTC):
// "Can't rename folder. SERVERBUG failed to rename mailbox 'amazon' to 'amazontest':
// failed to update child mailboxes: ERROR: duplicate key value violates unique constraint
// mailboxes_account_id_name_unique (SQLSTATE 23505)"
//
// The key phrase is "failed to update CHILD mailboxes"!
//
// Scenario:
// 1. User has "amazon" with child "amazon/subfolder"
// 2. User has "amazontest/subfolder" (created separately at some point)
// 3. User tries to rename "amazon" → "amazontest"
// 4. Code successfully checks "amazontest" doesn't exist (or it does exist and that's OK)
// 5. Code tries to rename child: "amazon/subfolder" → "amazontest/subfolder"
// 6. CONFLICT! "amazontest/subfolder" already exists
// 7. Database throws constraint violation
//
// The fix (commit 390dcab) added child conflict detection, but we need to verify it works.
func TestRenameMailbox_ChildConflictProductionBug(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _ := setupMailboxRenameTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// CREATE THE EXACT PRODUCTION SCENARIO:

	// 1. Create "amazon" parent
	tx1, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx1.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx1, accountID, "amazon", nil)
	require.NoError(t, err)

	err = tx1.Commit(ctx)
	require.NoError(t, err)

	// Get amazon mailbox ID
	amazonMailbox, err := db.GetMailboxByName(ctx, accountID, "amazon")
	require.NoError(t, err)

	// 2. Create "amazon/subfolder" child
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx2, accountID, "amazon/subfolder", nil)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// 3. Create "amazontest" parent
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx3, accountID, "amazontest", nil)
	require.NoError(t, err)

	err = tx3.Commit(ctx)
	require.NoError(t, err)

	// 4. Create "amazontest/subfolder" (THE CONFLICTING CHILD!)
	tx4, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx4.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx4, accountID, "amazontest/subfolder", nil)
	require.NoError(t, err)

	err = tx4.Commit(ctx)
	require.NoError(t, err)

	t.Logf("✓ Created production scenario:")
	t.Logf("  - amazon")
	t.Logf("  - amazon/subfolder")
	t.Logf("  - amazontest")
	t.Logf("  - amazontest/subfolder (THE CONFLICT!)")

	// 5. Try to rename "amazon" → "amazontest"
	// This will try to rename "amazon/subfolder" → "amazontest/subfolder"
	// But "amazontest/subfolder" ALREADY EXISTS!
	tx5, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx5.Rollback(ctx)

	err = db.RenameMailbox(ctx, tx5, amazonMailbox.ID, accountID, "amazontest", nil)

	// VERIFY THE ERROR
	if err == nil {
		t.Fatalf("❌ CRITICAL BUG: Rename succeeded when child conflict should have been detected!\n" +
			"Renaming 'amazon' → 'amazontest' should fail because 'amazontest/subfolder' already exists")
	}

	errMsg := err.Error()
	t.Logf("Got error: %v", err)

	// Check if it's the production bug (constraint violation on child update)
	if strings.Contains(errMsg, "failed to update child mailboxes") &&
		(strings.Contains(errMsg, "SQLSTATE") || strings.Contains(errMsg, "23505") ||
			strings.Contains(errMsg, "duplicate key") || strings.Contains(errMsg, "unique constraint")) {
		t.Fatalf("❌ EXACT PRODUCTION BUG REPRODUCED!\n\n"+
			"Got: %v\n\n"+
			"This matches the production error:\n"+
			"'failed to rename mailbox amazon to amazontest: failed to update child mailboxes: \n"+
			"ERROR: duplicate key violates unique constraint mailboxes_account_id_name_unique (SQLSTATE 23505)'\n\n"+
			"The code is NOT detecting the child name conflict before attempting the rename!", err)
	}

	// Check for other constraint violations (still a bug, just different message)
	if strings.Contains(errMsg, "SQLSTATE") || strings.Contains(errMsg, "23505") ||
		(strings.Contains(errMsg, "duplicate") && strings.Contains(errMsg, "constraint")) {
		t.Fatalf("❌ BUG: Got database constraint violation (child conflict not detected): %v", err)
	}

	// If we get here, the error is NOT a constraint violation - good!
	// Verify it's a meaningful error about the conflict
	if strings.Contains(errMsg, "conflict") ||
		strings.Contains(errMsg, "already exists") ||
		strings.Contains(errMsg, "would create") {
		t.Logf("✅ FIXED: Rename properly rejected with meaningful error")
		t.Logf("   Error message describes the conflict: %v", err)
	} else {
		t.Logf("⚠️  Warning: Error doesn't clearly describe the child conflict")
		t.Logf("   Consider improving error message: %v", err)
		// Still pass the test as long as it's not a constraint violation
	}

	// Verify data integrity - all mailboxes should still exist unchanged
	tx5.Rollback(ctx)

	amazon, err := db.GetMailboxByName(ctx, accountID, "amazon")
	assert.NoError(t, err)
	assert.Equal(t, "amazon", amazon.Name)

	amazonSub, err := db.GetMailboxByName(ctx, accountID, "amazon/subfolder")
	assert.NoError(t, err)
	assert.Equal(t, "amazon/subfolder", amazonSub.Name)

	amazontest, err := db.GetMailboxByName(ctx, accountID, "amazontest")
	assert.NoError(t, err)
	assert.Equal(t, "amazontest", amazontest.Name)

	amazontestSub, err := db.GetMailboxByName(ctx, accountID, "amazontest/subfolder")
	assert.NoError(t, err)
	assert.Equal(t, "amazontest/subfolder", amazontestSub.Name)

	t.Logf("✅ All mailboxes preserved correctly after failed rename")
}
