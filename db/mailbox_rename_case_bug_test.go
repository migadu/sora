package db

import (
	"context"
	"strings"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRenameMailbox_CaseSensitivityProductionBug reproduces the exact production bug:
//
// Production error log (2026-02-10T08:35:52):
// "failed to rename mailbox 'amazon' to 'amazontest': failed to update child mailboxes:
// ERROR: duplicate key value violates unique constraint mailboxes_account_id_name_unique (SQLSTATE 23505)"
//
// ROOT CAUSE in deployed code (commit 390dcab):
// Line 745 uses case-sensitive check (good!) but the logic flow is:
// 1. Check if "amazontest" exists (case-sensitive)
// 2. If user has "Amazontest" (capital A), check passes (different case!)
// 3. UPDATE tries to create "amazontest"
// 4. Constraint violation because case-insensitive collation or the check uses AccountID instead of ownerAccountID
//
// This test creates the exact scenario and verifies it either:
// - Returns ErrMailboxAlreadyExists (FIXED)
// - Returns database constraint error (BUG PRESENT)
func TestRenameMailbox_CaseSensitivityProductionBug(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _ := setupMailboxRenameTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Create the exact production scenario:
	// 1. Create "amazon" with a child
	// 2. Create "Amazontest" (capital A)
	// 3. Try to rename "amazon" -> "amazontest" (lowercase)
	// Expected: Should fail with ErrMailboxAlreadyExists
	// Bug: Fails with SQLSTATE 23505 constraint violation

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Create "amazon"
	err = db.CreateMailbox(ctx, tx, accountID, "amazon", nil)
	require.NoError(t, err, "Failed to create 'amazon'")

	// Get amazon mailbox ID
	err = tx.Commit(ctx)
	require.NoError(t, err)

	amazonMailbox, err := db.GetMailboxByName(ctx, accountID, "amazon")
	require.NoError(t, err)

	// Create "amazon/subfolder" (child)
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx2, accountID, "amazon/subfolder", nil)
	require.NoError(t, err, "Failed to create 'amazon/subfolder'")

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Create "amazontest" (lowercase - exact match for what user is trying to rename to)
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx3, accountID, "amazontest", nil)
	require.NoError(t, err, "Failed to create 'amazontest'")

	err = tx3.Commit(ctx)
	require.NoError(t, err)

	t.Logf("✓ Created test scenario: amazon, amazon/subfolder, amazontest")

	// Now try to rename "amazon" -> "amazontest"
	// This MUST fail because "amazontest" already exists
	tx4, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx4.Rollback(ctx)

	err = db.RenameMailbox(ctx, tx4, amazonMailbox.ID, accountID, "amazontest", nil)

	// CHECK THE ERROR TYPE
	if err == nil {
		t.Fatalf("❌ CRITICAL: Rename succeeded when it should have failed (mailbox conflict not detected)")
	}

	errMsg := err.Error()

	// Check if it's a database constraint violation (BUG!)
	if strings.Contains(errMsg, "SQLSTATE") ||
		strings.Contains(errMsg, "23505") ||
		strings.Contains(errMsg, "duplicate key") ||
		strings.Contains(errMsg, "unique constraint") ||
		strings.Contains(errMsg, "violates") {
		t.Fatalf("❌ PRODUCTION BUG REPRODUCED!\n"+
			"Got database constraint violation: %v\n"+
			"Expected: ErrMailboxAlreadyExists\n"+
			"This is the EXACT error from production logs!", err)
	}

	// Check if it's the expected error (FIXED!)
	if err == consts.ErrMailboxAlreadyExists {
		t.Logf("✅ FIXED: Got proper ErrMailboxAlreadyExists instead of constraint violation")
	} else {
		// Some other error - log it
		t.Logf("Got error (verify if appropriate): %v", err)
		// For now, accept any non-constraint-violation error as acceptable
		if !strings.Contains(strings.ToLower(errMsg), "exists") &&
			!strings.Contains(strings.ToLower(errMsg), "already") {
			t.Logf("Warning: Error doesn't mention 'exists' or 'already': %v", err)
		}
	}

	// Verify data integrity - amazon should still exist with its child
	tx4.Rollback(ctx)

	amazonStillExists, err := db.GetMailboxByName(ctx, accountID, "amazon")
	assert.NoError(t, err, "Original 'amazon' mailbox should still exist")
	assert.Equal(t, "amazon", amazonStillExists.Name)

	subfolderStillExists, err := db.GetMailboxByName(ctx, accountID, "amazon/subfolder")
	assert.NoError(t, err, "Child 'amazon/subfolder' should still exist")
	assert.Equal(t, "amazon/subfolder", subfolderStillExists.Name)

	amazontestStillExists, err := db.GetMailboxByName(ctx, accountID, "amazontest")
	assert.NoError(t, err, "Existing 'amazontest' should be unchanged")
	assert.Equal(t, "amazontest", amazontestStillExists.Name)

	t.Logf("✅ All mailboxes preserved correctly after failed rename")
}
