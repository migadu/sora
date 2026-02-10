package db

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRenameMailbox_CaseChangeWithChildConflict tests the scenario where:
// User renames "amazon" → "Amazontest" (different case)
// But has child "amazon/subfolder" and "Amazontest/subfolder" exists
//
// The existence check passes (case-sensitive: "Amazontest" != "amazontest")
// But the child rename fails because PostgreSQL allows both cases!
func TestRenameMailbox_CaseChangeWithChildConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _ := setupMailboxRenameTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// CREATE SCENARIO:
	//  - amazon
	//  - amazon/subfolder
	//  - Amazontest (note capital A)
	//  - Amazontest/subfolder
	// User tries: rename "amazon" → "amazontest" (lowercase)

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

	// 2. Create "Amazontest" (capital A) with child
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx3, accountID, "Amazontest", nil)
	require.NoError(t, err)

	err = tx3.Commit(ctx)
	require.NoError(t, err)

	tx4, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx4.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx4, accountID, "Amazontest/subfolder", nil)
	require.NoError(t, err)

	err = tx4.Commit(ctx)
	require.NoError(t, err)

	t.Logf("✓ Created scenario:")
	t.Logf("  - amazon")
	t.Logf("  - amazon/subfolder")
	t.Logf("  - Amazontest (capital A)")
	t.Logf("  - Amazontest/subfolder")

	// 3. Try to rename "amazon" → "amazontest" (lowercase)
	// Existence check: "amazontest" (lowercase) doesn't exist - CHECK PASSES
	// Parent rename: "amazon" → "amazontest" - OK
	// Child rename: "amazon/subfolder" → "amazontest/subfolder"
	// But wait! PostgreSQL schema allows BOTH "Amazontest/subfolder" AND "amazontest/subfolder"
	// So this might actually succeed!

	tx5, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx5.Rollback(ctx)

	err = db.RenameMailbox(ctx, tx5, amazonMailbox.ID, accountID, "amazontest", nil)

	if err == nil {
		t.Logf("⚠️  Rename SUCCEEDED - PostgreSQL allows case-sensitive duplicates!")
		t.Logf("  This is actually OK given the schema allows it")

		// Verify both mailboxes exist
		amazontest, _ := db.GetMailboxByName(ctx, accountID, "amazontest")
		if amazontest != nil {
			t.Logf("  - Created: amazontest")
		}

		Amazontest, _ := db.GetMailboxByName(ctx, accountID, "Amazontest")
		if Amazontest != nil {
			t.Logf("  - Still exists: Amazontest")
		}

		tx5.Rollback(ctx)
		return
	}

	errMsg := err.Error()
	t.Logf("Got error: %v", err)

	// Check for production bug
	if strings.Contains(errMsg, "failed to update child mailboxes") &&
		(strings.Contains(errMsg, "SQLSTATE") || strings.Contains(errMsg, "23505")) {
		t.Fatalf("❌ PRODUCTION BUG REPRODUCED: %v", err)
	}

	if strings.Contains(errMsg, "SQLSTATE") || strings.Contains(errMsg, "23505") {
		t.Fatalf("❌ BUG: Database constraint violation: %v", err)
	}

	t.Logf("✅ Rename failed gracefully: %v", err)
	tx5.Rollback(ctx)

	// Verify data unchanged
	amazon, _ := db.GetMailboxByName(ctx, accountID, "amazon")
	assert.NotNil(t, amazon)

	amazonSub, _ := db.GetMailboxByName(ctx, accountID, "amazon/subfolder")
	assert.NotNil(t, amazonSub)

	Amazontest, _ := db.GetMailboxByName(ctx, accountID, "Amazontest")
	assert.NotNil(t, Amazontest)

	AmazontestSub, _ := db.GetMailboxByName(ctx, accountID, "Amazontest/subfolder")
	assert.NotNil(t, AmazontestSub)
}
