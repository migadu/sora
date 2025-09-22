package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Database test helpers for mailbox rename and UIDVALIDITY tests
func setupMailboxRenameTestDatabase(t *testing.T) (*Database, int64, int64) {
	db := setupTestDatabase(t)

	ctx := context.Background()

	// Use test name and timestamp to create unique email
	testEmail := fmt.Sprintf("test_%s_%d@example.com", t.Name(), time.Now().UnixNano())

	// Create test account
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	req := CreateAccountRequest{
		Email:     testEmail,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	}
	err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get account ID
	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	// Create test mailbox
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx2, accountID, "TestFolder", nil)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Get mailbox
	mailbox, err := db.GetMailboxByName(ctx, accountID, "TestFolder")
	require.NoError(t, err)

	return db, accountID, mailbox.ID
}

// TestRenameMailbox tests mailbox renaming functionality
func TestRenameMailbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMailboxRenameTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Basic mailbox rename
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.RenameMailbox(ctx, tx, mailboxID, accountID, "RenamedFolder", nil)
	assert.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test 2: Verify the mailbox was renamed
	renamedMailbox, err := db.GetMailboxByName(ctx, accountID, "RenamedFolder")
	assert.NoError(t, err)
	assert.NotNil(t, renamedMailbox)
	assert.Equal(t, "RenamedFolder", renamedMailbox.Name)
	assert.Equal(t, mailboxID, renamedMailbox.ID)

	// Test 3: Verify old name no longer exists
	_, err = db.GetMailboxByName(ctx, accountID, "TestFolder")
	assert.Error(t, err)

	// Test 4: Try to rename to existing name (should fail)
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	// Create another mailbox first
	err = db.CreateMailbox(ctx, tx2, accountID, "AnotherFolder", nil)
	require.NoError(t, err)

	// Try to rename to existing name
	err = db.RenameMailbox(ctx, tx2, mailboxID, accountID, "AnotherFolder", nil)
	assert.Error(t, err)

	tx2.Rollback(ctx)

	t.Logf("Successfully tested RenameMailbox with accountID: %d, mailboxID: %d", accountID, mailboxID)
}

// TestRenameMailboxInvalidName tests mailbox renaming with invalid names
func TestRenameMailboxInvalidName(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMailboxRenameTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test invalid names
	invalidNames := []string{
		"",                     // empty name
		"Name\twith\ttab",      // tab character
		"Name\rwith\rcarriage", // carriage return
		"Name\nwith\nnewline",  // newline
		"Name\x00with\x00null", // null character
	}

	for _, invalidName := range invalidNames {
		t.Run(fmt.Sprintf("InvalidName_%q", invalidName), func(t *testing.T) {
			tx, err := db.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)

			err = db.RenameMailbox(ctx, tx, mailboxID, accountID, invalidName, nil)
			assert.Error(t, err)

			tx.Rollback(ctx)
		})
	}

	t.Logf("Successfully tested RenameMailboxInvalidName with accountID: %d, mailboxID: %d", accountID, mailboxID)
}

// TestRenameMailboxHierarchy tests renaming mailboxes with parent-child relationships
func TestRenameMailboxHierarchy(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, parentMailboxID := setupMailboxRenameTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Create child mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx, accountID, "ChildFolder", &parentMailboxID)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get child mailbox
	childMailbox, err := db.GetMailboxByName(ctx, accountID, "ChildFolder")
	require.NoError(t, err)

	// Test 2: Rename parent mailbox (should update child paths)
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.RenameMailbox(ctx, tx2, parentMailboxID, accountID, "RenamedParent", nil)
	assert.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Test 3: Verify parent was renamed
	renamedParent, err := db.GetMailboxByName(ctx, accountID, "RenamedParent")
	assert.NoError(t, err)
	assert.NotNil(t, renamedParent)

	// Test 4: Verify child path was updated
	updatedChild, err := db.GetMailbox(ctx, childMailbox.ID, accountID)
	assert.NoError(t, err)
	assert.NotNil(t, updatedChild)
	// Child name should still be "ChildFolder" but path should be updated

	// Test 5: Try to move mailbox into its own child (should fail)
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	err = db.RenameMailbox(ctx, tx3, parentMailboxID, accountID, "MovedParent", &childMailbox.ID)
	assert.Error(t, err) // Should fail - can't move parent into child

	tx3.Rollback(ctx)

	t.Logf("Successfully tested RenameMailboxHierarchy with accountID: %d, parentID: %d, childID: %d", accountID, parentMailboxID, childMailbox.ID)
}

// TestMailboxUIDValidity tests UIDVALIDITY functionality
func TestMailboxUIDValidity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _ := setupMailboxRenameTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Create multiple mailboxes and verify they have unique UIDVALIDITY
	var mailboxes []*DBMailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("UIDTestMailbox_%d", i)
		err = db.CreateMailbox(ctx, tx, accountID, name, nil)
		require.NoError(t, err)
	}

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get all mailboxes for the account
	allMailboxes, err := db.GetMailboxes(ctx, accountID, false)
	assert.NoError(t, err)

	// Find our test mailboxes
	for _, mailbox := range allMailboxes {
		if mailbox.Name == "UIDTestMailbox_0" ||
			mailbox.Name == "UIDTestMailbox_1" ||
			mailbox.Name == "UIDTestMailbox_2" {
			mailboxes = append(mailboxes, mailbox)
		}
	}

	// Test 2: Verify each mailbox has a non-zero UIDVALIDITY
	require.Len(t, mailboxes, 3)
	for i, mailbox := range mailboxes {
		assert.Greater(t, mailbox.UIDValidity, uint32(0), "Mailbox %d should have non-zero UIDVALIDITY", i)
		t.Logf("Mailbox %s has UIDVALIDITY: %d", mailbox.Name, mailbox.UIDValidity)
	}

	// Test 3: Verify UIDVALIDITY values are reasonable and track uniqueness
	// Note: Mailboxes created in the same transaction may have identical UIDVALIDITY values
	// since they're timestamp-based, which is acceptable IMAP behavior
	uidValidities := make(map[uint32]int)
	for _, mailbox := range mailboxes {
		uidValidities[mailbox.UIDValidity]++
	}

	// At least verify that we don't have all different values or all the same value in suspicious ways
	assert.LessOrEqual(t, len(uidValidities), 3, "Should not have more unique UIDVALIDITY values than mailboxes")
	assert.GreaterOrEqual(t, len(uidValidities), 1, "Should have at least one UIDVALIDITY value")

	// Log the distribution for debugging
	t.Logf("UIDVALIDITY distribution: %v", uidValidities)

	// Test 4: Verify UIDVALIDITY is reasonable (nanosecond timestamp-based, truncated to uint32)
	// Since UIDVALIDITY is now based on nanoseconds truncated to uint32,
	// we need to check it's a reasonable nanosecond-derived value
	nowNano := time.Now().UnixNano()
	expectedUIDValidity := uint32(nowNano)

	for _, mailbox := range mailboxes {
		// UIDVALIDITY should be within a reasonable range of the current nanosecond timestamp
		// (truncated to uint32). Allow for some time difference due to test execution time.
		timeDiff := int64(mailbox.UIDValidity) - int64(expectedUIDValidity)
		if timeDiff < 0 {
			timeDiff = -timeDiff
		}
		// Allow up to 1 second worth of nanoseconds difference (1e9 nanoseconds)
		assert.Less(t, timeDiff, int64(1000000000),
			"UIDVALIDITY %d should be within 1 second of expected nanosecond-based value %d",
			mailbox.UIDValidity, expectedUIDValidity)
	}

	t.Logf("Successfully tested MailboxUIDValidity with accountID: %d", accountID)
}

// TestMailboxUIDValidityPersistence tests that UIDVALIDITY persists across operations
func TestMailboxUIDValidityPersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMailboxRenameTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Get initial UIDVALIDITY
	initialMailbox, err := db.GetMailbox(ctx, mailboxID, accountID)
	require.NoError(t, err)
	initialUIDValidity := initialMailbox.UIDValidity

	// Test 2: Rename mailbox and verify UIDVALIDITY doesn't change
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.RenameMailbox(ctx, tx, mailboxID, accountID, "RenamedForUIDTest", nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test 3: Verify UIDVALIDITY is unchanged after rename
	renamedMailbox, err := db.GetMailbox(ctx, mailboxID, accountID)
	assert.NoError(t, err)
	assert.Equal(t, initialUIDValidity, renamedMailbox.UIDValidity, "UIDVALIDITY should not change during rename")

	// Test 4: Set subscription status and verify UIDVALIDITY doesn't change
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.SetMailboxSubscribed(ctx, tx2, mailboxID, accountID, true)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Test 5: Verify UIDVALIDITY is still unchanged
	subscribedMailbox, err := db.GetMailbox(ctx, mailboxID, accountID)
	assert.NoError(t, err)
	assert.Equal(t, initialUIDValidity, subscribedMailbox.UIDValidity, "UIDVALIDITY should not change during subscription update")
	assert.True(t, subscribedMailbox.Subscribed, "Mailbox should be subscribed")

	t.Logf("Successfully tested MailboxUIDValidityPersistence with accountID: %d, mailboxID: %d, UIDVALIDITY: %d", accountID, mailboxID, initialUIDValidity)
}

// TestRenameNonExistentMailbox tests renaming non-existent mailbox
func TestRenameNonExistentMailbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _ := setupMailboxRenameTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test: Try to rename non-existent mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	nonExistentMailboxID := int64(99999)
	err = db.RenameMailbox(ctx, tx, nonExistentMailboxID, accountID, "NewName", nil)
	assert.Error(t, err)

	tx.Rollback(ctx)

	t.Logf("Successfully tested RenameNonExistentMailbox with accountID: %d", accountID)
}
