package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Database test helpers for UIDVALIDITY tests
func setupUIDValidityTestDatabase(t *testing.T) (*Database, int64) {
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

	return db, accountID
}

// TestUIDValidityGeneration tests UIDVALIDITY generation for new mailboxes
func TestUIDValidityGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID := setupUIDValidityTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Create mailboxes with small time delays to ensure unique UIDVALIDITY
	var mailboxes []*DBMailbox

	for i := 0; i < 3; i++ {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)

		name := fmt.Sprintf("UIDTestMailbox_%d", i)
		err = db.CreateMailbox(ctx, tx, accountID, name, nil)
		require.NoError(t, err)

		err = tx.Commit(ctx)
		require.NoError(t, err)

		// Get the created mailbox
		mailbox, err := db.GetMailboxByName(ctx, accountID, name)
		require.NoError(t, err)
		mailboxes = append(mailboxes, mailbox)

		// Small delay to ensure different timestamps
		time.Sleep(10 * time.Millisecond)
	}

	// Test 2: Verify each mailbox has a non-zero UIDVALIDITY
	require.Len(t, mailboxes, 3)
	for i, mailbox := range mailboxes {
		assert.Greater(t, mailbox.UIDValidity, uint32(0), "Mailbox %d should have non-zero UIDVALIDITY", i)
		t.Logf("Mailbox %s has UIDVALIDITY: %d", mailbox.Name, mailbox.UIDValidity)
	}

	// Test 3: Verify UIDVALIDITY is reasonable (nanosecond timestamp-based)
	nowNano := time.Now().UnixNano()
	expectedUIDValidity := uint32(nowNano)
	for _, mailbox := range mailboxes {
		timeDiff := int64(mailbox.UIDValidity) - int64(expectedUIDValidity)
		if timeDiff < 0 {
			timeDiff = -timeDiff
		}
		// Allow up to 1 second worth of nanoseconds difference (1e9 nanoseconds)
		assert.Less(t, timeDiff, int64(1000000000),
			"UIDVALIDITY %d should be within 1 second of expected nanosecond-based value %d", mailbox.UIDValidity, expectedUIDValidity)
	}

	t.Logf("Successfully tested UIDValidityGeneration with accountID: %d", accountID)
}

// TestUIDValidityPersistence tests that UIDVALIDITY persists across operations
func TestUIDValidityPersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID := setupUIDValidityTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Create a mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx, accountID, "PersistenceTest", nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get the mailbox and record initial UIDVALIDITY
	mailbox, err := db.GetMailboxByName(ctx, accountID, "PersistenceTest")
	require.NoError(t, err)
	initialUIDValidity := mailbox.UIDValidity

	// Test 2: Set subscription status and verify UIDVALIDITY doesn't change
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.SetMailboxSubscribed(ctx, tx2, mailbox.ID, accountID, true)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Test 3: Verify UIDVALIDITY is unchanged
	subscribedMailbox, err := db.GetMailbox(ctx, mailbox.ID, accountID)
	assert.NoError(t, err)
	assert.Equal(t, initialUIDValidity, subscribedMailbox.UIDValidity, "UIDVALIDITY should not change during subscription update")
	assert.True(t, subscribedMailbox.Subscribed, "Mailbox should be subscribed")

	// Test 4: Multiple reads should return same UIDVALIDITY
	for i := 0; i < 3; i++ {
		readMailbox, err := db.GetMailbox(ctx, mailbox.ID, accountID)
		assert.NoError(t, err)
		assert.Equal(t, initialUIDValidity, readMailbox.UIDValidity, "UIDVALIDITY should be consistent across reads")
	}

	t.Logf("Successfully tested UIDValidityPersistence with accountID: %d, mailboxID: %d, UIDVALIDITY: %d", accountID, mailbox.ID, initialUIDValidity)
}

// TestDefaultMailboxesUIDValidity tests UIDVALIDITY in default mailboxes
func TestDefaultMailboxesUIDValidity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID := setupUIDValidityTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Create default mailboxes
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateDefaultMailboxes(ctx, tx, accountID)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test 2: Get all mailboxes
	mailboxes, err := db.GetMailboxes(ctx, accountID, false)
	assert.NoError(t, err)
	assert.NotEmpty(t, mailboxes)

	// Test 3: Verify all default mailboxes have valid UIDVALIDITY
	defaultMailboxNames := []string{"INBOX", "Drafts", "Sent", "Trash"}
	foundDefaultMailboxes := 0

	for _, mailbox := range mailboxes {
		for _, defaultName := range defaultMailboxNames {
			if mailbox.Name == defaultName {
				foundDefaultMailboxes++
				assert.Greater(t, mailbox.UIDValidity, uint32(0), "Default mailbox %s should have non-zero UIDVALIDITY", defaultName)
				t.Logf("Default mailbox %s has UIDVALIDITY: %d", mailbox.Name, mailbox.UIDValidity)
				break
			}
		}
	}

	assert.Equal(t, len(defaultMailboxNames), foundDefaultMailboxes, "Should find all default mailboxes")

	t.Logf("Successfully tested DefaultMailboxesUIDValidity with accountID: %d", accountID)
}

// TestUIDValidityRangeValidation tests UIDVALIDITY value ranges
func TestUIDValidityRangeValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID := setupUIDValidityTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Create a mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx, accountID, "RangeTest", nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test 2: Get mailbox and validate UIDVALIDITY range
	mailbox, err := db.GetMailboxByName(ctx, accountID, "RangeTest")
	require.NoError(t, err)

	// UIDVALIDITY should be a 32-bit unsigned integer within reasonable bounds
	assert.Greater(t, mailbox.UIDValidity, uint32(0), "UIDVALIDITY should be non-zero")
	assert.Less(t, mailbox.UIDValidity, uint32(4294967295), "UIDVALIDITY should be within uint32 range")

	// UIDVALIDITY should be close to current nanosecond timestamp (truncated to uint32)
	nowNano := time.Now().UnixNano()
	expectedUIDValidity := uint32(nowNano)
	timeDiff := int64(mailbox.UIDValidity) - int64(expectedUIDValidity)
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	// Allow up to 1 second worth of nanoseconds difference (1e9 nanoseconds)
	assert.Less(t, timeDiff, int64(1000000000), "UIDVALIDITY should be within 1 second of current nanosecond timestamp")

	t.Logf("Successfully tested UIDValidityRangeValidation with accountID: %d, UIDVALIDITY: %d (expected around: %d)", accountID, mailbox.UIDValidity, expectedUIDValidity)
}
