package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewDBMailbox tests the DBMailbox constructor function
func TestNewDBMailbox(t *testing.T) {
	now := time.Now()

	mailbox := NewDBMailbox(
		1,                  // id
		"INBOX/Sent",       // name
		123456,             // uidValidity
		"/001/002",         // path
		true,               // subscribed
		false,              // hasChildren
		now,                // createdAt
		now.Add(time.Hour), // updatedAt
	)

	assert.Equal(t, int64(1), mailbox.ID)
	assert.Equal(t, "INBOX/Sent", mailbox.Name)
	assert.Equal(t, uint32(123456), mailbox.UIDValidity)
	assert.Equal(t, "/001/002", mailbox.Path)
	assert.True(t, mailbox.Subscribed)
	assert.False(t, mailbox.HasChildren)
	assert.Equal(t, now, mailbox.CreatedAt)
	assert.Equal(t, now.Add(time.Hour), mailbox.UpdatedAt)
}

// TestDBMailboxStruct tests the DBMailbox struct fields
func TestDBMailboxStruct(t *testing.T) {
	var mailbox DBMailbox

	// Test zero values
	assert.Equal(t, int64(0), mailbox.ID)
	assert.Equal(t, "", mailbox.Name)
	assert.Equal(t, uint32(0), mailbox.UIDValidity)
	assert.Equal(t, "", mailbox.Path)
	assert.False(t, mailbox.Subscribed)
	assert.False(t, mailbox.HasChildren)
	assert.True(t, mailbox.CreatedAt.IsZero())
	assert.True(t, mailbox.UpdatedAt.IsZero())
}

// TestMailboxSummaryStruct tests the MailboxSummary struct
func TestMailboxSummaryStruct(t *testing.T) {
	summary := MailboxSummary{
		UIDNext:           12345,
		NumMessages:       100,
		TotalSize:         1024000,
		HighestModSeq:     9876543210,
		RecentCount:       5,
		UnseenCount:       15,
		FirstUnseenSeqNum: 85,
	}

	assert.Equal(t, int64(12345), summary.UIDNext)
	assert.Equal(t, 100, summary.NumMessages)
	assert.Equal(t, int64(1024000), summary.TotalSize)
	assert.Equal(t, uint64(9876543210), summary.HighestModSeq)
	assert.Equal(t, 5, summary.RecentCount)
	assert.Equal(t, 15, summary.UnseenCount)
	assert.Equal(t, uint32(85), summary.FirstUnseenSeqNum)
}

// TestMailboxSummaryZeroValues tests MailboxSummary with zero values
func TestMailboxSummaryZeroValues(t *testing.T) {
	var summary MailboxSummary

	assert.Equal(t, int64(0), summary.UIDNext)
	assert.Equal(t, 0, summary.NumMessages)
	assert.Equal(t, int64(0), summary.TotalSize)
	assert.Equal(t, uint64(0), summary.HighestModSeq)
	assert.Equal(t, 0, summary.RecentCount)
	assert.Equal(t, 0, summary.UnseenCount)
	assert.Equal(t, uint32(0), summary.FirstUnseenSeqNum)
}

// Database test helpers for mailbox tests
func setupMailboxTestDatabase(t *testing.T) (*Database, int64) {
	db := setupTestDatabase(t)

	ctx := context.Background()

	// Use test name and timestamp to create unique email with unique domain
	// This prevents test isolation issues with shared mailboxes that have "anyone" ACL
	testEmail := fmt.Sprintf("test_%s_%d@test-%d.example.com", t.Name(), time.Now().UnixNano(), time.Now().UnixNano())

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

// TestGetMailboxes tests mailbox listing
func TestGetMailboxes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID := setupMailboxTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Get all mailboxes for user with no mailboxes
	mailboxes, err := db.GetMailboxes(ctx, accountID, false)
	assert.NoError(t, err)
	assert.Empty(t, mailboxes)

	// Test 2: Get only subscribed mailboxes (should also be empty)
	mailboxes, err = db.GetMailboxes(ctx, accountID, true)
	assert.NoError(t, err)
	assert.Empty(t, mailboxes)

	// Test 3: Non-existent user
	mailboxes, err = db.GetMailboxes(ctx, 99999, false)
	assert.NoError(t, err)
	assert.Empty(t, mailboxes)

	t.Logf("Successfully tested GetMailboxes with accountID: %d", accountID)
}

// TestCreateMailbox tests mailbox creation
func TestCreateMailbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID := setupMailboxTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Create simple mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx, accountID, "Test", nil)
	assert.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify mailbox was created
	mailbox, err := db.GetMailboxByName(ctx, accountID, "Test")
	assert.NoError(t, err)
	assert.NotNil(t, mailbox)
	assert.Equal(t, "Test", mailbox.Name)

	// Test 2: Create hierarchical mailbox
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx2, accountID, "INBOX/Sent", nil)
	assert.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Verify hierarchical mailbox was created
	sentMailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX/Sent")
	assert.NoError(t, err)
	assert.NotNil(t, sentMailbox)
	assert.Equal(t, "INBOX/Sent", sentMailbox.Name)

	// Test 3: Try to create duplicate mailbox (should fail)
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx3, accountID, "Test", nil)
	assert.Error(t, err) // Should fail due to duplicate name

	tx3.Rollback(ctx)

	t.Logf("Successfully tested CreateMailbox with accountID: %d", accountID)
}

// TestGetMailboxByName tests mailbox retrieval by name
func TestGetMailboxByName(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID := setupMailboxTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// First create a test mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx, accountID, "Drafts", nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test 1: Get mailbox by exact name
	mailbox, err := db.GetMailboxByName(ctx, accountID, "Drafts")
	assert.NoError(t, err)
	assert.NotNil(t, mailbox)
	assert.Equal(t, "Drafts", mailbox.Name)

	// Test 2: Get mailbox by non-existent name
	mailbox, err = db.GetMailboxByName(ctx, accountID, "NonExistent")
	assert.Error(t, err)
	assert.Nil(t, mailbox)

	// Test 3: Get mailbox for wrong user
	mailbox, err = db.GetMailboxByName(ctx, 99999, "Drafts")
	assert.Error(t, err)
	assert.Nil(t, mailbox)

	// Test 4: Empty name
	mailbox, err = db.GetMailboxByName(ctx, accountID, "")
	assert.Error(t, err)
	assert.Nil(t, mailbox)

	t.Logf("Successfully tested GetMailboxByName with accountID: %d", accountID)
}

// TestGetMailbox tests single mailbox retrieval by ID
func TestGetMailbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID := setupMailboxTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// First create a test mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx, accountID, "Trash", nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get the created mailbox to get its ID
	createdMailbox, err := db.GetMailboxByName(ctx, accountID, "Trash")
	require.NoError(t, err)

	// Test 1: Get existing mailbox by ID
	mailbox, err := db.GetMailbox(ctx, createdMailbox.ID, accountID)
	assert.NoError(t, err)
	assert.NotNil(t, mailbox)
	assert.Equal(t, createdMailbox.ID, mailbox.ID)
	assert.Equal(t, "Trash", mailbox.Name)

	// Test 2: Get non-existent mailbox
	mailbox, err = db.GetMailbox(ctx, 99999, accountID)
	assert.Error(t, err)
	assert.Nil(t, mailbox)

	// Test 3: Get mailbox for wrong user
	mailbox, err = db.GetMailbox(ctx, createdMailbox.ID, 99999)
	assert.Error(t, err)
	assert.Nil(t, mailbox)

	// Test 4: Get mailbox with zero ID
	mailbox, err = db.GetMailbox(ctx, 0, accountID)
	assert.Error(t, err)
	assert.Nil(t, mailbox)

	t.Logf("Successfully tested GetMailbox with accountID: %d, mailboxID: %d", accountID, createdMailbox.ID)
}

// TestCreateDefaultMailboxes tests creating all default mailboxes
func TestCreateDefaultMailboxes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID := setupMailboxTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Create default mailboxes for new user
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateDefaultMailboxes(ctx, tx, accountID)
	assert.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test 2: Verify all expected mailboxes are created
	mailboxes, err := db.GetMailboxes(ctx, accountID, false)
	assert.NoError(t, err)
	assert.NotEmpty(t, mailboxes)

	// Check that we have the expected default mailboxes
	expectedMailboxes := []string{"INBOX", "Sent", "Drafts", "Trash"}
	actualNames := make([]string, len(mailboxes))
	for i, mb := range mailboxes {
		actualNames[i] = mb.Name
	}

	for _, expected := range expectedMailboxes {
		assert.Contains(t, actualNames, expected, "Default mailbox %s should be created", expected)
	}

	t.Logf("Successfully tested CreateDefaultMailboxes with accountID: %d, created %d mailboxes", accountID, len(mailboxes))

	// Test 3: Verify early exit optimization - calling again should be fast (no inserts)
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.CreateDefaultMailboxes(ctx, tx2, accountID)
	assert.NoError(t, err, "Second call should succeed with early exit")

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Verify mailbox count hasn't changed
	mailboxes2, err := db.GetMailboxes(ctx, accountID, false)
	assert.NoError(t, err)
	assert.Equal(t, len(mailboxes), len(mailboxes2), "Mailbox count should not change on second call")
}

// TestSetMailboxSubscribed tests mailbox subscription management
func TestSetMailboxSubscribed(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID := setupMailboxTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// First create a test mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx, accountID, "TestSubscription", nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get the created mailbox
	mailbox, err := db.GetMailboxByName(ctx, accountID, "TestSubscription")
	require.NoError(t, err)

	// Test 1: Subscribe to mailbox
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.SetMailboxSubscribed(ctx, tx2, mailbox.ID, accountID, true)
	assert.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Test 2: Unsubscribe from mailbox
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	err = db.SetMailboxSubscribed(ctx, tx3, mailbox.ID, accountID, false)
	assert.NoError(t, err)

	err = tx3.Commit(ctx)
	require.NoError(t, err)

	// Test 3: Set subscription for non-existent mailbox (should error)
	tx4, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx4.Rollback(ctx)

	err = db.SetMailboxSubscribed(ctx, tx4, 99999, accountID, true)
	require.Error(t, err, "should error when mailbox does not exist")
	assert.ErrorIs(t, err, consts.ErrMailboxNotFound)

	tx4.Rollback(ctx)

	t.Logf("Successfully tested SetMailboxSubscribed with accountID: %d, mailboxID: %d", accountID, mailbox.ID)
}

// TestDeleteMailbox tests mailbox deletion
func TestDeleteMailbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID := setupMailboxTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// First create a test mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx, accountID, "ToDelete", nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get the created mailbox
	mailbox, err := db.GetMailboxByName(ctx, accountID, "ToDelete")
	require.NoError(t, err)

	// Test 1: Delete empty mailbox
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.DeleteMailbox(ctx, tx2, mailbox.ID, accountID)
	assert.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Verify mailbox was deleted
	_, err = db.GetMailboxByName(ctx, accountID, "ToDelete")
	assert.Error(t, err) // Should not be found

	// Test 2: Delete non-existent mailbox (should fail)
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	err = db.DeleteMailbox(ctx, tx3, 99999, accountID)
	assert.Error(t, err)

	tx3.Rollback(ctx)

	t.Logf("Successfully tested DeleteMailbox with accountID: %d", accountID)
}

// TestDeleteMailboxWithSibling verifies that deleting a mailbox does not accidentally
// delete a sibling mailbox that shares a common name prefix. This tests against
// the bug where `LIKE 'path%'` was used instead of `LIKE 'path/%'`.
func TestDeleteMailboxWithSibling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID := setupMailboxTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Create sibling mailboxes
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Create a mailbox to be deleted
	err = db.CreateMailbox(ctx, tx, accountID, "ToDelete", nil)
	require.NoError(t, err)

	// Create a sibling with a common prefix that should NOT be deleted
	err = db.CreateMailbox(ctx, tx, accountID, "ToDeleteSibling", nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get the mailbox to be deleted
	mailboxToDelete, err := db.GetMailboxByName(ctx, accountID, "ToDelete")
	require.NoError(t, err)

	// --- Perform Deletion ---
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.DeleteMailbox(ctx, tx2, mailboxToDelete.ID, accountID)
	assert.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// --- Verify Results ---
	// 1. Verify the target mailbox was deleted
	_, err = db.GetMailboxByName(ctx, accountID, "ToDelete")
	assert.ErrorIs(t, err, consts.ErrMailboxNotFound, "Mailbox 'ToDelete' should have been deleted")

	// 2. Verify the sibling mailbox STILL EXISTS
	_, err = db.GetMailboxByName(ctx, accountID, "ToDeleteSibling")
	assert.NoError(t, err, "Sibling mailbox 'ToDeleteSibling' should NOT have been deleted")

	t.Logf("Successfully tested that DeleteMailbox does not delete sibling mailboxes with common prefixes.")
}

// TestGetMailboxSummary tests mailbox summary retrieval
func TestGetMailboxSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID := setupMailboxTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// First create a test mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx, accountID, "SummaryTest", nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get the created mailbox
	mailbox, err := db.GetMailboxByName(ctx, accountID, "SummaryTest")
	require.NoError(t, err)

	// Test 1: Get summary for empty mailbox
	summary, err := db.GetMailboxSummary(ctx, mailbox.ID)
	assert.NoError(t, err)
	assert.NotNil(t, summary)
	assert.Equal(t, 0, summary.NumMessages)
	assert.Equal(t, int64(0), summary.TotalSize)

	// Test 2: Get summary for non-existent mailbox
	summary, err = db.GetMailboxSummary(ctx, 99999)
	assert.Error(t, err) // Should return error for non-existent mailbox
	assert.Nil(t, summary)

	t.Logf("Successfully tested GetMailboxSummary with accountID: %d, mailboxID: %d", accountID, mailbox.ID)
}

// TestGetMailboxMessageCountAndSizeSum tests message statistics
func TestGetMailboxMessageCountAndSizeSum(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID := setupMailboxTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// First create a test mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx, accountID, "StatsTest", nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get the created mailbox
	mailbox, err := db.GetMailboxByName(ctx, accountID, "StatsTest")
	require.NoError(t, err)

	// Test 1: Count messages in empty mailbox (should be 0, 0)
	count, size, err := db.GetMailboxMessageCountAndSizeSum(ctx, mailbox.ID)
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Equal(t, int64(0), size)

	// Test 2: Count for non-existent mailbox
	count, size, err = db.GetMailboxMessageCountAndSizeSum(ctx, 99999)
	assert.NoError(t, err) // Might return 0,0 instead of error
	assert.Equal(t, 0, count)
	assert.Equal(t, int64(0), size)

	t.Logf("Successfully tested GetMailboxMessageCountAndSizeSum with accountID: %d, mailboxID: %d", accountID, mailbox.ID)
}

// TestMailboxNameValidation tests mailbox name validation scenarios
func TestMailboxNameValidation(t *testing.T) {
	tests := []struct {
		name    string
		mailbox string
		valid   bool
	}{
		{"valid simple name", "Sent", true},
		{"valid hierarchical name", "INBOX/Sent", true},
		{"valid with spaces", "My Folder", true},
		{"empty name", "", false},
		{"just delimiter", "/", false},
		{"leading delimiter", "/Folder", false},
		{"trailing delimiter", "Folder/", false},
		{"double delimiter", "INBOX//Sent", false},
		{"unicode name", "📧 Mail", true},
		{"very long name", string(make([]byte, 300)), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This would test mailbox name validation logic
			// Since there's no explicit validation function visible,
			// this demonstrates the test structure for when one is added

			t.Skip("Mailbox name validation not yet implemented")

			// Example test:
			// valid := validateMailboxName(tt.mailbox)
			// assert.Equal(t, tt.valid, valid)
		})
	}
}

// TestMailboxPathHandling tests mailbox path generation and parsing
func TestMailboxPathHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID := setupMailboxTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test cases:
	// 1. Path for root level mailbox - create and test INBOX
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx, accountID, "INBOX", nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	inbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	assert.Equal(t, "INBOX", inbox.Name)
	assert.NotEmpty(t, inbox.Path, "Path should be a hex-encoded ID string")

	// 2. Path for nested mailbox
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx2, accountID, "Work/Projects", nil)
	require.NoError(t, err)
	require.NoError(t, tx2.Commit(ctx))

	workProjects, err := db.GetMailboxByName(ctx, accountID, "Work/Projects")
	require.NoError(t, err)
	assert.Equal(t, "Work/Projects", workProjects.Name)
	assert.NotEmpty(t, workProjects.Path, "Path should be a hex-encoded ID string")

	// 3. Path for deeply nested mailbox
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx3, accountID, "Work/Projects/2024/Q1", nil)
	require.NoError(t, err)
	require.NoError(t, tx3.Commit(ctx))

	deepNested, err := db.GetMailboxByName(ctx, accountID, "Work/Projects/2024/Q1")
	require.NoError(t, err)
	assert.Equal(t, "Work/Projects/2024/Q1", deepNested.Name)
	assert.NotEmpty(t, deepNested.Path, "Path should be a hex-encoded ID string")

	// 4. Verify the Path field is different from Name (hex encoding)
	assert.NotEqual(t, inbox.Name, inbox.Path, "Path should be hex-encoded, different from name")
	assert.NotEqual(t, workProjects.Name, workProjects.Path, "Path should be hex-encoded, different from name")
}
