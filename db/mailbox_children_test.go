package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to find a mailbox by name from a slice of mailboxes.
func findMailboxByName(mailboxes []*DBMailbox, name string) *DBMailbox {
	for _, mbox := range mailboxes {
		if mbox.Name == name {
			return mbox
		}
	}
	return nil
}

func TestMailboxHasChildrenFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Setup account
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)

	testEmail := fmt.Sprintf("test_children_%d@example.com", time.Now().UnixNano())
	req := CreateAccountRequest{Email: testEmail, Password: "password", IsPrimary: true, HashType: "bcrypt"}
	err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	// --- Scenario 1: Create a single mailbox with no children ---
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	err = db.CreateMailbox(ctx, tx, accountID, "Parent", nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	parentMailbox, err := db.GetMailboxByName(ctx, accountID, "Parent")
	require.NoError(t, err)

	t.Run("SingleMailboxNoChildren", func(t *testing.T) {
		// Test GetMailbox
		mbox, err := db.GetMailbox(ctx, parentMailbox.ID, accountID)
		require.NoError(t, err)
		assert.False(t, mbox.HasChildren, "Parent mailbox should not have children yet")

		// Test GetMailboxes
		allMailboxes, err := db.GetMailboxes(ctx, accountID, false)
		require.NoError(t, err)
		parentFromList := findMailboxByName(allMailboxes, "Parent")
		require.NotNil(t, parentFromList)
		assert.False(t, parentFromList.HasChildren, "Parent mailbox in list should not have children")
	})

	// --- Scenario 2: Add a child mailbox ---
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	err = db.CreateMailbox(ctx, tx, accountID, "Parent/Child", &parentMailbox.ID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	childMailbox, err := db.GetMailboxByName(ctx, accountID, "Parent/Child")
	require.NoError(t, err)

	t.Run("MailboxWithOneChild", func(t *testing.T) {
		// Test GetMailbox for parent
		parent, err := db.GetMailbox(ctx, parentMailbox.ID, accountID)
		require.NoError(t, err)
		assert.True(t, parent.HasChildren, "Parent mailbox should now have children")

		// Test GetMailbox for child
		child, err := db.GetMailbox(ctx, childMailbox.ID, accountID)
		require.NoError(t, err)
		assert.False(t, child.HasChildren, "Child mailbox should not have children")

		// Test GetMailboxes
		allMailboxes, err := db.GetMailboxes(ctx, accountID, false)
		require.NoError(t, err)
		parentFromList := findMailboxByName(allMailboxes, "Parent")
		require.NotNil(t, parentFromList)
		assert.True(t, parentFromList.HasChildren, "Parent in list should have children")

		childFromList := findMailboxByName(allMailboxes, "Parent/Child")
		require.NotNil(t, childFromList)
		assert.False(t, childFromList.HasChildren, "Child in list should not have children")
	})

	// --- Scenario 3: Add a grandchild mailbox ---
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	err = db.CreateMailbox(ctx, tx, accountID, "Parent/Child/Grandchild", &childMailbox.ID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	_, err = db.GetMailboxByName(ctx, accountID, "Parent/Child/Grandchild")
	require.NoError(t, err)

	t.Run("MailboxWithGrandchild", func(t *testing.T) {
		// Test GetMailbox for parent and child
		parent, err := db.GetMailbox(ctx, parentMailbox.ID, accountID)
		require.NoError(t, err)
		assert.True(t, parent.HasChildren, "Parent should still have children")

		child, err := db.GetMailbox(ctx, childMailbox.ID, accountID)
		require.NoError(t, err)
		assert.True(t, child.HasChildren, "Child should now have children")

		// Test GetMailboxes list
		allMailboxes, err := db.GetMailboxes(ctx, accountID, false)
		require.NoError(t, err)

		grandchildFromList := findMailboxByName(allMailboxes, "Parent/Child/Grandchild")
		require.NotNil(t, grandchildFromList)
		assert.False(t, grandchildFromList.HasChildren, "Grandchild in list should not have children")
	})

	// --- Scenario 4: Add a sibling mailbox to test path prefix bug ---
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	// Create a sibling with a common prefix.
	// Before the fix, "SiblingIsNotAChild" would be incorrectly identified as a child of "Sibling".
	err = db.CreateMailbox(ctx, tx, accountID, "Sibling", nil)
	require.NoError(t, err)
	err = db.CreateMailbox(ctx, tx, accountID, "SiblingIsNotAChild", nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	siblingMailbox, err := db.GetMailboxByName(ctx, accountID, "Sibling")
	require.NoError(t, err)

	t.Run("MailboxWithSibling", func(t *testing.T) {
		// Test GetMailbox for the sibling
		mbox, err := db.GetMailbox(ctx, siblingMailbox.ID, accountID)
		require.NoError(t, err)
		assert.False(t, mbox.HasChildren, "Mailbox 'Sibling' should not have children")

		// Test GetMailboxes list
		allMailboxes, err := db.GetMailboxes(ctx, accountID, false)
		require.NoError(t, err)
		siblingFromList := findMailboxByName(allMailboxes, "Sibling")
		require.NotNil(t, siblingFromList)
		assert.False(t, siblingFromList.HasChildren, "Mailbox 'Sibling' in list should not have children")
	})
}
