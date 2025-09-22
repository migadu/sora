package db

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Database test helpers for account management tests
func setupAccountManagementTestDatabase(t *testing.T) (*Database, string) {
	db := setupTestDatabase(t)

	// Use test name and timestamp to create unique email
	testEmail := fmt.Sprintf("test_%s_%d@example.com", t.Name(), time.Now().UnixNano())

	return db, testEmail
}

// TestDeleteAccount tests account soft deletion
func TestDeleteAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail := setupAccountManagementTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Create an account first
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

	// Test 2: Verify account exists
	exists, err := db.AccountExists(ctx, testEmail)
	assert.NoError(t, err)
	assert.True(t, exists)

	// Test 3: Delete the account
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.DeleteAccount(ctx, tx2, testEmail)
	assert.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Test 4: Try to delete already deleted account
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	err = db.DeleteAccount(ctx, tx3, testEmail)
	assert.ErrorIs(t, err, ErrAccountAlreadyDeleted)

	tx3.Rollback(ctx)

	t.Logf("Successfully tested DeleteAccount with email: %s", testEmail)
}

// TestRestoreAccount tests account restoration from soft deletion
func TestRestoreAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail := setupAccountManagementTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Create and delete an account
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

	// Delete the account
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.DeleteAccount(ctx, tx2, testEmail)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Test 2: Restore the account
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	err = db.RestoreAccount(ctx, tx3, testEmail)
	assert.NoError(t, err)

	err = tx3.Commit(ctx)
	require.NoError(t, err)

	// Test 3: Verify account is restored and exists
	exists, err := db.AccountExists(ctx, testEmail)
	assert.NoError(t, err)
	assert.True(t, exists)

	// Test 4: Try to restore non-deleted account
	tx4, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx4.Rollback(ctx)

	err = db.RestoreAccount(ctx, tx4, testEmail)
	assert.ErrorIs(t, err, ErrAccountNotDeleted)

	tx4.Rollback(ctx)

	t.Logf("Successfully tested RestoreAccount with email: %s", testEmail)
}

// TestUpdateAccount tests account update functionality
func TestUpdateAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail := setupAccountManagementTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Create an account first
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

	// Test 2: Update the account password
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	updateReq := UpdateAccountRequest{
		Email:    testEmail,
		Password: "newpassword456",
		HashType: "bcrypt",
	}
	err = db.UpdateAccount(ctx, tx2, updateReq)
	assert.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Test 3: Try to update non-existent account
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	nonExistentUpdateReq := UpdateAccountRequest{
		Email:    "nonexistent@example.com",
		Password: "password",
		HashType: "bcrypt",
	}
	err = db.UpdateAccount(ctx, tx3, nonExistentUpdateReq)
	assert.Error(t, err)

	tx3.Rollback(ctx)

	t.Logf("Successfully tested UpdateAccount with email: %s", testEmail)
}

// TestAccountExists tests account existence checking
func TestAccountExists(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail := setupAccountManagementTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Check non-existent account
	exists, err := db.AccountExists(ctx, testEmail)
	assert.NoError(t, err)
	assert.False(t, exists)

	// Test 2: Create account and check existence
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

	// Test 3: Verify account now exists
	exists, err = db.AccountExists(ctx, testEmail)
	assert.NoError(t, err)
	assert.True(t, exists)

	t.Logf("Successfully tested AccountExists with email: %s", testEmail)
}

// TestGetAccountDetails tests retrieving account details
func TestGetAccountDetails(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail := setupAccountManagementTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Create an account first
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

	// Test 2: Get account details
	details, err := db.GetAccountDetails(ctx, testEmail)
	assert.NoError(t, err)
	assert.NotNil(t, details)
	// Note: emails are normalized to lowercase by the server
	expectedEmail := strings.ToLower(testEmail)
	assert.Equal(t, expectedEmail, details.PrimaryEmail)
	assert.Greater(t, details.ID, int64(0))

	// Test 3: Try to get details for non-existent account
	_, err = db.GetAccountDetails(ctx, "nonexistent@example.com")
	assert.Error(t, err)

	t.Logf("Successfully tested GetAccountDetails with email: %s", testEmail)
}

// TestListAccounts tests listing all accounts
func TestListAccounts(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, _ := setupAccountManagementTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: List accounts before creating any
	accounts, err := db.ListAccounts(ctx)
	assert.NoError(t, err)
	initialCount := len(accounts)

	// Test 2: Create a few accounts (each with unique email)
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	// Create 3 separate accounts with different emails
	var createdEmails []string
	for i := 0; i < 3; i++ {
		// Create completely unique emails for separate accounts
		email := fmt.Sprintf("account_%d_%d@example.com", time.Now().UnixNano()/1000000, i)
		createdEmails = append(createdEmails, strings.ToLower(email))

		req := CreateAccountRequest{
			Email:     email,
			Password:  "password123",
			IsPrimary: true, // Each is primary for its own account
			HashType:  "bcrypt",
		}
		err = db.CreateAccount(ctx, tx, req)
		require.NoError(t, err)
	}

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Test 3: List accounts after creating some
	accounts, err = db.ListAccounts(ctx)
	assert.NoError(t, err)
	assert.Len(t, accounts, initialCount+3)

	// Find our test accounts in the list
	var foundAccounts int
	for _, account := range accounts {
		for _, expectedEmail := range createdEmails {
			if account.PrimaryEmail == expectedEmail {
				foundAccounts++
				t.Logf("Found expected account: %s", account.PrimaryEmail)
				break
			}
		}
	}

	assert.Equal(t, 3, foundAccounts)

	t.Logf("Successfully tested ListAccounts with %d total accounts", len(accounts))
}
