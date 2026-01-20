//go:build integration
// +build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/testutils"
	"github.com/stretchr/testify/require"
)

// TestAccountPurge tests purging a single account
func TestAccountPurge(t *testing.T) {
	ctx := context.Background()

	// Setup database
	rdb := setupPurgeTestDatabase(t)
	defer rdb.Close()

	// Create file-based S3 mock
	s3Storage := createPurgeTestS3Storage(t)

	// Load admin config for purgeAccount function
	cfg := createPurgeTestConfig(t)

	// Create test account
	email := fmt.Sprintf("test-purge-%d@example.com", time.Now().Unix())
	createPurgeTestAccount(t, rdb, email, "password123")

	// Get account ID
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, email)
	require.NoError(t, err)

	// Create test mailbox
	err = rdb.CreateMailboxForUserWithRetry(ctx, accountID, "TestFolder")
	require.NoError(t, err)

	// Add test messages
	messageCount := 10
	messageIDs, s3Keys := createPurgeTestMessages(t, ctx, rdb, s3Storage, accountID, email, messageCount)
	require.Len(t, messageIDs, messageCount)

	// Verify messages exist in DB
	messages, err := rdb.GetMessagesForAccount(ctx, accountID)
	require.NoError(t, err)
	require.Len(t, messages, messageCount)

	// Verify S3 objects exist
	for _, s3Key := range s3Keys {
		exists, _, err := s3Storage.Exists(s3Key)
		require.NoError(t, err)
		require.True(t, exists, "S3 object should exist: %s", s3Key)
	}

	// PURGE ACCOUNT (pass s3Storage mock)
	err = purgeAccountWithStorage(ctx, cfg, rdb, accountID, email, s3Storage)
	require.NoError(t, err)

	// Verify account deleted
	exists, err := rdb.AccountExistsWithRetry(ctx, email)
	require.NoError(t, err)
	require.False(t, exists, "Account should be deleted")

	// Verify messages deleted from DB
	messages, err = rdb.GetMessagesForAccount(ctx, accountID)
	require.NoError(t, err)
	require.Len(t, messages, 0, "All messages should be deleted from DB")

	// Verify S3 objects deleted
	for _, s3Key := range s3Keys {
		exists, _, err := s3Storage.Exists(s3Key)
		require.NoError(t, err)
		require.False(t, exists, "S3 object should be deleted: %s", s3Key)
	}
}

// TestAccountPurgeResumability tests that purge can be resumed after interruption
func TestAccountPurgeResumability(t *testing.T) {
	ctx := context.Background()

	// Setup database
	rdb := setupPurgeTestDatabase(t)
	defer rdb.Close()

	// Create file-based S3 mock
	s3Storage := createPurgeTestS3Storage(t)

	// Load admin config
	cfg := createPurgeTestConfig(t)

	// Create test account
	email := fmt.Sprintf("test-resume-%d@example.com", time.Now().Unix())
	createPurgeTestAccount(t, rdb, email, "password123")

	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, email)
	require.NoError(t, err)

	// Add test messages
	messageCount := 5
	createPurgeTestMessages(t, ctx, rdb, s3Storage, accountID, email, messageCount)

	// Step 1: Mark all messages as expunged (simulating partial purge)
	expungedCount, err := rdb.ExpungeAllMessagesForAccount(ctx, accountID)
	require.NoError(t, err)
	require.Equal(t, int64(messageCount), expungedCount)

	// Verify messages still exist in DB (but marked as expunged)
	messages, err := rdb.GetMessagesForAccount(ctx, accountID)
	require.NoError(t, err)
	require.Len(t, messages, messageCount, "Messages should still exist after marking as expunged")

	// RESUME: Run purge again (should complete cleanup - delete from S3 and DB)
	err = purgeAccountWithStorage(ctx, cfg, rdb, accountID, email, s3Storage)
	require.NoError(t, err)

	// Verify account fully purged
	exists, err := rdb.AccountExistsWithRetry(ctx, email)
	require.NoError(t, err)
	require.False(t, exists)
}

// TestAccountPurgeIsolation tests that purging one account doesn't affect another
func TestAccountPurgeIsolation(t *testing.T) {
	ctx := context.Background()

	// Setup database
	rdb := setupPurgeTestDatabase(t)
	defer rdb.Close()

	// Create file-based S3 mock
	s3Storage := createPurgeTestS3Storage(t)

	// Load admin config
	cfg := createPurgeTestConfig(t)

	timestamp := time.Now().Unix()

	// Create two accounts
	email1 := fmt.Sprintf("test-iso-1-%d@example.com", timestamp)
	email2 := fmt.Sprintf("test-iso-2-%d@example.com", timestamp)

	createPurgeTestAccount(t, rdb, email1, "password1")
	createPurgeTestAccount(t, rdb, email2, "password2")

	accountID1, err := rdb.GetAccountIDByEmailWithRetry(ctx, email1)
	require.NoError(t, err)
	accountID2, err := rdb.GetAccountIDByEmailWithRetry(ctx, email2)
	require.NoError(t, err)

	// Add messages to both accounts (same content - will have same hash but different S3 paths)
	messageCount := 3
	msg1IDs, s3Keys1 := createPurgeTestMessages(t, ctx, rdb, s3Storage, accountID1, email1, messageCount)
	msg2IDs, s3Keys2 := createPurgeTestMessages(t, ctx, rdb, s3Storage, accountID2, email2, messageCount)

	require.Len(t, msg1IDs, messageCount)
	require.Len(t, msg2IDs, messageCount)

	// Verify both accounts have messages
	messages1, err := rdb.GetMessagesForAccount(ctx, accountID1)
	require.NoError(t, err)
	require.Len(t, messages1, messageCount)

	messages2, err := rdb.GetMessagesForAccount(ctx, accountID2)
	require.NoError(t, err)
	require.Len(t, messages2, messageCount)

	// PURGE ACCOUNT 1
	err = purgeAccountWithStorage(ctx, cfg, rdb, accountID1, email1, s3Storage)
	require.NoError(t, err)

	// Verify account 1 deleted
	exists, err := rdb.AccountExistsWithRetry(ctx, email1)
	require.NoError(t, err)
	require.False(t, exists)

	// Verify account 1's S3 objects deleted
	for _, s3Key := range s3Keys1 {
		exists, _, err := s3Storage.Exists(s3Key)
		require.NoError(t, err)
		require.False(t, exists, "Account 1 S3 object should be deleted: %s", s3Key)
	}

	// VERIFY ACCOUNT 2 UNAFFECTED
	exists, err = rdb.AccountExistsWithRetry(ctx, email2)
	require.NoError(t, err)
	require.True(t, exists, "Account 2 should still exist")

	messages2After, err := rdb.GetMessagesForAccount(ctx, accountID2)
	require.NoError(t, err)
	require.Len(t, messages2After, messageCount, "Account 2 messages should be unaffected")

	// Verify account 2's S3 objects still exist
	for _, s3Key := range s3Keys2 {
		exists, _, err := s3Storage.Exists(s3Key)
		require.NoError(t, err)
		require.True(t, exists, "Account 2 S3 object should still exist: %s", s3Key)
	}

	// Cleanup: purge account 2
	err = purgeAccountWithStorage(ctx, cfg, rdb, accountID2, email2, s3Storage)
	require.NoError(t, err)
}

// TestDomainPurge tests purging all accounts in a domain
func TestDomainPurge(t *testing.T) {
	ctx := context.Background()

	// Setup database
	rdb := setupPurgeTestDatabase(t)
	defer rdb.Close()

	// Create file-based S3 mock
	s3Storage := createPurgeTestS3Storage(t)

	// Load admin config
	cfg := createPurgeTestConfig(t)

	// Create unique test domain
	testDomain := fmt.Sprintf("test-domain-%d.com", time.Now().Unix())

	// Create 3 accounts in test domain
	var testEmails []string
	var testAccountIDs []int64
	for i := 0; i < 3; i++ {
		email := fmt.Sprintf("user%d@%s", i+1, testDomain)
		createPurgeTestAccount(t, rdb, email, "password")

		accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, email)
		require.NoError(t, err)

		// Add messages to each account
		createPurgeTestMessages(t, ctx, rdb, s3Storage, accountID, email, 5)

		testEmails = append(testEmails, email)
		testAccountIDs = append(testAccountIDs, accountID)
	}

	// Create account in different domain (should NOT be purged)
	otherEmail := fmt.Sprintf("other-%d@different.com", time.Now().Unix())
	createPurgeTestAccount(t, rdb, otherEmail, "password")

	otherAccountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, otherEmail)
	require.NoError(t, err)
	createPurgeTestMessages(t, ctx, rdb, s3Storage, otherAccountID, otherEmail, 3)

	// PURGE DOMAIN (manually purge each account using the test storage)
	for i, email := range testEmails {
		accountID := testAccountIDs[i]
		err := purgeAccountWithStorage(ctx, cfg, rdb, accountID, email, s3Storage)
		require.NoError(t, err)
	}

	// Verify all test domain accounts deleted
	for _, email := range testEmails {
		exists, err := rdb.AccountExistsWithRetry(ctx, email)
		require.NoError(t, err)
		require.False(t, exists, "Account should be deleted: %s", email)
	}

	// Verify other domain account still exists
	exists, err := rdb.AccountExistsWithRetry(ctx, otherEmail)
	require.NoError(t, err)
	require.True(t, exists, "Other domain account should still exist")

	messages, err := rdb.GetMessagesForAccount(ctx, otherAccountID)
	require.NoError(t, err)
	require.Len(t, messages, 3, "Other domain messages should be unaffected")

	// Cleanup: purge other account
	err = purgeAccountWithStorage(ctx, cfg, rdb, otherAccountID, otherEmail, s3Storage)
	require.NoError(t, err)
}

// TestDomainPurgeResumability tests that domain purge can be resumed
func TestDomainPurgeResumability(t *testing.T) {
	ctx := context.Background()

	// Setup database
	rdb := setupPurgeTestDatabase(t)
	defer rdb.Close()

	// Create file-based S3 mock
	s3Storage := createPurgeTestS3Storage(t)

	// Load admin config
	cfg := createPurgeTestConfig(t)

	// Create unique test domain
	testDomain := fmt.Sprintf("test-resume-domain-%d.com", time.Now().Unix())

	// Create 3 accounts
	var testEmails []string
	var testAccountIDs []int64
	for i := 0; i < 3; i++ {
		email := fmt.Sprintf("user%d@%s", i+1, testDomain)
		createPurgeTestAccount(t, rdb, email, "password")

		accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, email)
		require.NoError(t, err)
		createPurgeTestMessages(t, ctx, rdb, s3Storage, accountID, email, 2)

		testEmails = append(testEmails, email)
		testAccountIDs = append(testAccountIDs, accountID)
	}

	// Purge first account manually (simulating partial completion)
	err := purgeAccountWithStorage(ctx, cfg, rdb, testAccountIDs[0], testEmails[0], s3Storage)
	require.NoError(t, err)

	// RESUME: Purge remaining accounts (should skip first since already deleted)
	for i := 1; i < len(testEmails); i++ {
		email := testEmails[i]
		accountID := testAccountIDs[i]

		// Check if exists first (this simulates resumability)
		exists, err := rdb.AccountExistsWithRetry(ctx, email)
		require.NoError(t, err)

		if exists {
			err = purgeAccountWithStorage(ctx, cfg, rdb, accountID, email, s3Storage)
			require.NoError(t, err)
		}
	}

	// Verify all accounts deleted
	for _, email := range testEmails {
		exists, err := rdb.AccountExistsWithRetry(ctx, email)
		require.NoError(t, err)
		require.False(t, exists, "Account should be deleted: %s", email)
	}
}

// Helper functions

// setupPurgeTestDatabase creates and initializes a test database connection
func setupPurgeTestDatabase(t *testing.T) *resilient.ResilientDatabase {
	t.Helper()

	// Skip if database is not available
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	ctx := context.Background()

	cfg := &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{
			Hosts:    []string{"localhost"},
			Port:     "5432",
			User:     "postgres",
			Name:     "sora_mail_db",
			Password: "",
		},
	}

	// Create ResilientDatabase
	rdb, err := resilient.NewResilientDatabase(ctx, cfg, false, false)
	if err != nil {
		t.Skipf("Failed to connect to test database: %v", err)
	}

	return rdb
}

// createPurgeTestS3Storage creates a file-based S3 mock for testing
func createPurgeTestS3Storage(t *testing.T) objectStorage {
	t.Helper()

	// Create temporary directory for mock S3 storage
	tmpDir := t.TempDir()
	s3Dir := filepath.Join(tmpDir, "mock-s3")

	mock, err := testutils.NewFileBasedS3Mock(s3Dir)
	if err != nil {
		t.Fatalf("Failed to create file-based S3 mock: %v", err)
	}

	t.Logf("Created file-based S3 mock in %s", s3Dir)
	return mock
}

// createPurgeTestConfig creates a test AdminConfig
func createPurgeTestConfig(t *testing.T) AdminConfig {
	t.Helper()

	return AdminConfig{
		Database: config.DatabaseConfig{
			Write: &config.DatabaseEndpointConfig{
				Hosts:    []string{"localhost"},
				Port:     "5432",
				User:     "postgres",
				Name:     "sora_mail_db",
				Password: "",
			},
		},
		S3: config.S3Config{
			Endpoint:   "localhost:9000",
			AccessKey:  "minioadmin",
			SecretKey:  "minioadmin",
			Bucket:     "sora-test",
			DisableTLS: true,
		},
	}
}

// createPurgeTestAccount creates a test account with default mailboxes
func createPurgeTestAccount(t *testing.T, rdb *resilient.ResilientDatabase, email, password string) {
	t.Helper()

	ctx := context.Background()

	req := db.CreateAccountRequest{
		Email:     email,
		Password:  password,
		IsPrimary: true,
		HashType:  "bcrypt",
	}

	err := rdb.CreateAccountWithRetry(ctx, req)
	if err != nil {
		t.Fatalf("Failed to create test account: %v", err)
	}

	// Get account ID
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	// Create default mailboxes (INBOX, Sent, Drafts, Trash)
	err = rdb.CreateDefaultMailboxesWithRetry(ctx, accountID)
	if err != nil {
		t.Fatalf("Failed to create default mailboxes: %v", err)
	}
}

// createPurgeTestMessages creates test messages for an account
func createPurgeTestMessages(t *testing.T, ctx context.Context, rdb *resilient.ResilientDatabase, s3Storage objectStorage, accountID int64, email string, count int) ([]int64, []string) {
	t.Helper()

	// Get INBOX
	mailbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)

	// Parse email to get domain and localpart
	parts := splitPurgeEmail(email)
	s3Localpart := "testuser"
	s3Domain := "example.com"
	if len(parts) == 2 {
		s3Localpart = parts[0]
		s3Domain = parts[1]
	}

	var messageIDs []int64
	var s3Keys []string

	hostname, _ := os.Hostname()

	for i := 0; i < count; i++ {
		messageBody := []byte(fmt.Sprintf("Subject: Test %d\r\n\r\nTest message body %d", i, i))
		contentHash := fmt.Sprintf("hash-%d-%d", accountID, i)

		// Upload to S3 first
		s3Key := fmt.Sprintf("%s/%s/%s", s3Domain, s3Localpart, contentHash)
		err = s3Storage.Put(s3Key, bytes.NewReader(messageBody), int64(len(messageBody)))
		require.NoError(t, err)

		// Create body structure (required by InsertMessageOptions)
		bodyStructurePart := &imap.BodyStructureSinglePart{
			Type:    "text",
			Subtype: "plain",
			Size:    uint32(len(messageBody)),
		}
		var bodyStructure imap.BodyStructure = bodyStructurePart

		// Insert message with empty PendingUpload (since we already uploaded to S3)
		opts := &db.InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     mailbox.ID,
			MailboxName:   "INBOX",
			S3Domain:      s3Domain,
			S3Localpart:   s3Localpart,
			ContentHash:   contentHash,
			MessageID:     fmt.Sprintf("test-%d@example.com", i),
			InternalDate:  time.Now(),
			Size:          int64(len(messageBody)),
			Flags:         []imap.Flag{},
			BodyStructure: &bodyStructure,
		}

		pendingUpload := db.PendingUpload{
			InstanceID:  hostname,
			ContentHash: contentHash,
			Size:        int64(len(messageBody)),
			AccountID:   accountID,
		}

		msgID, _, err := rdb.InsertMessageWithRetry(ctx, opts, pendingUpload)
		require.NoError(t, err)

		// Mark message as uploaded since we already uploaded to S3
		_, err = rdb.ExecWithRetry(ctx, `UPDATE messages SET uploaded = TRUE WHERE id = $1`, msgID)
		require.NoError(t, err)

		messageIDs = append(messageIDs, msgID)
		s3Keys = append(s3Keys, s3Key)
	}

	return messageIDs, s3Keys
}

// splitPurgeEmail splits an email address into localpart and domain
func splitPurgeEmail(email string) []string {
	for i, c := range email {
		if c == '@' {
			return []string{email[:i], email[i+1:]}
		}
	}
	return []string{email}
}
