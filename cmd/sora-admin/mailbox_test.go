//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
)

// TestMailboxCommands tests the sora-admin mailbox commands
func TestMailboxCommands(t *testing.T) {
	// Skip if database is not available
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	// Setup test database
	rdb := setupMailboxTestDatabase(t)
	defer rdb.Close()

	// Create test account with unique email to avoid conflicts
	timestamp := time.Now().UnixNano()
	testEmail := fmt.Sprintf("mailbox-test-%d@example.com", timestamp)
	accountID := createMailboxTestAccount(t, rdb, testEmail, "password123")

	ctx := context.Background()

	t.Run("ListMailboxes_Default", func(t *testing.T) {
		testMailboxList(t, rdb, ctx, accountID, testEmail, 0) // No default mailboxes when using CreateAccountRequest
	})

	t.Run("CreateMailbox", func(t *testing.T) {
		testMailboxCreate(t, rdb, ctx, accountID, "TestFolder")
	})

	t.Run("ListMailboxes_AfterCreate", func(t *testing.T) {
		testMailboxList(t, rdb, ctx, accountID, testEmail, 1) // 0 default + 1 created
	})

	t.Run("CreateNestedMailbox", func(t *testing.T) {
		testMailboxCreate(t, rdb, ctx, accountID, "Projects/2024/Q1")
	})

	t.Run("RenameMailbox", func(t *testing.T) {
		testMailboxRename(t, rdb, ctx, accountID, "TestFolder", "WorkFolder")
	})

	t.Run("SubscribeToMailbox", func(t *testing.T) {
		testMailboxSubscribe(t, rdb, ctx, accountID, testEmail, "WorkFolder")
	})

	t.Run("UnsubscribeFromMailbox", func(t *testing.T) {
		testMailboxUnsubscribe(t, rdb, ctx, accountID, testEmail, "WorkFolder")
	})

	t.Run("DeleteMailbox", func(t *testing.T) {
		testMailboxDelete(t, rdb, ctx, accountID, "WorkFolder")
	})

	t.Run("ListMailboxes_AfterDelete", func(t *testing.T) {
		// Should have: Projects/2024/Q1 only (parent folders are created automatically)
		testMailboxList(t, rdb, ctx, accountID, testEmail, 1)
	})

	t.Log("✅ All mailbox command tests passed!")
}

func testMailboxCreate(t *testing.T, rdb *resilient.ResilientDatabase, ctx context.Context, accountID int64, mailboxName string) {
	t.Helper()

	// Create mailbox using database directly
	err := rdb.CreateMailboxWithRetry(ctx, accountID, mailboxName, nil)
	if err != nil {
		t.Fatalf("Failed to create mailbox '%s': %v", mailboxName, err)
	}

	t.Logf("✅ Successfully created mailbox: %s", mailboxName)
}

func testMailboxList(t *testing.T, rdb *resilient.ResilientDatabase, ctx context.Context, accountID int64, email string, expectedCount int) {
	t.Helper()

	// Get mailboxes using database directly
	mailboxes, err := rdb.GetMailboxesWithRetry(ctx, accountID, false)
	if err != nil {
		t.Fatalf("Failed to get mailboxes: %v", err)
	}

	mailboxCount := len(mailboxes)
	if mailboxCount != expectedCount {
		t.Errorf("Expected %d mailboxes, got %d", expectedCount, mailboxCount)
		for i, mbox := range mailboxes {
			t.Logf("  [%d] %s", i, mbox.Name)
		}
	}

	t.Logf("✅ Listed %d mailboxes for %s", mailboxCount, email)
}

func testMailboxRename(t *testing.T, rdb *resilient.ResilientDatabase, ctx context.Context, accountID int64, oldName, newName string) {
	t.Helper()

	// Get the mailbox to rename
	mbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, oldName)
	if err != nil {
		t.Fatalf("Failed to get mailbox '%s': %v", oldName, err)
	}

	// Rename mailbox using database directly
	err = rdb.RenameMailboxWithRetry(ctx, mbox.ID, accountID, newName, nil)
	if err != nil {
		t.Fatalf("Failed to rename mailbox from '%s' to '%s': %v", oldName, newName, err)
	}

	t.Logf("✅ Successfully renamed mailbox from '%s' to '%s'", oldName, newName)
}

func testMailboxSubscribe(t *testing.T, rdb *resilient.ResilientDatabase, ctx context.Context, accountID int64, email, mailboxName string) {
	t.Helper()

	// Get the mailbox to subscribe to
	mbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
	if err != nil {
		t.Fatalf("Failed to get mailbox '%s': %v", mailboxName, err)
	}

	// Subscribe to mailbox using database directly
	err = rdb.SetMailboxSubscribedWithRetry(ctx, mbox.ID, accountID, true)
	if err != nil {
		t.Fatalf("Failed to subscribe to mailbox '%s': %v", mailboxName, err)
	}

	t.Logf("✅ Successfully subscribed to mailbox: %s", mailboxName)
}

func testMailboxUnsubscribe(t *testing.T, rdb *resilient.ResilientDatabase, ctx context.Context, accountID int64, email, mailboxName string) {
	t.Helper()

	// Get the mailbox to unsubscribe from
	mbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
	if err != nil {
		t.Fatalf("Failed to get mailbox '%s': %v", mailboxName, err)
	}

	// Unsubscribe from mailbox using database directly
	err = rdb.SetMailboxSubscribedWithRetry(ctx, mbox.ID, accountID, false)
	if err != nil {
		t.Fatalf("Failed to unsubscribe from mailbox '%s': %v", mailboxName, err)
	}

	t.Logf("✅ Successfully unsubscribed from mailbox: %s", mailboxName)
}

func testMailboxDelete(t *testing.T, rdb *resilient.ResilientDatabase, ctx context.Context, accountID int64, mailboxName string) {
	t.Helper()

	// Get the mailbox to delete
	mbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
	if err != nil {
		t.Fatalf("Failed to get mailbox '%s': %v", mailboxName, err)
	}

	// Delete mailbox using database directly
	err = rdb.DeleteMailboxWithRetry(ctx, mbox.ID, accountID)
	if err != nil {
		t.Fatalf("Failed to delete mailbox '%s': %v", mailboxName, err)
	}

	t.Logf("✅ Successfully deleted mailbox: %s", mailboxName)
}

// setupMailboxTestDatabase sets up a test database connection
func setupMailboxTestDatabase(t *testing.T) *resilient.ResilientDatabase {
	t.Helper()

	// Load test configuration
	var cfg AdminConfig
	if _, err := toml.DecodeFile("../../config-test.toml", &cfg); err != nil {
		t.Fatalf("Failed to load test configuration: %v", err)
	}

	// Create resilient database connection
	ctx := context.Background()
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		t.Fatalf("Failed to create resilient database: %v", err)
	}

	return rdb
}

// createMailboxTestAccount creates a test account
func createMailboxTestAccount(t *testing.T, rdb *resilient.ResilientDatabase, email, password string) int64 {
	t.Helper()

	ctx := context.Background()

	// Create account request
	req := db.CreateAccountRequest{
		Email:     email,
		Password:  password,
		HashType:  "bcrypt",
		IsPrimary: true,
	}

	// Create account
	err := rdb.CreateAccountWithRetry(ctx, req)
	if err != nil {
		t.Fatalf("Failed to create test account: %v", err)
	}

	// Get account ID
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	t.Logf("Created test account: %s (ID: %d)", email, accountID)
	return accountID
}
