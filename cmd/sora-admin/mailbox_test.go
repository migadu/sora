//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
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
	createMailboxTestAccount(t, rdb, testEmail, "password123")

	t.Run("ListMailboxes_Default", func(t *testing.T) {
		testMailboxList(t, testEmail, 0) // No default mailboxes when using CreateAccountRequest
	})

	t.Run("CreateMailbox", func(t *testing.T) {
		testMailboxCreate(t, testEmail, "TestFolder")
	})

	t.Run("ListMailboxes_AfterCreate", func(t *testing.T) {
		testMailboxList(t, testEmail, 1) // 0 default + 1 created
	})

	t.Run("CreateNestedMailbox", func(t *testing.T) {
		testMailboxCreate(t, testEmail, "Projects/2024/Q1")
	})

	t.Run("RenameMailbox", func(t *testing.T) {
		testMailboxRename(t, testEmail, "TestFolder", "WorkFolder")
	})

	t.Run("SubscribeToMailbox", func(t *testing.T) {
		testMailboxSubscribe(t, testEmail, "WorkFolder")
	})

	t.Run("UnsubscribeFromMailbox", func(t *testing.T) {
		testMailboxUnsubscribe(t, testEmail, "WorkFolder")
	})

	t.Run("DeleteMailbox", func(t *testing.T) {
		testMailboxDelete(t, testEmail, "WorkFolder")
	})

	t.Run("ListMailboxes_AfterDelete", func(t *testing.T) {
		// Should have: Projects/2024/Q1 only (parent folders are created automatically)
		testMailboxList(t, testEmail, 1)
	})

	t.Log("✅ All mailbox command tests passed!")
}

func testMailboxCreate(t *testing.T, email, mailboxName string) {
	t.Helper()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Prepare test args
	os.Args = []string{
		"sora-admin",
		"mailbox",
		"create",
		"--config", "../../config-test.toml",
		"--email", email,
		"--mailbox", mailboxName,
	}

	// Run command
	ctx := context.Background()
	handleMailboxCreate(ctx)

	// Restore stdout and read output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output
	if !strings.Contains(output, "Successfully created mailbox") {
		t.Errorf("Expected success message, got: %s", output)
	}
	if !strings.Contains(output, mailboxName) {
		t.Errorf("Expected mailbox name '%s' in output, got: %s", mailboxName, output)
	}

	t.Logf("✅ Successfully created mailbox: %s", mailboxName)
}

func testMailboxList(t *testing.T, email string, expectedCount int) {
	t.Helper()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Prepare test args
	os.Args = []string{
		"sora-admin",
		"mailbox",
		"list",
		"--config", "../../config-test.toml",
		"--email", email,
	}

	// Run command
	ctx := context.Background()
	handleMailboxList(ctx)

	// Restore stdout and read output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Check if no mailboxes found
	if strings.Contains(output, "No mailboxes found") {
		if expectedCount != 0 {
			t.Errorf("Expected %d mailboxes, got 0. Output:\n%s", expectedCount, output)
		}
		t.Logf("✅ Listed 0 mailboxes for %s", email)
		return
	}

	// Count mailboxes (lines with UID Validity numbers, excluding the header)
	lines := strings.Split(output, "\n")
	mailboxCount := 0
	for _, line := range lines {
		// Skip header lines, empty lines, and the "Mailboxes for" line
		if strings.Contains(line, "Subscribed") || strings.Contains(line, "----") ||
			strings.Contains(line, "Mailboxes for") || len(strings.TrimSpace(line)) == 0 {
			continue
		}
		// Check if line has mailbox data (contains Yes/No for subscribed status)
		if strings.Contains(line, "Yes") || strings.Contains(line, "No") {
			mailboxCount++
		}
	}

	if mailboxCount != expectedCount {
		t.Errorf("Expected %d mailboxes, got %d. Output:\n%s", expectedCount, mailboxCount, output)
	}

	t.Logf("✅ Listed %d mailboxes for %s", mailboxCount, email)
}

func testMailboxRename(t *testing.T, email, oldName, newName string) {
	t.Helper()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Prepare test args
	os.Args = []string{
		"sora-admin",
		"mailbox",
		"rename",
		"--config", "../../config-test.toml",
		"--email", email,
		"--old-name", oldName,
		"--new-name", newName,
	}

	// Run command
	ctx := context.Background()
	handleMailboxRename(ctx)

	// Restore stdout and read output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output
	if !strings.Contains(output, "Successfully renamed mailbox") {
		t.Errorf("Expected success message, got: %s", output)
	}
	if !strings.Contains(output, oldName) || !strings.Contains(output, newName) {
		t.Errorf("Expected old name '%s' and new name '%s' in output, got: %s", oldName, newName, output)
	}

	t.Logf("✅ Successfully renamed mailbox from '%s' to '%s'", oldName, newName)
}

func testMailboxSubscribe(t *testing.T, email, mailboxName string) {
	t.Helper()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Prepare test args
	os.Args = []string{
		"sora-admin",
		"mailbox",
		"subscribe",
		"--config", "../../config-test.toml",
		"--email", email,
		"--mailbox", mailboxName,
	}

	// Run command
	ctx := context.Background()
	handleMailboxSubscribe(ctx)

	// Restore stdout and read output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output
	if !strings.Contains(output, "Successfully subscribed") {
		t.Errorf("Expected success message, got: %s", output)
	}

	t.Logf("✅ Successfully subscribed to mailbox: %s", mailboxName)
}

func testMailboxUnsubscribe(t *testing.T, email, mailboxName string) {
	t.Helper()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Prepare test args
	os.Args = []string{
		"sora-admin",
		"mailbox",
		"unsubscribe",
		"--config", "../../config-test.toml",
		"--email", email,
		"--mailbox", mailboxName,
	}

	// Run command
	ctx := context.Background()
	handleMailboxUnsubscribe(ctx)

	// Restore stdout and read output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output
	if !strings.Contains(output, "Successfully unsubscribed") {
		t.Errorf("Expected success message, got: %s", output)
	}

	t.Logf("✅ Successfully unsubscribed from mailbox: %s", mailboxName)
}

func testMailboxDelete(t *testing.T, email, mailboxName string) {
	t.Helper()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Prepare test args
	os.Args = []string{
		"sora-admin",
		"mailbox",
		"delete",
		"--config", "../../config-test.toml",
		"--email", email,
		"--mailbox", mailboxName,
		"--confirm",
	}

	// Run command
	ctx := context.Background()
	handleMailboxDelete(ctx)

	// Restore stdout and read output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify output
	if !strings.Contains(output, "Successfully deleted mailbox") {
		t.Errorf("Expected success message, got: %s", output)
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
