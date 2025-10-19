//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/aclservice"
)

// TestACLCommands tests the sora-admin ACL grant, list, and revoke commands
func TestACLCommands(t *testing.T) {
	// Skip if database is not available
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	// Setup test database
	rdb := setupACLTestDatabase(t)
	defer rdb.Close()

	// Create test accounts with unique emails to avoid conflicts
	timestamp := time.Now().UnixNano()
	owner := createACLTestAccount(t, rdb, fmt.Sprintf("owner-%d@example.com", timestamp), "password123")
	user1 := createACLTestAccount(t, rdb, fmt.Sprintf("user1-%d@example.com", timestamp), "password123")

	// Create a shared mailbox
	ctx := context.Background()
	cfg := &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{
			Enabled:         true,
			NamespacePrefix: "Shared/",
		},
	}
	ctx = context.WithValue(ctx, "config", cfg)

	mailboxName := "Shared/TestMailbox"
	err := rdb.CreateMailboxWithRetry(ctx, owner.AccountID, mailboxName, nil)
	if err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}

	t.Run("GrantACL", func(t *testing.T) {
		testACLGrant(t, rdb, owner.Email, user1.Email, mailboxName)
	})

	t.Run("ListACL", func(t *testing.T) {
		testACLList(t, rdb, owner.Email, mailboxName, user1.Email)
	})

	t.Run("GrantACL_Anyone", func(t *testing.T) {
		testACLGrantAnyone(t, rdb, owner.Email, mailboxName)
	})

	t.Run("ListACL_WithAnyone", func(t *testing.T) {
		testACLListWithAnyone(t, rdb, owner.Email, mailboxName, user1.Email)
	})

	t.Run("RevokeACL", func(t *testing.T) {
		testACLRevoke(t, rdb, owner.Email, user1.Email, mailboxName)
	})

	t.Run("ListACL_AfterRevoke", func(t *testing.T) {
		testACLListAfterRevoke(t, rdb, owner.Email, mailboxName, user1.Email)
	})

	// Skip error case tests because they call os.Exit(1) which terminates the test process
	// Error handling is already tested in the HTTP API integration tests

	t.Log("✅ All ACL command tests passed!")
}

func testACLGrant(t *testing.T, rdb *resilient.ResilientDatabase, ownerEmail, userEmail, mailboxName string) {
	t.Helper()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Prepare test args
	os.Args = []string{
		"sora-admin",
		"acl",
		"grant",
		"--config", "../../config-test.toml",
		"--email", ownerEmail,
		"--mailbox", mailboxName,
		"--identifier", userEmail,
		"--rights", "lrs",
	}

	// Run command
	ctx := context.Background()
	handleACLCommand(ctx)

	// Restore stdout and capture output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	t.Logf("Grant ACL output: %s", output)

	// Verify that the grant was successful by checking database via aclservice
	aclSvc := aclservice.New(rdb)
	acls, err := aclSvc.List(context.Background(), ownerEmail, mailboxName)
	if err != nil {
		t.Fatalf("Failed to get ACLs: %v", err)
	}

	found := false
	for _, acl := range acls {
		if acl.Identifier == userEmail && acl.Rights == "lrs" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected ACL entry for %s with rights 'lrs', but not found", userEmail)
	}
}

func testACLList(t *testing.T, rdb *resilient.ResilientDatabase, ownerEmail, mailboxName, userEmail string) {
	t.Helper()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Prepare test args
	os.Args = []string{
		"sora-admin",
		"acl",
		"list",
		"--config", "../../config-test.toml",
		"--email", ownerEmail,
		"--mailbox", mailboxName,
	}

	// Run command
	ctx := context.Background()
	handleACLCommand(ctx)

	// Restore stdout and capture output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	t.Logf("List ACL output: %s", output)

	// Verify output contains the granted user
	if !bytes.Contains([]byte(output), []byte(userEmail)) {
		t.Errorf("Expected list output to contain %s, but it didn't", userEmail)
	}

	if !bytes.Contains([]byte(output), []byte("lrs")) {
		t.Errorf("Expected list output to contain rights 'lrs', but it didn't")
	}
}

func testACLGrantAnyone(t *testing.T, rdb *resilient.ResilientDatabase, ownerEmail, mailboxName string) {
	t.Helper()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Prepare test args
	os.Args = []string{
		"sora-admin",
		"acl",
		"grant",
		"--config", "../../config-test.toml",
		"--email", ownerEmail,
		"--mailbox", mailboxName,
		"--identifier", "anyone",
		"--rights", "lr",
	}

	// Run command
	ctx := context.Background()
	handleACLCommand(ctx)

	// Restore stdout and capture output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	t.Logf("Grant 'anyone' ACL output: %s", output)

	// Verify that the grant was successful via aclservice
	aclSvc := aclservice.New(rdb)
	acls, err := aclSvc.List(context.Background(), ownerEmail, mailboxName)
	if err != nil {
		t.Fatalf("Failed to get ACLs: %v", err)
	}

	found := false
	for _, acl := range acls {
		if acl.Identifier == "anyone" && acl.Rights == "lr" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected ACL entry for 'anyone' with rights 'lr', but not found")
	}
}

func testACLListWithAnyone(t *testing.T, rdb *resilient.ResilientDatabase, ownerEmail, mailboxName, userEmail string) {
	t.Helper()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Prepare test args
	os.Args = []string{
		"sora-admin",
		"acl",
		"list",
		"--config", "../../config-test.toml",
		"--email", ownerEmail,
		"--mailbox", mailboxName,
	}

	// Run command
	ctx := context.Background()
	handleACLCommand(ctx)

	// Restore stdout and capture output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	t.Logf("List ACL with 'anyone' output: %s", output)

	// Verify output contains both user and 'anyone'
	if !bytes.Contains([]byte(output), []byte(userEmail)) {
		t.Errorf("Expected list output to contain %s", userEmail)
	}

	if !bytes.Contains([]byte(output), []byte("anyone")) {
		t.Errorf("Expected list output to contain 'anyone'")
	}
}

func testACLRevoke(t *testing.T, rdb *resilient.ResilientDatabase, ownerEmail, userEmail, mailboxName string) {
	t.Helper()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Prepare test args
	os.Args = []string{
		"sora-admin",
		"acl",
		"revoke",
		"--config", "../../config-test.toml",
		"--email", ownerEmail,
		"--mailbox", mailboxName,
		"--identifier", userEmail,
	}

	// Run command
	ctx := context.Background()
	handleACLCommand(ctx)

	// Restore stdout and capture output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	t.Logf("Revoke ACL output: %s", output)

	// Verify that the revoke was successful via aclservice
	aclSvc := aclservice.New(rdb)
	acls, err := aclSvc.List(context.Background(), ownerEmail, mailboxName)
	if err != nil {
		t.Fatalf("Failed to get ACLs: %v", err)
	}

	for _, acl := range acls {
		if acl.Identifier == userEmail {
			t.Errorf("Expected ACL entry for %s to be removed, but it still exists", userEmail)
		}
	}
}

func testACLListAfterRevoke(t *testing.T, rdb *resilient.ResilientDatabase, ownerEmail, mailboxName, userEmail string) {
	t.Helper()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Prepare test args
	os.Args = []string{
		"sora-admin",
		"acl",
		"list",
		"--config", "../../config-test.toml",
		"--email", ownerEmail,
		"--mailbox", mailboxName,
	}

	// Run command
	ctx := context.Background()
	handleACLCommand(ctx)

	// Restore stdout and capture output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	t.Logf("List ACL after revoke output: %s", output)

	// Verify output does not contain the revoked user
	if bytes.Contains([]byte(output), []byte(userEmail)) {
		t.Errorf("Expected list output to not contain %s after revoke, but it did", userEmail)
	}

	// Verify 'anyone' still exists
	if !bytes.Contains([]byte(output), []byte("anyone")) {
		t.Errorf("Expected list output to still contain 'anyone' after revoking user")
	}
}

// Helper functions

func setupACLTestDatabase(t *testing.T) *resilient.ResilientDatabase {
	t.Helper()

	// Load test configuration - use adminConfig structure instead of full config
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile("../../config-test.toml", &cfg); err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	// Create database connection
	ctx := context.Background()
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	return rdb
}

type TestAccount struct {
	Email     string
	AccountID int64
}

func createACLTestAccount(t *testing.T, rdb *resilient.ResilientDatabase, email, password string) TestAccount {
	t.Helper()

	ctx := context.Background()

	// Create account with credential
	req := db.CreateAccountRequest{
		Email:     email,
		Password:  password,
		HashType:  "bcrypt",
		IsPrimary: true,
	}

	err := rdb.CreateAccountWithRetry(ctx, req)
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	// Get account ID
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	return TestAccount{
		Email:     email,
		AccountID: accountID,
	}
}
