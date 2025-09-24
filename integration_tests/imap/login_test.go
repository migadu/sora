//go:build integration

package imap_test

import (
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_LoginAndSelect(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Start log capture to verify no proxy= entries (direct backend connection)
	logCapture := NewLogCapture()
	defer func() {
		logs := logCapture.Stop()
		if strings.Contains(logs, "proxy=") {
			t.Errorf("Expected NO 'proxy=' entries in logs for direct backend connection, but found some. Logs:\n%s", logs)
		} else {
			t.Log("✓ Verified no 'proxy=' entries in logs for direct backend connection")
		}
	}()

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	t.Logf("Connected to IMAP server at %s", server.Address)

	// Test login
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed for user %s: %v", account.Email, err)
	}
	t.Log("Login successful")

	// Test selecting INBOX
	selectCmd := c.Select("INBOX", nil)
	mbox, err := selectCmd.Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	if mbox.NumMessages != 0 {
		t.Errorf("Expected 0 messages in INBOX, got %d", mbox.NumMessages)
	}
	t.Log("INBOX selected successfully")
}

func TestIMAP_InvalidLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Start log capture to verify no proxy= entries (direct backend connection)
	logCapture := NewLogCapture()
	defer func() {
		logs := logCapture.Stop()
		if strings.Contains(logs, "proxy=") {
			t.Errorf("Expected NO 'proxy=' entries in logs for direct backend connection, but found some. Logs:\n%s", logs)
		} else {
			t.Log("✓ Verified no 'proxy=' entries in logs for direct backend connection")
		}
	}()

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	// Test invalid password
	err = c.Login(account.Email, "wrong_password").Wait()
	if err == nil {
		t.Fatal("Expected login to fail with wrong password, but it succeeded")
	}
	t.Logf("Login correctly failed with wrong password: %v", err)

	// Test non-existent user
	err = c.Login("nonexistent@example.com", "password").Wait()
	if err == nil {
		t.Fatal("Expected login to fail with non-existent user, but it succeeded")
	}
	t.Logf("Login correctly failed with non-existent user: %v", err)
}
