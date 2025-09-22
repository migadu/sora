//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_LoginAndSelect(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

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

func TestIMAP_MailboxOperations(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Test LIST command
	listCmd := c.List("", "*", nil)
	mailboxes, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST command failed: %v", err)
	}

	// Should at least have INBOX
	found := false
	for _, mbox := range mailboxes {
		if mbox.Mailbox == "INBOX" {
			found = true
			break
		}
	}
	if !found {
		t.Error("INBOX not found in LIST response")
	}
	t.Logf("LIST returned %d mailboxes", len(mailboxes))

	// Test CREATE mailbox
	testMailbox := "TestFolder"
	if err := c.Create(testMailbox, nil).Wait(); err != nil {
		t.Fatalf("CREATE mailbox failed: %v", err)
	}
	t.Logf("Created mailbox: %s", testMailbox)

	// Verify the mailbox was created
	listCmd = c.List("", "*", nil)
	mailboxes, err = listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST command failed after CREATE: %v", err)
	}

	found = false
	for _, mbox := range mailboxes {
		if mbox.Mailbox == testMailbox {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Created mailbox %s not found in LIST response", testMailbox)
	}

	// Test DELETE mailbox
	if err := c.Delete(testMailbox).Wait(); err != nil {
		t.Fatalf("DELETE mailbox failed: %v", err)
	}
	t.Logf("Deleted mailbox: %s", testMailbox)
}

func TestIMAP_MultipleConnections(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Test multiple concurrent connections
	numConnections := 3
	done := make(chan error, numConnections)

	for i := 0; i < numConnections; i++ {
		go func(connID int) {
			c, err := imapclient.DialInsecure(server.Address, nil)
			if err != nil {
				done <- fmt.Errorf("connection %d: failed to dial: %v", connID, err)
				return
			}
			defer c.Logout()

			if err := c.Login(account.Email, account.Password).Wait(); err != nil {
				done <- fmt.Errorf("connection %d: login failed: %v", connID, err)
				return
			}

			// Select INBOX
			if _, err := c.Select("INBOX", nil).Wait(); err != nil {
				done <- fmt.Errorf("connection %d: select failed: %v", connID, err)
				return
			}

			// Create a unique mailbox for this connection
			testMailbox := fmt.Sprintf("Test%d", connID)
			if err := c.Create(testMailbox, nil).Wait(); err != nil {
				done <- fmt.Errorf("connection %d: create mailbox failed: %v", connID, err)
				return
			}

			// Clean up
			if err := c.Delete(testMailbox).Wait(); err != nil {
				done <- fmt.Errorf("connection %d: delete mailbox failed: %v", connID, err)
				return
			}

			done <- nil
		}(i)
	}

	// Wait for all connections to complete
	for i := 0; i < numConnections; i++ {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
	t.Logf("Successfully handled %d concurrent connections", numConnections)
}

func TestIMAP_IdleCommand(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Test IDLE command
	idleCmd, err := c.Idle()
	if err != nil {
		// Check if IDLE is supported
		if strings.Contains(err.Error(), "IDLE") || strings.Contains(err.Error(), "not supported") {
			t.Skip("IDLE command not supported by server")
		}
		t.Fatalf("IDLE command failed to start: %v", err)
	}
	t.Log("IDLE command started")

	// Give it a moment to idle
	time.Sleep(100 * time.Millisecond)

	if err := idleCmd.Close(); err != nil {
		t.Fatalf("Failed to stop IDLE: %v", err)
	}
	t.Log("IDLE command executed and stopped successfully")
}

func TestIMAP_Capabilities(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	// Test CAPABILITY command
	caps, err := c.Capability().Wait()
	if err != nil {
		t.Fatalf("CAPABILITY command failed: %v", err)
	}

	// Check for required capabilities
	requiredCaps := []string{"IMAP4rev1"}
	for _, required := range requiredCaps {
		if !caps.Has(imap.Cap(required)) {
			t.Errorf("Required capability %s not found", required)
		}
	}

	var capsList []string
	for c := range caps {
		capsList = append(capsList, string(c))
	}

	t.Logf("Server capabilities: %v", capsList)
}

func TestIMAP_ConnectionReuse(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Test multiple operations on the same connection
	for i := 0; i < 5; i++ {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server iteration %d: %v", i+1, err)
		}

		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			c.Close()
			t.Fatalf("Login %d failed: %v", i+1, err)
		}

		if _, err := c.Select("INBOX", nil).Wait(); err != nil {
			c.Close()
			t.Fatalf("Select %d failed: %v", i+1, err)
		}

		// Test logout and re-login
		if err := c.Logout().Wait(); err != nil {
			// Logout might fail if server closes connection first, which is ok.
			t.Logf("Logout %d returned an error (might be expected): %v", i+1, err)
		}
	}

	t.Log("Connection reuse test completed successfully")
}
