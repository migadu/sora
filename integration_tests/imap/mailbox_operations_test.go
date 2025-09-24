//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

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
