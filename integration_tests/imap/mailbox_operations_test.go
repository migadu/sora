//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/consts"
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

func TestIMAP_DefaultMailboxVisibility(t *testing.T) {
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

	// Test LIST command - should return all default mailboxes
	listCmd := c.List("", "*", nil)
	listResponse, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST command failed: %v", err)
	}

	// Convert to a map for easier lookup
	listedMailboxes := make(map[string]*imap.ListData)
	for _, mbox := range listResponse {
		listedMailboxes[mbox.Mailbox] = mbox
		t.Logf("LIST: %s (attrs: %v, subscribed: %t)",
			mbox.Mailbox,
			mbox.Attrs,
			hasAttr(mbox.Attrs, imap.MailboxAttrSubscribed))
	}

	// Verify all default mailboxes are present in LIST
	for _, defaultMailbox := range consts.DefaultMailboxes {
		if _, found := listedMailboxes[defaultMailbox]; !found {
			t.Errorf("Default mailbox '%s' not found in LIST response", defaultMailbox)
		}
	}

	// Test LSUB command - should return all subscribed default mailboxes
	lsubOptions := &imap.ListOptions{SelectSubscribed: true}
	lsubCmd := c.List("", "*", lsubOptions)
	lsubResponse, err := lsubCmd.Collect()
	if err != nil {
		t.Fatalf("LSUB command failed: %v", err)
	}

	// Convert to a map for easier lookup
	subscribedMailboxes := make(map[string]*imap.ListData)
	for _, mbox := range lsubResponse {
		subscribedMailboxes[mbox.Mailbox] = mbox
		t.Logf("LSUB: %s (attrs: %v)", mbox.Mailbox, mbox.Attrs)
	}

	// Verify all default mailboxes are present in LSUB (they should be auto-subscribed)
	for _, defaultMailbox := range consts.DefaultMailboxes {
		if _, found := subscribedMailboxes[defaultMailbox]; !found {
			t.Errorf("Default mailbox '%s' not found in LSUB response (should be auto-subscribed)", defaultMailbox)
		}
	}

	// Verify that default mailboxes have the subscribed attribute in LIST response
	for _, defaultMailbox := range consts.DefaultMailboxes {
		if mbox, found := listedMailboxes[defaultMailbox]; found {
			if !hasAttr(mbox.Attrs, imap.MailboxAttrSubscribed) {
				t.Errorf("Default mailbox '%s' should have \\Subscribed attribute in LIST response", defaultMailbox)
			}
		}
	}

	t.Logf("Successfully verified %d default mailboxes are visible in LIST and LSUB", len(consts.DefaultMailboxes))
}

// hasAttr checks if a mailbox attribute list contains a specific attribute
func hasAttr(attrs []imap.MailboxAttr, target imap.MailboxAttr) bool {
	for _, attr := range attrs {
		if attr == target {
			return true
		}
	}
	return false
}
