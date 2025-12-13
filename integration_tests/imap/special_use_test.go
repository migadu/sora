//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_ChildrenAttributes(t *testing.T) {
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

	parent := "ChildrenTestParent"
	child := "ChildrenTestParent/Child"

	// Create Parent
	if err := c.Create(parent, nil).Wait(); err != nil {
		t.Fatalf("CREATE parent failed: %v", err)
	}

	// Verify Parent has \HasNoChildren initially
	listCmd := c.List("", parent, nil)
	mboxes, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST parent failed: %v", err)
	}
	if len(mboxes) == 0 {
		t.Fatalf("Parent mailbox not found")
	}

	attrs := mboxes[0].Attrs
	if hasAttr(attrs, imap.MailboxAttrHasChildren) {
		t.Error("Parent should not have \\HasChildren initially")
	}
	if !hasAttr(attrs, imap.MailboxAttrHasNoChildren) {
		t.Error("Parent should have \\HasNoChildren initially")
	}

	// Create Child
	if err := c.Create(child, nil).Wait(); err != nil {
		t.Fatalf("CREATE child failed: %v", err)
	}

	// Verify Parent has \HasChildren now
	listCmd = c.List("", parent, nil)
	mboxes, err = listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST parent after child create failed: %v", err)
	}
	if len(mboxes) == 0 {
		t.Fatalf("Parent mailbox not found")
	}

	attrs = mboxes[0].Attrs
	if !hasAttr(attrs, imap.MailboxAttrHasChildren) {
		t.Error("Parent should have \\HasChildren after child creation")
	}
	if hasAttr(attrs, imap.MailboxAttrHasNoChildren) {
		t.Error("Parent should not have \\HasNoChildren after child creation")
	}

	// Verify Child has \HasNoChildren
	listCmd = c.List("", child, nil)
	mboxes, err = listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST child failed: %v", err)
	}
	if len(mboxes) == 0 {
		t.Fatalf("Child mailbox not found")
	}
	attrs = mboxes[0].Attrs
	if !hasAttr(attrs, imap.MailboxAttrHasNoChildren) {
		t.Error("Child should have \\HasNoChildren")
	}
}

func TestIMAP_SpecialUseAttributes(t *testing.T) {
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

	// Define expected special use attributes for default mailboxes
	expectedAttributes := map[string]imap.MailboxAttr{
		"Sent":   imap.MailboxAttrSent,
		"Drafts": imap.MailboxAttrDrafts,
		"Trash":  imap.MailboxAttrTrash,
		"Junk":   imap.MailboxAttrJunk,
		// Archive behavior might vary, RFC 6154 defines \Archive
	}

	// Check all mailboxes
	listCmd := c.List("", "*", &imap.ListOptions{
		ReturnStatus: &imap.StatusOptions{NumMessages: true}, // Just to use extended options if needed
	})
	mboxes, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST failed: %v", err)
	}

	for _, mbox := range mboxes {
		if expectedAttr, ok := expectedAttributes[mbox.Mailbox]; ok {
			if !hasAttr(mbox.Attrs, expectedAttr) {
				t.Errorf("Mailbox %s missing expected attribute %s. Got: %v", mbox.Mailbox, expectedAttr, mbox.Attrs)
			} else {
				t.Logf("Mailbox %s correctly has attribute %s", mbox.Mailbox, expectedAttr)
			}
		}
	}
}
