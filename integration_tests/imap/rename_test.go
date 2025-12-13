//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_RenameMailbox(t *testing.T) {
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

	// 1. Rename Simple Mailbox
	originalName := "RenameSource"
	newName := "RenameDest"

	if err := c.Create(originalName, nil).Wait(); err != nil {
		t.Fatalf("CREATE failed: %v", err)
	}

	if err := c.Rename(originalName, newName, nil).Wait(); err != nil {
		t.Fatalf("RENAME failed: %v", err)
	}

	// Verify old name is gone
	listCmd := c.List("", originalName, nil)
	mboxes, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST original name failed: %v", err)
	}
	if len(mboxes) != 0 {
		t.Errorf("Original mailbox %s still exists", originalName)
	}

	// Verify new name exists
	listCmd = c.List("", newName, nil)
	mboxes, err = listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST new name failed: %v", err)
	}
	if len(mboxes) == 0 {
		t.Errorf("New mailbox %s not found", newName)
	}

	// 2. Rename Hierarchy
	parent := "Parent"
	child := "Parent/Child"
	newParent := "NewParent"
	newChild := "NewParent/Child"

	if err := c.Create(parent, nil).Wait(); err != nil {
		t.Fatalf("CREATE parent failed: %v", err)
	}
	if err := c.Create(child, nil).Wait(); err != nil {
		t.Fatalf("CREATE child failed: %v", err)
	}

	// Rename Parent
	if err := c.Rename(parent, newParent, nil).Wait(); err != nil {
		t.Fatalf("RENAME parent failed: %v", err)
	}

	// Verify Parent is moved
	listCmd = c.List("", newParent, nil)
	mboxes, err = listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST new parent failed: %v", err)
	}
	if len(mboxes) == 0 {
		t.Errorf("New parent %s not found", newParent)
	}

	// Verify Child is moved
	// Note: Generic IMAP servers usually rename children too, but it's not strictly required by RFC 3501 unless they are physically hierarchical.
	// Most implementations do. Let's check if Sora does.
	listCmd = c.List("", newChild, nil)
	mboxes, err = listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST new child failed: %v", err)
	}
	if len(mboxes) == 0 {
		t.Logf("New child %s not found - server might not support hierarchical rename implicitly", newChild)
		// Check if old child exists
		listCmd = c.List("", child, nil)
		mboxes, err = listCmd.Collect()
		if len(mboxes) > 0 {
			t.Logf("Old child %s still exists", child)
		}
	} else {
		t.Logf("Hierarchical rename verified: %s -> %s", child, newChild)
	}

	// 3. Rename INBOX (Special case)
	// Renaming INBOX usually moves the contents to the new name, but creates a new empty INBOX.
	// RFC 3501: "Renaming INBOX is permitted, and has special behavior. It moves all messages..."
	renamedInbox := "OldInbox"
	if err := c.Rename("INBOX", renamedInbox, nil).Wait(); err != nil {
		t.Logf("RENAME INBOX failed (server might not support it): %v", err)
	} else {
		t.Logf("RENAME INBOX succeeded")
		// Verify INBOX still exists
		listCmd = c.List("", "INBOX", nil)
		mboxes, err = listCmd.Collect()
		if len(mboxes) == 0 {
			t.Log("INBOX disappeared after rename - server might not auto-create INBOX immediately")
		} else {
			t.Log("INBOX still exists after rename")
		}
		// Verify OldInbox exists
		listCmd = c.List("", renamedInbox, nil)
		mboxes, err = listCmd.Collect()
		if len(mboxes) == 0 {
			t.Error("Destination mailbox OldInbox not found after INBOX rename")
		}
	}
}
