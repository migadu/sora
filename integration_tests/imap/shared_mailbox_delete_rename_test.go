//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// TestSharedMailbox_DeleteWithChildren tests the bug where deleting a shared mailbox
// with children incorrectly reports "has children" error when the requester is not the owner.
func TestSharedMailbox_DeleteWithChildren(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second user in same domain
	domain := strings.Split(owner.Email, "@")[1]
	user2Email := fmt.Sprintf("user2-%d@%s", common.GetTimestamp(), domain)
	user2Password := "password2"

	req := db.CreateAccountRequest{
		Email:     user2Email,
		Password:  user2Password,
		HashType:  "bcrypt",
		IsPrimary: true,
	}
	if err := server.ResilientDB.CreateAccountWithRetry(context.Background(), req); err != nil {
		t.Fatalf("Failed to create second user: %v", err)
	}

	user2 := common.TestAccount{Email: user2Email, Password: user2Password}

	// Connect as owner and create shared mailbox hierarchy
	ownerConn, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server as owner: %v", err)
	}
	defer ownerConn.Logout()

	if err := ownerConn.Login(owner.Email, owner.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	// Create parent and child shared mailboxes
	parentMailbox := "Shared/TestParent"
	childMailbox := "Shared/TestParent/Child"
	leafMailbox := "Shared/TestLeaf"

	if err := ownerConn.Create(parentMailbox, nil).Wait(); err != nil {
		t.Fatalf("CREATE parent mailbox failed: %v", err)
	}
	if err := ownerConn.Create(childMailbox, nil).Wait(); err != nil {
		t.Fatalf("CREATE child mailbox failed: %v", err)
	}
	if err := ownerConn.Create(leafMailbox, nil).Wait(); err != nil {
		t.Fatalf("CREATE leaf mailbox failed: %v", err)
	}

	// Grant user2 delete rights ('x') on all mailboxes
	if err := ownerConn.SetACL(parentMailbox, imap.RightsIdentifier(user2.Email), imap.RightModificationReplace, imap.RightSet("lrswipkxtea")).Wait(); err != nil {
		t.Fatalf("SETACL on parent failed: %v", err)
	}
	if err := ownerConn.SetACL(leafMailbox, imap.RightsIdentifier(user2.Email), imap.RightModificationReplace, imap.RightSet("lrswipkxtea")).Wait(); err != nil {
		t.Fatalf("SETACL on leaf failed: %v", err)
	}

	t.Logf("✓ Created shared mailbox hierarchy and granted ACL rights to user2")

	// Connect as user2 and try to delete
	user2Conn, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server as user2: %v", err)
	}
	defer user2Conn.Logout()

	if err := user2Conn.Login(user2.Email, user2.Password).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}

	// BUG: This should fail because parent has children, but it incorrectly
	// returns success because HasChildren check uses requester's AccountID
	// instead of owner's AccountID for shared mailboxes
	err = user2Conn.Delete(parentMailbox).Wait()
	if err == nil {
		t.Errorf("DELETE should have failed because parent has children, but succeeded")
	} else {
		t.Logf("✓ DELETE correctly failed: %v", err)
		// Verify it's the right error message
		if !contains(err.Error(), "has children") && !contains(err.Error(), "children") {
			t.Errorf("Expected 'has children' error, got: %v", err)
		}
	}

	// This should succeed because leaf has no children
	err = user2Conn.Delete(leafMailbox).Wait()
	if err != nil {
		t.Errorf("DELETE leaf mailbox failed: %v (should succeed because it has no children)", err)
	} else {
		t.Logf("✓ DELETE leaf mailbox succeeded")
	}
}

// TestMailbox_RenameCaseSensitivity tests that renaming a mailbox to a name
// that differs only in case from an existing mailbox is properly rejected.
// With case-insensitive mailbox lookups (LOWER on both sides), the system
// prevents both creating case-duplicate mailboxes and renaming into case conflicts.
func TestMailbox_RenameCaseSensitivity(t *testing.T) {
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

	// Create two distinct mailboxes
	mailboxExisting := "testfolder"
	mailboxOther := "otherfolder"

	if err := c.Create(mailboxExisting, nil).Wait(); err != nil {
		t.Fatalf("CREATE %s failed: %v", mailboxExisting, err)
	}
	if err := c.Create(mailboxOther, nil).Wait(); err != nil {
		t.Fatalf("CREATE %s failed: %v", mailboxOther, err)
	}

	t.Logf("✓ Created mailboxes: %s, %s", mailboxExisting, mailboxOther)

	// Verify that creating a case-duplicate is prevented
	err = c.Create("TESTFOLDER", nil).Wait()
	if err == nil {
		t.Errorf("CREATE TESTFOLDER should have failed (case-insensitive duplicate of testfolder)")
	} else {
		t.Logf("✓ CREATE correctly prevented case-duplicate: %v", err)
	}

	// Verify that renaming to a case-insensitive conflict is rejected
	err = c.Rename(mailboxOther, "TestFolder", nil).Wait()
	if err == nil {
		t.Errorf("RENAME should have failed (case-insensitive conflict with testfolder)")
	} else {
		if !contains(err.Error(), "exists") && !contains(err.Error(), "duplicate") && !contains(err.Error(), "unique") {
			t.Errorf("Expected 'already exists' or 'duplicate' error, got: %v", err)
		} else {
			t.Logf("✓ RENAME correctly failed with: %v", err)
		}
	}

	// Verify that renaming to the same name (case-insensitive) is rejected
	err = c.Rename(mailboxExisting, "TESTFOLDER", nil).Wait()
	if err == nil {
		t.Errorf("RENAME to same name (different case) should have failed")
	} else {
		t.Logf("✓ RENAME to same name (different case) correctly failed: %v", err)
	}
}

// TestMailbox_RenameChildConflict tests the bug where renaming a mailbox with children
// fails with "duplicate key violation" when a child's new name would conflict with
// an existing mailbox.
func TestMailbox_RenameChildConflict(t *testing.T) {
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

	// Create a parent with children and a conflicting mailbox
	// Setup: Foo/Bar exists, and we'll rename Foo to Baz
	// But Baz/Bar already exists, which should cause a conflict
	if err := c.Create("Foo", nil).Wait(); err != nil {
		t.Fatalf("CREATE Foo failed: %v", err)
	}
	if err := c.Create("Foo/Bar", nil).Wait(); err != nil {
		t.Fatalf("CREATE Foo/Bar failed: %v", err)
	}
	if err := c.Create("Baz", nil).Wait(); err != nil {
		t.Fatalf("CREATE Baz failed: %v", err)
	}
	if err := c.Create("Baz/Bar", nil).Wait(); err != nil {
		t.Fatalf("CREATE Baz/Bar failed: %v", err)
	}

	t.Logf("✓ Created mailboxes: Foo, Foo/Bar, Baz, Baz/Bar")

	// BUG: This should fail because renaming Foo to Baz would make Foo/Bar become Baz/Bar,
	// which already exists. Without conflict detection, this results in a unique constraint violation.
	err = c.Rename("Foo", "Baz", nil).Wait()
	if err == nil {
		t.Errorf("RENAME should have failed because child would conflict, but succeeded")
	} else {
		t.Logf("✓ RENAME correctly failed: %v", err)
		// Verify it's a meaningful error, not just a database constraint violation
		if contains(err.Error(), "SQLSTATE") || contains(err.Error(), "23505") {
			t.Errorf("Got raw database error instead of user-friendly message: %v", err)
		}
	}
}

// TestSharedMailbox_RenameWithChildren tests renaming a shared mailbox that has children
func TestSharedMailbox_RenameWithChildren(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second user in same domain
	domain := strings.Split(owner.Email, "@")[1]
	user2Email := fmt.Sprintf("user2-%d@%s", common.GetTimestamp(), domain)
	user2Password := "password2"

	req := db.CreateAccountRequest{
		Email:     user2Email,
		Password:  user2Password,
		HashType:  "bcrypt",
		IsPrimary: true,
	}
	if err := server.ResilientDB.CreateAccountWithRetry(context.Background(), req); err != nil {
		t.Fatalf("Failed to create second user: %v", err)
	}

	user2 := common.TestAccount{Email: user2Email, Password: user2Password}

	// Connect as owner and create shared mailbox hierarchy
	ownerConn, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server as owner: %v", err)
	}
	defer ownerConn.Logout()

	if err := ownerConn.Login(owner.Email, owner.Password).Wait(); err != nil {
		t.Fatalf("Owner login failed: %v", err)
	}

	// Create parent and child shared mailboxes
	oldParent := "Shared/OldParent"
	oldChild := "Shared/OldParent/Child"
	newParent := "Shared/NewParent"
	newChild := "Shared/NewParent/Child"

	if err := ownerConn.Create(oldParent, nil).Wait(); err != nil {
		t.Fatalf("CREATE parent mailbox failed: %v", err)
	}
	if err := ownerConn.Create(oldChild, nil).Wait(); err != nil {
		t.Fatalf("CREATE child mailbox failed: %v", err)
	}

	// Grant user2 delete rights ('x') which is required for rename
	if err := ownerConn.SetACL(oldParent, imap.RightsIdentifier(user2.Email), imap.RightModificationReplace, imap.RightSet("lrswipkxtea")).Wait(); err != nil {
		t.Fatalf("SETACL on parent failed: %v", err)
	}

	t.Logf("✓ Created shared mailbox hierarchy")

	// Connect as user2 and try to rename
	user2Conn, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server as user2: %v", err)
	}
	defer user2Conn.Logout()

	if err := user2Conn.Login(user2.Email, user2.Password).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}

	// Rename the parent (this should also rename the child)
	err = user2Conn.Rename(oldParent, newParent, nil).Wait()
	if err != nil {
		t.Fatalf("RENAME shared mailbox failed: %v", err)
	}

	t.Logf("✓ RENAME shared mailbox succeeded")

	// Verify the parent was renamed
	listCmd := user2Conn.List("", newParent, nil)
	mboxes, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST new parent failed: %v", err)
	}
	if len(mboxes) == 0 {
		t.Errorf("New parent %s not found after rename", newParent)
	} else {
		t.Logf("✓ Verified parent renamed to %s", newParent)
	}

	// Verify the child was also renamed (check as owner since user2 might not have access)
	listCmd = ownerConn.List("", newChild, nil)
	mboxes, err = listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST new child failed: %v", err)
	}
	if len(mboxes) == 0 {
		t.Errorf("New child %s not found after rename", newChild)
	} else {
		t.Logf("✓ Verified child renamed to %s", newChild)
	}

	// Verify old names are gone (check as owner)
	listCmd = ownerConn.List("", oldParent, nil)
	mboxes, err = listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST old parent failed: %v", err)
	}
	if len(mboxes) > 0 {
		t.Errorf("Old parent %s still exists after rename", oldParent)
	} else {
		t.Logf("✓ Verified old parent %s is gone", oldParent)
	}
}

// Helper function to check if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && (s[0:len(substr)] == substr ||
			(len(s) > len(substr) && contains(s[1:], substr)))))
}
