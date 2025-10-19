//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// TestACL_ChildMailboxInheritance tests that child mailboxes inherit ACLs from parent
func TestACL_ChildMailboxInheritance(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second user in same domain
	domain := "example.com"
	email1 := account1.Email
	email2 := fmt.Sprintf("user2-%d@%s", common.GetTimestamp(), domain)
	password1 := account1.Password
	password2 := "password2"

	req2 := db.CreateAccountRequest{
		Email:     email2,
		Password:  password2,
		HashType:  "bcrypt",
		IsPrimary: true,
	}
	if err := server.ResilientDB.CreateAccountWithRetry(context.Background(), req2); err != nil {
		t.Fatalf("Failed to create account2: %v", err)
	}

	// Connect as owner
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, password1).Wait(); err != nil {
		t.Fatalf("Failed to login as owner: %v", err)
	}

	// Create parent shared mailbox with unique name
	parentMailbox := fmt.Sprintf("Shared/ProjectA-%d", common.GetTimestamp())
	if err := c1.Create(parentMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create parent mailbox: %v", err)
	}

	// Grant ACL to user2 on parent mailbox
	if err := c1.SetACL(parentMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lrs")).Wait(); err != nil {
		t.Fatalf("Failed to grant ACL to user2: %v", err)
	}

	// Grant ACL to "anyone" on parent mailbox
	if err := c1.SetACL(parentMailbox, imap.RightsIdentifier(db.AnyoneIdentifier), imap.RightModificationReplace, imap.RightSet("lr")).Wait(); err != nil {
		t.Fatalf("Failed to grant ACL to anyone: %v", err)
	}

	// Create child mailbox
	childMailbox := fmt.Sprintf("%s/Documents", parentMailbox)
	if err := c1.Create(childMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create child mailbox: %v", err)
	}

	// Verify child mailbox inherited ACLs from parent
	getACLData, err := c1.GetACL(childMailbox).Wait()
	if err != nil {
		t.Fatalf("Failed to get ACL for child mailbox: %v", err)
	}

	// Check user2's inherited rights
	user2Rights, foundUser2 := getACLData.Rights[imap.RightsIdentifier(email2)]
	if !foundUser2 {
		t.Errorf("Child mailbox should inherit ACL for user2 from parent")
	} else {
		expectedRights := imap.RightSet("lrs")
		if !hasAllRights(user2Rights, expectedRights) {
			t.Errorf("Child mailbox ACL for user2 = %v, want %v", user2Rights, expectedRights)
		}
	}

	// Check "anyone" inherited rights
	anyoneRights, foundAnyone := getACLData.Rights[imap.RightsIdentifier(db.AnyoneIdentifier)]
	if !foundAnyone {
		t.Errorf("Child mailbox should inherit ACL for 'anyone' from parent")
	} else {
		expectedRights := imap.RightSet("lr")
		if !hasAllRights(anyoneRights, expectedRights) {
			t.Errorf("Child mailbox ACL for anyone = %v, want %v", anyoneRights, expectedRights)
		}
	}

	// Connect as user2 and verify access to child mailbox
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server as user2: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("Failed to login as user2: %v", err)
	}

	// User2 should see child mailbox (has 'l' right via inheritance)
	mboxes, err := c2.List("", childMailbox, nil).Collect()
	if err != nil {
		t.Fatalf("Failed to list mailboxes as user2: %v", err)
	}

	if len(mboxes) == 0 {
		t.Errorf("User2 should see child mailbox via inherited ACL")
	}

	// User2 should be able to SELECT child mailbox (has 'r' right via inheritance)
	_, err = c2.Select(childMailbox, nil).Wait()
	if err != nil {
		t.Errorf("User2 should be able to SELECT child mailbox via inherited ACL: %v", err)
	}
}

// TestACL_ChildMailboxInheritance_NoParent tests that mailboxes without parent don't inherit
func TestACL_ChildMailboxInheritance_NoParent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	email1 := account1.Email
	password1 := account1.Password

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, password1).Wait(); err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	// Create top-level shared mailbox (no parent)
	mailbox := fmt.Sprintf("Shared/TopLevel-%d", common.GetTimestamp())
	if err := c1.Create(mailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create mailbox: %v", err)
	}

	// Get ACL - should only have creator's rights, no inherited ACLs
	getACLData, err := c1.GetACL(mailbox).Wait()
	if err != nil {
		t.Fatalf("Failed to get ACL: %v", err)
	}

	// Should only have owner's ACL entry
	if len(getACLData.Rights) != 1 {
		t.Errorf("Top-level mailbox should only have owner's ACL, got %d entries", len(getACLData.Rights))
	}

	ownerRights, found := getACLData.Rights[imap.RightsIdentifier(email1)]
	if !found {
		t.Errorf("Owner should have ACL entry")
	} else if !hasAllRights(ownerRights, imap.RightSet("lrswipkxtea")) {
		t.Errorf("Owner should have full rights, got %v", ownerRights)
	}
}

// TestACL_ChildMailboxInheritance_ModifyParent tests that modifying parent ACL doesn't affect existing children
func TestACL_ChildMailboxInheritance_ModifyParent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second user in same domain
	domain := "example.com"
	email1 := account1.Email
	email2 := fmt.Sprintf("user2-%d@%s", common.GetTimestamp(), domain)
	password1 := account1.Password
	password2 := "password2"

	req2 := db.CreateAccountRequest{
		Email:     email2,
		Password:  password2,
		HashType:  "bcrypt",
		IsPrimary: true,
	}
	if err := server.ResilientDB.CreateAccountWithRetry(context.Background(), req2); err != nil {
		t.Fatalf("Failed to create account2: %v", err)
	}

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, password1).Wait(); err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	// Create parent mailbox
	parentMailbox := fmt.Sprintf("Shared/ProjectB-%d", common.GetTimestamp())
	if err := c1.Create(parentMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create parent mailbox: %v", err)
	}

	// Grant ACL to user2 on parent
	if err := c1.SetACL(parentMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lr")).Wait(); err != nil {
		t.Fatalf("Failed to grant ACL: %v", err)
	}

	// Create child mailbox (inherits "lr" rights for user2)
	childMailbox := fmt.Sprintf("%s/Files", parentMailbox)
	if err := c1.Create(childMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create child mailbox: %v", err)
	}

	// Modify parent ACL to add more rights
	if err := c1.SetACL(parentMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lrswi")).Wait(); err != nil {
		t.Fatalf("Failed to modify parent ACL: %v", err)
	}

	// Child mailbox should still have original inherited rights (lr), not modified rights
	getACLData, err := c1.GetACL(childMailbox).Wait()
	if err != nil {
		t.Fatalf("Failed to get child ACL: %v", err)
	}

	user2Rights, found := getACLData.Rights[imap.RightsIdentifier(email2)]
	if !found {
		t.Errorf("Child mailbox should have ACL for user2")
	} else {
		expectedRights := imap.RightSet("lr")
		if !hasAllRights(user2Rights, expectedRights) {
			t.Errorf("Child mailbox ACL should remain unchanged = %v, want %v", user2Rights, expectedRights)
		}
		// Should NOT have the newly added rights
		if hasAllRights(user2Rights, imap.RightSet("swi")) {
			t.Errorf("Child mailbox should not inherit changes made after creation")
		}
	}
}

// Helper function to check if actual rights contain all expected rights
func hasAllRights(actual, expected imap.RightSet) bool {
	for _, right := range expected {
		found := false
		for _, r := range actual {
			if r == right {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
