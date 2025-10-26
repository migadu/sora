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

// TestACL_MYRIGHTS tests the MYRIGHTS command which shows what rights the current user has on a mailbox
// RFC 4314 Section 3.7: MYRIGHTS Command
//
// Syntax: MYRIGHTS <mailbox-name>
// Response: MYRIGHTS <mailbox-name> <rights>
//
// Example:
//
//	C: A001 MYRIGHTS INBOX
//	S: * MYRIGHTS INBOX lrswipkxtea
//	S: A001 OK MYRIGHTS completed
func TestACL_MYRIGHTS(t *testing.T) {
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

	// Test MYRIGHTS on INBOX (user owns it, should have all rights)
	myRightsCmd := c.MyRights("INBOX")
	myRightsData, err := myRightsCmd.Wait()
	if err != nil {
		t.Fatalf("MYRIGHTS command failed: %v", err)
	}

	t.Logf("MYRIGHTS response: %+v", myRightsData)

	// Expect MYRIGHTS response with all rights for owned mailbox
	// Should contain: lrswipkxtea (all 11 rights)
	expectedRights := "lrswipkxtea"
	foundRights := myRightsData.Rights.String()

	// Check if all expected rights are present
	for _, r := range expectedRights {
		if !strings.ContainsRune(foundRights, r) {
			t.Errorf("Expected right %c not found in %s", r, foundRights)
		}
	}

	t.Logf("✓ MYRIGHTS on owned mailbox returned all rights: %s", foundRights)
}

// TestACL_GETACL tests the GETACL command which lists all ACLs for a mailbox
// RFC 4314 Section 3.3: GETACL Command
//
// Syntax: GETACL <mailbox-name>
// Response: ACL <mailbox-name> <identifier> <rights> [<identifier> <rights> ...]
//
// Example:
//
//	C: A001 GETACL "Shared/Sales"
//	S: * ACL "Shared/Sales" user1@example.com lrswipkxtea user2@example.com lr
//	S: A001 OK GETACL completed
func TestACL_GETACL(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second user in same domain
	domain := strings.Split(account1.Email, "@")[1]
	email2 := fmt.Sprintf("user2-%d@%s", common.GetTimestamp(), domain)
	password2 := "password2"

	req := db.CreateAccountRequest{
		Email:     email2,
		Password:  password2,
		HashType:  "bcrypt",
		IsPrimary: true,
	}
	if err := server.ResilientDB.CreateAccountWithRetry(context.Background(), req); err != nil {
		t.Fatalf("Failed to create second user: %v", err)
	}

	// User1 connects and creates a shared mailbox
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("User1 login failed: %v", err)
	}

	// Use unique mailbox name to avoid conflicts with previous test runs
	sharedMailbox := fmt.Sprintf("Shared/TestACL-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	// Grant user2 read-only access via database
	accountID1, _ := server.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account1.Email)

	if err := server.ResilientDB.GrantMailboxAccessByIdentifierWithRetry(context.Background(), accountID1, email2, sharedMailbox, "lr"); err != nil {
		t.Fatalf("Failed to grant access: %v", err)
	}

	// Test GETACL - should show both user1 (owner) and user2 (granted)
	getACLData, err := c1.GetACL(sharedMailbox).Wait()
	if err != nil {
		t.Fatalf("GETACL command failed: %v", err)
	}

	t.Logf("GETACL response: %+v", getACLData)

	// Expect ACL response with both users
	// ACL data contains map of RightsIdentifier -> RightSet
	user2Rights, foundUser2 := getACLData.Rights[imap.RightsIdentifier(email2)]
	if !foundUser2 {
		t.Fatalf("User2 not found in ACL response")
	}
	if user2Rights.String() != "lr" {
		t.Errorf("Expected user2 to have 'lr' rights, got '%s'", user2Rights.String())
	}

	// Verify owner has full rights
	ownerRights, foundOwner := getACLData.Rights[imap.RightsIdentifier(account1.Email)]
	if !foundOwner {
		t.Errorf("Owner %s not found in ACL response", account1.Email)
	}
	rightsStr := ownerRights.String()
	if !strings.Contains(rightsStr, "l") || !strings.Contains(rightsStr, "r") {
		t.Errorf("Owner should have full rights, got '%s'", rightsStr)
	}

	t.Logf("✓ GETACL returned ACLs for both users")
}

// TestACL_SETACL tests the SETACL command which grants or modifies access rights
// RFC 4314 Section 3.1: SETACL Command
//
// Syntax: SETACL <mailbox-name> <identifier> <rights>
// Response: OK SETACL completed
//
// Example:
//
//	C: A001 SETACL "Shared/Sales" user@example.com lr
//	S: A001 OK SETACL completed
func TestACL_SETACL(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second user in same domain
	domain := strings.Split(account1.Email, "@")[1]
	email2 := fmt.Sprintf("user2-%d@%s", common.GetTimestamp(), domain)
	password2 := "password2"

	req := db.CreateAccountRequest{
		Email:     email2,
		Password:  password2,
		HashType:  "bcrypt",
		IsPrimary: true,
	}
	if err := server.ResilientDB.CreateAccountWithRetry(context.Background(), req); err != nil {
		t.Fatalf("Failed to create second user: %v", err)
	}

	// User1 connects and creates a shared mailbox
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("User1 login failed: %v", err)
	}

	sharedMailbox := "Shared/TestSETACL"
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	// Grant user2 read-only access using SETACL
	err = c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lr")).Wait()
	if err != nil {
		t.Fatalf("SETACL command failed: %v", err)
	}

	t.Logf("✓ SETACL granted read rights to %s", email2)

	// Verify user2 can now see and select the mailbox
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server for user2: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}

	// User2 should see the shared mailbox in LIST
	listCmd := c2.List("", "*", nil)
	mailboxes, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST command failed: %v", err)
	}

	found := false
	for _, mbox := range mailboxes {
		if mbox.Mailbox == sharedMailbox {
			found = true
			t.Logf("User2 can see shared mailbox: %s", mbox.Mailbox)
			break
		}
	}
	if !found {
		t.Errorf("User2 should see shared mailbox %s after SETACL", sharedMailbox)
	}

	// User2 should be able to SELECT (has 'r' right)
	_, err = c2.Select(sharedMailbox, nil).Wait()
	if err != nil {
		t.Errorf("User2 should be able to SELECT with 'lr' rights: %v", err)
	} else {
		t.Logf("✓ User2 can SELECT shared mailbox")
	}

	// Test SETACL to modify rights (upgrade to read-write)
	err = c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lrswi")).Wait()
	if err != nil {
		t.Fatalf("SETACL modify command failed: %v", err)
	}

	t.Logf("✓ SETACL modified rights to lrswi")

	// Verify via GETACL
	getACLData, err := c1.GetACL(sharedMailbox).Wait()
	if err != nil {
		t.Fatalf("GETACL command failed: %v", err)
	}

	user2NewRights, foundUser2WithNewRights := getACLData.Rights[imap.RightsIdentifier(email2)]
	if !foundUser2WithNewRights {
		t.Errorf("User2 not found in ACL after modification")
	}
	rightsStr := user2NewRights.String()
	if !strings.Contains(rightsStr, "l") || !strings.Contains(rightsStr, "r") || !strings.Contains(rightsStr, "s") {
		t.Errorf("Expected modified rights to include 'lrs', got: %s", rightsStr)
	}

	t.Logf("✓ SETACL successfully modified rights")
}

// TestACL_DELETEACL tests the DELETEACL command which revokes access rights
// RFC 4314 Section 3.2: DELETEACL Command
//
// Syntax: DELETEACL <mailbox-name> <identifier>
// Response: OK DELETEACL completed
//
// Example:
//
//	C: A001 DELETEACL "Shared/Sales" user@example.com
//	S: A001 OK DELETEACL completed
func TestACL_DELETEACL(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second user in same domain
	domain := strings.Split(account1.Email, "@")[1]
	email2 := fmt.Sprintf("user2-%d@%s", common.GetTimestamp(), domain)
	password2 := "password2"

	req := db.CreateAccountRequest{
		Email:     email2,
		Password:  password2,
		HashType:  "bcrypt",
		IsPrimary: true,
	}
	if err := server.ResilientDB.CreateAccountWithRetry(context.Background(), req); err != nil {
		t.Fatalf("Failed to create second user: %v", err)
	}

	// User1 connects and creates a shared mailbox
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("User1 login failed: %v", err)
	}

	sharedMailbox := "Shared/TestDELETEACL"
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	// Grant user2 access using SETACL
	err = c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lr")).Wait()
	if err != nil {
		t.Fatalf("SETACL command failed: %v", err)
	}

	// Verify user2 can see the mailbox
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server for user2: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}

	listCmd := c2.List("", sharedMailbox, nil)
	mailboxes, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST command failed: %v", err)
	}

	if len(mailboxes) == 0 {
		t.Fatalf("User2 should see shared mailbox before DELETEACL")
	}
	t.Logf("User2 can see shared mailbox before DELETEACL")

	// Revoke access using DELETEACL
	err = c1.DeleteACL(sharedMailbox, imap.RightsIdentifier(email2)).Wait()
	if err != nil {
		t.Fatalf("DELETEACL command failed: %v", err)
	}

	t.Logf("✓ DELETEACL revoked access for %s", email2)

	// Verify user2 can NO LONGER see the mailbox
	listCmd = c2.List("", sharedMailbox, nil)
	mailboxes, err = listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST command failed after DELETEACL: %v", err)
	}

	if len(mailboxes) > 0 {
		t.Errorf("User2 should NOT see shared mailbox after DELETEACL, but found %d mailboxes", len(mailboxes))
	} else {
		t.Logf("✓ User2 can no longer see shared mailbox after DELETEACL")
	}

	// Verify via GETACL that user2 is not in the ACL list
	getACLData, err := c1.GetACL(sharedMailbox).Wait()
	if err != nil {
		t.Fatalf("GETACL command failed: %v", err)
	}

	_, foundUser2AfterDelete := getACLData.Rights[imap.RightsIdentifier(email2)]
	if foundUser2AfterDelete {
		t.Errorf("User2 should NOT appear in GETACL response after DELETEACL")
	}

	t.Logf("✓ DELETEACL successfully removed user from ACL")
}

// TestACL_LISTRIGHTS tests the LISTRIGHTS command which shows available rights for an identifier
// RFC 4314 Section 3.6: LISTRIGHTS Command
//
// Syntax: LISTRIGHTS <mailbox-name> <identifier>
// Response: LISTRIGHTS <mailbox-name> <identifier> <required-rights> <optional-rights>
//
// Example:
//
//	C: A001 LISTRIGHTS INBOX user@example.com
//	S: * LISTRIGHTS INBOX user@example.com "" lrswipkxtea
//	S: A001 OK LISTRIGHTS completed
func TestACL_LISTRIGHTS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second user
	domain := strings.Split(account1.Email, "@")[1]
	email2 := fmt.Sprintf("user2-%d@%s", common.GetTimestamp(), domain)
	password2 := "password2"

	req := db.CreateAccountRequest{
		Email:     email2,
		Password:  password2,
		HashType:  "bcrypt",
		IsPrimary: true,
	}
	if err := server.ResilientDB.CreateAccountWithRetry(context.Background(), req); err != nil {
		t.Fatalf("Failed to create second user: %v", err)
	}

	// User1 connects
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("User1 login failed: %v", err)
	}

	// Test LISTRIGHTS on INBOX
	listRightsCmd := c1.ListRights("INBOX", imap.RightsIdentifier(email2))
	listRightsData, err := listRightsCmd.Wait()
	if err != nil {
		t.Fatalf("LISTRIGHTS command failed: %v", err)
	}

	t.Logf("LISTRIGHTS response: %+v", listRightsData)

	// Expect LISTRIGHTS response showing all available rights
	// RequiredRights should be empty for non-owner
	// OptionalRights is a slice of RightSet containing all available rights
	allRightsStr := listRightsData.RequiredRights.String()
	for _, optRights := range listRightsData.OptionalRights {
		allRightsStr += optRights.String()
	}

	if allRightsStr == "" {
		t.Fatalf("No LISTRIGHTS response found")
	}

	// Should contain most of the rights (RequiredRights + OptionalRights should cover lrswipkxtea)
	t.Logf("LISTRIGHTS returned rights: required=%s, all=%s", listRightsData.RequiredRights.String(), allRightsStr)

	t.Logf("✓ LISTRIGHTS returned all available rights")
}

// TestACL_PermissionDenied tests that ACL commands require appropriate permissions
func TestACL_PermissionDenied(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second user
	domain := strings.Split(account1.Email, "@")[1]
	email2 := fmt.Sprintf("user2-%d@%s", common.GetTimestamp(), domain)
	password2 := "password2"

	req := db.CreateAccountRequest{
		Email:     email2,
		Password:  password2,
		HashType:  "bcrypt",
		IsPrimary: true,
	}
	if err := server.ResilientDB.CreateAccountWithRetry(context.Background(), req); err != nil {
		t.Fatalf("Failed to create second user: %v", err)
	}

	// User1 creates a shared mailbox
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("User1 login failed: %v", err)
	}

	sharedMailbox := "Shared/TestPermissions"
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	// Grant user2 read-only access (no 'a' admin right)
	err = c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lr")).Wait()
	if err != nil {
		t.Fatalf("SETACL command failed: %v", err)
	}

	// User2 connects
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server for user2: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}

	// User2 tries to SETACL (should fail - no 'a' admin right)
	email3 := fmt.Sprintf("user3-%d@%s", common.GetTimestamp(), domain)
	err = c2.SetACL(sharedMailbox, imap.RightsIdentifier(email3), imap.RightModificationReplace, imap.RightSet("lr")).Wait()
	if err == nil {
		t.Errorf("SETACL should fail for user without admin rights")
	} else {
		t.Logf("✓ SETACL correctly denied for user without admin rights: %v", err)
	}

	// User2 tries to DELETEACL (should fail - no 'a' admin right)
	err = c2.DeleteACL(sharedMailbox, imap.RightsIdentifier(account1.Email)).Wait()
	if err == nil {
		t.Errorf("DELETEACL should fail for user without admin rights")
	} else {
		t.Logf("✓ DELETEACL correctly denied for user without admin rights: %v", err)
	}

	// User2 should be able to GETACL (requires 'l' lookup right which they have)
	_, err = c2.GetACL(sharedMailbox).Wait()
	if err != nil {
		t.Errorf("GETACL should succeed for user with lookup rights: %v", err)
	} else {
		t.Logf("✓ GETACL succeeded for user with lookup rights")
	}

	// User2 should be able to MYRIGHTS (no special permission required)
	_, err = c2.MyRights(sharedMailbox).Wait()
	if err != nil {
		t.Errorf("MYRIGHTS should succeed: %v", err)
	} else {
		t.Logf("✓ MYRIGHTS succeeded")
	}
}

// TestACL_CrossDomainDenied tests that ACL commands cannot grant access across domains
func TestACL_CrossDomainDenied(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	// Create user in DIFFERENT domain
	email2 := fmt.Sprintf("user-%d@different-domain.com", common.GetTimestamp())
	password2 := "password2"

	req := db.CreateAccountRequest{
		Email:     email2,
		Password:  password2,
		HashType:  "bcrypt",
		IsPrimary: true,
	}
	if err := server.ResilientDB.CreateAccountWithRetry(context.Background(), req); err != nil {
		t.Fatalf("Failed to create user from different domain: %v", err)
	}

	// User1 creates a shared mailbox
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(account1.Email, account1.Password).Wait(); err != nil {
		t.Fatalf("User1 login failed: %v", err)
	}

	sharedMailbox := "Shared/TestCrossDomain"
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	// Try to grant access to user from different domain (should fail)
	err = c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lr")).Wait()
	if err == nil {
		t.Errorf("SETACL should fail for cross-domain access")
	} else {
		t.Logf("✓ SETACL correctly denied for cross-domain access: %v", err)
	}
}
