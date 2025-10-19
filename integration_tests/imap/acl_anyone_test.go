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

// TestACL_AnyoneIdentifier_BasicGrant tests granting access using "anyone" identifier
func TestACL_AnyoneIdentifier_BasicGrant(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second user in same domain
	domain := "example.com"
	email1 := account1.Email
	email2 := fmt.Sprintf("user2-%d@%s", common.GetTimestamp(), domain)
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

	// User1 connects and creates a shared mailbox
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, account1.Password).Wait(); err != nil {
		t.Fatalf("User1 login failed: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/AnyoneTest-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	// Grant "anyone" read-only access
	err = c1.SetACL(sharedMailbox, imap.RightsIdentifier(db.AnyoneIdentifier), imap.RightModificationReplace, imap.RightSet("lr")).Wait()
	if err != nil {
		t.Fatalf("SETACL for 'anyone' failed: %v", err)
	}
	t.Logf("✓ Granted 'lr' rights to 'anyone'")

	// Verify GETACL shows "anyone" entry
	getACLData, err := c1.GetACL(sharedMailbox).Wait()
	if err != nil {
		t.Fatalf("GETACL failed: %v", err)
	}

	anyoneRights, foundAnyone := getACLData.Rights[imap.RightsIdentifier(db.AnyoneIdentifier)]
	if !foundAnyone {
		t.Fatalf("'anyone' not found in ACL response")
	}
	if anyoneRights.String() != "lr" {
		t.Errorf("Expected 'anyone' to have 'lr' rights, got '%s'", anyoneRights.String())
	}
	t.Logf("✓ GETACL shows 'anyone' with 'lr' rights")

	// User2 connects and should be able to see and select the mailbox
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server for user2: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}

	// User2 should see the mailbox (has 'l' right via "anyone")
	mboxes, err := c2.List("", sharedMailbox, nil).Collect()
	if err != nil {
		t.Fatalf("LIST failed for user2: %v", err)
	}
	if len(mboxes) == 0 {
		t.Errorf("❌ User2 should see mailbox via 'anyone' rights")
	} else {
		t.Logf("✓ User2 can LIST mailbox via 'anyone' rights")
	}

	// User2 should be able to SELECT (has 'r' right via "anyone")
	if _, err := c2.Select(sharedMailbox, nil).Wait(); err != nil {
		t.Errorf("❌ User2 should SELECT mailbox via 'anyone' rights: %v", err)
	} else {
		t.Logf("✓ User2 can SELECT mailbox via 'anyone' rights")
	}

	// User2 should NOT be able to DELETE (no 'x' right)
	if err := c2.Delete(sharedMailbox).Wait(); err == nil {
		t.Errorf("❌ User2 should not DELETE mailbox without 'x' right")
	} else {
		t.Logf("✓ User2 cannot DELETE mailbox (no 'x' right in 'anyone')")
	}

	t.Logf("✓ All 'anyone' identifier basic grant tests passed")
}

// TestACL_AnyoneIdentifier_SameDomainOnly tests that "anyone" is scoped to same domain
func TestACL_AnyoneIdentifier_SameDomainOnly(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	// Create user in different domain
	domain2 := "otherdomain.com"
	email1 := account1.Email // Should be in example.com
	email2 := fmt.Sprintf("user-%d@%s", common.GetTimestamp(), domain2)
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

	// User1 connects and creates a shared mailbox
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, account1.Password).Wait(); err != nil {
		t.Fatalf("User1 login failed: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/AnyoneDomain-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	// Grant "anyone" read access
	err = c1.SetACL(sharedMailbox, imap.RightsIdentifier(db.AnyoneIdentifier), imap.RightModificationReplace, imap.RightSet("lr")).Wait()
	if err != nil {
		t.Fatalf("SETACL for 'anyone' failed: %v", err)
	}

	// User2 from different domain connects
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server for user2: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}

	// User2 should NOT see the mailbox (different domain)
	mboxes, err := c2.List("", sharedMailbox, nil).Collect()
	if err != nil {
		t.Fatalf("LIST failed for user2: %v", err)
	}
	if len(mboxes) > 0 {
		t.Errorf("❌ User2 from different domain should NOT see mailbox with 'anyone' rights")
	} else {
		t.Logf("✓ User2 from different domain cannot see mailbox (same-domain enforcement works)")
	}

	// User2 should NOT be able to SELECT
	if _, err := c2.Select(sharedMailbox, nil).Wait(); err == nil {
		t.Errorf("❌ User2 from different domain should not SELECT mailbox")
	} else {
		t.Logf("✓ User2 from different domain cannot SELECT mailbox")
	}

	t.Logf("✓ 'anyone' same-domain enforcement tests passed")
}

// TestACL_AnyoneIdentifier_ModifyRights tests modifying "anyone" rights
func TestACL_AnyoneIdentifier_ModifyRights(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second user in same domain
	domain := "example.com"
	email1 := account1.Email
	email2 := fmt.Sprintf("user2-%d@%s", common.GetTimestamp(), domain)
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

	// User1 connects and creates a shared mailbox
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, account1.Password).Wait(); err != nil {
		t.Fatalf("User1 login failed: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/AnyoneModify-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	// Grant "anyone" initial rights 'lr'
	err = c1.SetACL(sharedMailbox, imap.RightsIdentifier(db.AnyoneIdentifier), imap.RightModificationReplace, imap.RightSet("lr")).Wait()
	if err != nil {
		t.Fatalf("Initial SETACL failed: %v", err)
	}

	// Add 'i' (insert) right using RightModificationAdd
	err = c1.SetACL(sharedMailbox, imap.RightsIdentifier(db.AnyoneIdentifier), imap.RightModificationAdd, imap.RightSet("i")).Wait()
	if err != nil {
		t.Fatalf("SETACL +i failed: %v", err)
	}
	t.Logf("✓ Added 'i' right to 'anyone'")

	// Verify rights are now 'lri'
	getACLData, err := c1.GetACL(sharedMailbox).Wait()
	if err != nil {
		t.Fatalf("GETACL failed: %v", err)
	}

	anyoneRights := getACLData.Rights[imap.RightsIdentifier(db.AnyoneIdentifier)].String()
	if anyoneRights != "ilr" && anyoneRights != "lri" && anyoneRights != "irl" {
		t.Errorf("Expected 'anyone' to have 'lri' rights (any order), got '%s'", anyoneRights)
	} else {
		t.Logf("✓ 'anyone' rights updated to include 'i': %s", anyoneRights)
	}

	// Remove 'l' right using RightModificationRemove
	err = c1.SetACL(sharedMailbox, imap.RightsIdentifier(db.AnyoneIdentifier), imap.RightModificationRemove, imap.RightSet("l")).Wait()
	if err != nil {
		t.Fatalf("SETACL -l failed: %v", err)
	}
	t.Logf("✓ Removed 'l' right from 'anyone'")

	// Verify rights no longer have 'l'
	getACLData, err = c1.GetACL(sharedMailbox).Wait()
	if err != nil {
		t.Fatalf("GETACL failed: %v", err)
	}

	anyoneRights = getACLData.Rights[imap.RightsIdentifier(db.AnyoneIdentifier)].String()
	for _, r := range anyoneRights {
		if r == 'l' {
			t.Errorf("'anyone' should not have 'l' right after removal, got '%s'", anyoneRights)
		}
	}
	t.Logf("✓ 'anyone' rights after removal: %s (no 'l')", anyoneRights)

	// User2 should NOT see the mailbox now (no 'l' right)
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server for user2: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}

	mboxes, err := c2.List("", sharedMailbox, nil).Collect()
	if err != nil {
		t.Fatalf("LIST failed for user2: %v", err)
	}
	if len(mboxes) > 0 {
		t.Errorf("❌ User2 should not see mailbox without 'l' right")
	} else {
		t.Logf("✓ User2 cannot see mailbox after 'l' right removed from 'anyone'")
	}

	t.Logf("✓ All 'anyone' modify rights tests passed")
}

// TestACL_AnyoneIdentifier_DeleteACL tests deleting "anyone" ACL entry
func TestACL_AnyoneIdentifier_DeleteACL(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second user in same domain
	domain := "example.com"
	email1 := account1.Email
	email2 := fmt.Sprintf("user2-%d@%s", common.GetTimestamp(), domain)
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

	// User1 connects and creates a shared mailbox
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, account1.Password).Wait(); err != nil {
		t.Fatalf("User1 login failed: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/AnyoneDelete-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	// Grant "anyone" rights
	err = c1.SetACL(sharedMailbox, imap.RightsIdentifier(db.AnyoneIdentifier), imap.RightModificationReplace, imap.RightSet("lr")).Wait()
	if err != nil {
		t.Fatalf("SETACL failed: %v", err)
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

	// User2 should see mailbox initially
	mboxes, err := c2.List("", sharedMailbox, nil).Collect()
	if err != nil {
		t.Fatalf("LIST failed for user2: %v", err)
	}
	if len(mboxes) == 0 {
		t.Fatalf("User2 should see mailbox initially")
	}
	t.Logf("✓ User2 can see mailbox with 'anyone' rights")

	// User1 deletes "anyone" ACL
	err = c1.DeleteACL(sharedMailbox, imap.RightsIdentifier(db.AnyoneIdentifier)).Wait()
	if err != nil {
		t.Fatalf("DELETEACL failed: %v", err)
	}
	t.Logf("✓ Deleted 'anyone' ACL entry")

	// Verify GETACL no longer shows "anyone"
	getACLData, err := c1.GetACL(sharedMailbox).Wait()
	if err != nil {
		t.Fatalf("GETACL failed: %v", err)
	}

	_, foundAnyone := getACLData.Rights[imap.RightsIdentifier(db.AnyoneIdentifier)]
	if foundAnyone {
		t.Errorf("'anyone' should not be in ACL after DELETEACL")
	} else {
		t.Logf("✓ 'anyone' removed from ACL")
	}

	// User2 should NOT see mailbox after "anyone" removed
	mboxes, err = c2.List("", sharedMailbox, nil).Collect()
	if err != nil {
		t.Fatalf("LIST failed for user2: %v", err)
	}
	if len(mboxes) > 0 {
		t.Errorf("❌ User2 should not see mailbox after 'anyone' ACL deleted")
	} else {
		t.Logf("✓ User2 cannot see mailbox after 'anyone' ACL deleted")
	}

	t.Logf("✓ All DELETEACL 'anyone' tests passed")
}

// TestACL_AnyoneIdentifier_CombinedWithUserACL tests "anyone" combined with specific user ACLs
func TestACL_AnyoneIdentifier_CombinedWithUserACL(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	// Create two users in same domain
	domain := "example.com"
	email1 := account1.Email
	email2 := fmt.Sprintf("user2-%d@%s", common.GetTimestamp(), domain)
	password2 := "password2"
	email3 := fmt.Sprintf("user3-%d@%s", common.GetTimestamp(), domain)
	password3 := "password3"

	req2 := db.CreateAccountRequest{
		Email:     email2,
		Password:  password2,
		HashType:  "bcrypt",
		IsPrimary: true,
	}
	if err := server.ResilientDB.CreateAccountWithRetry(context.Background(), req2); err != nil {
		t.Fatalf("Failed to create account2: %v", err)
	}

	req3 := db.CreateAccountRequest{
		Email:     email3,
		Password:  password3,
		HashType:  "bcrypt",
		IsPrimary: true,
	}
	if err := server.ResilientDB.CreateAccountWithRetry(context.Background(), req3); err != nil {
		t.Fatalf("Failed to create account3: %v", err)
	}

	// User1 connects and creates a shared mailbox
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, account1.Password).Wait(); err != nil {
		t.Fatalf("User1 login failed: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/Combined-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	// Grant "anyone" read-only access 'lr'
	err = c1.SetACL(sharedMailbox, imap.RightsIdentifier(db.AnyoneIdentifier), imap.RightModificationReplace, imap.RightSet("lr")).Wait()
	if err != nil {
		t.Fatalf("SETACL for 'anyone' failed: %v", err)
	}

	// Grant user2 specific write access 'lrsw'
	err = c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lrsw")).Wait()
	if err != nil {
		t.Fatalf("SETACL for user2 failed: %v", err)
	}

	// Verify both ACLs exist
	getACLData, err := c1.GetACL(sharedMailbox).Wait()
	if err != nil {
		t.Fatalf("GETACL failed: %v", err)
	}

	anyoneRights, foundAnyone := getACLData.Rights[imap.RightsIdentifier(db.AnyoneIdentifier)]
	if !foundAnyone {
		t.Fatalf("'anyone' not found in ACL")
	}
	user2Rights, foundUser2 := getACLData.Rights[imap.RightsIdentifier(email2)]
	if !foundUser2 {
		t.Fatalf("user2 not found in ACL")
	}

	t.Logf("✓ 'anyone' has rights: %s", anyoneRights.String())
	t.Logf("✓ user2 has rights: %s", user2Rights.String())

	// User2 should have write access (specific ACL, not "anyone")
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial for user2: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}

	myRights2, err := c2.MyRights(sharedMailbox).Wait()
	if err != nil {
		t.Fatalf("MYRIGHTS failed for user2: %v", err)
	}

	// User2 should have at least 'lrsw' from specific ACL
	hasWrite := false
	for _, r := range myRights2.Rights {
		if r == 'w' {
			hasWrite = true
			break
		}
	}
	if !hasWrite {
		t.Errorf("User2 should have 'w' right from specific ACL, got: %s", myRights2.Rights.String())
	} else {
		t.Logf("✓ User2 has write access from specific ACL: %s", myRights2.Rights.String())
	}

	// User3 should only have read access from "anyone"
	c3, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial for user3: %v", err)
	}
	defer c3.Logout()

	if err := c3.Login(email3, password3).Wait(); err != nil {
		t.Fatalf("User3 login failed: %v", err)
	}

	myRights3, err := c3.MyRights(sharedMailbox).Wait()
	if err != nil {
		t.Fatalf("MYRIGHTS failed for user3: %v", err)
	}

	// User3 should have 'lr' from "anyone", but not 'w'
	hasWrite = false
	for _, r := range myRights3.Rights {
		if r == 'w' {
			hasWrite = true
			break
		}
	}
	if hasWrite {
		t.Errorf("User3 should not have 'w' right (only 'anyone' rights), got: %s", myRights3.Rights.String())
	} else {
		t.Logf("✓ User3 has read-only access from 'anyone': %s", myRights3.Rights.String())
	}

	t.Logf("✓ All combined ACL tests passed")
}

// TestACL_AnyoneIdentifier_MYRIGHTS tests MYRIGHTS command with "anyone" access
func TestACL_AnyoneIdentifier_MYRIGHTS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second user in same domain
	domain := "example.com"
	email1 := account1.Email
	email2 := fmt.Sprintf("user2-%d@%s", common.GetTimestamp(), domain)
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

	// User1 connects and creates a shared mailbox
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, account1.Password).Wait(); err != nil {
		t.Fatalf("User1 login failed: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/MyRights-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}
	defer func() { c1.Delete(sharedMailbox).Wait() }()

	// Grant "anyone" rights 'lrs'
	err = c1.SetACL(sharedMailbox, imap.RightsIdentifier(db.AnyoneIdentifier), imap.RightModificationReplace, imap.RightSet("lrs")).Wait()
	if err != nil {
		t.Fatalf("SETACL failed: %v", err)
	}

	// User2 connects and checks MYRIGHTS
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial for user2: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}

	myRightsData, err := c2.MyRights(sharedMailbox).Wait()
	if err != nil {
		t.Fatalf("MYRIGHTS failed: %v", err)
	}

	// User2 should see 'lrs' from "anyone"
	rightsStr := myRightsData.Rights.String()
	expectedRights := map[rune]bool{'l': true, 'r': true, 's': true}
	for _, r := range rightsStr {
		if _, ok := expectedRights[r]; ok {
			delete(expectedRights, r)
		}
	}
	if len(expectedRights) > 0 {
		t.Errorf("User2 should have 'lrs' rights from 'anyone', got: %s", rightsStr)
	} else {
		t.Logf("✓ User2 MYRIGHTS shows correct rights from 'anyone': %s", rightsStr)
	}

	t.Logf("✓ MYRIGHTS with 'anyone' test passed")
}
