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

// TestLIST_SharedMailboxes_DirectACL tests that LIST shows shared mailboxes with direct user ACL
func TestLIST_SharedMailboxes_DirectACL(t *testing.T) {
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

	// Connect as user1 (owner)
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, password1).Wait(); err != nil {
		t.Fatalf("User1 login failed: %v", err)
	}

	// Create shared mailbox
	sharedMailbox := fmt.Sprintf("Shared/DirectACL-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}

	// Grant user2 lookup right
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lr")).Wait(); err != nil {
		t.Fatalf("SETACL failed: %v", err)
	}

	// Connect as user2
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server as user2: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}

	// LIST should show the shared mailbox
	mboxes, err := c2.List("", "*", nil).Collect()
	if err != nil {
		t.Fatalf("LIST failed for user2: %v", err)
	}

	// Verify shared mailbox is visible
	found := false
	for _, mbox := range mboxes {
		if mbox.Mailbox == sharedMailbox {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("User2 should see shared mailbox '%s' via direct ACL in LIST response", sharedMailbox)
		t.Logf("Mailboxes visible to user2: %v", mboxes)
	}

	// NAMESPACE should show shared namespace
	nsData, err := c2.Namespace().Wait()
	if err != nil {
		t.Fatalf("NAMESPACE failed: %v", err)
	}

	if nsData.Shared == nil || len(nsData.Shared) == 0 {
		t.Errorf("NAMESPACE should include Shared namespace")
	} else if nsData.Shared[0].Prefix != "Shared/" {
		t.Errorf("Shared namespace prefix = %s, want 'Shared/'", nsData.Shared[0].Prefix)
	}
}

// TestLIST_SharedMailboxes_AnyoneIdentifier tests that LIST shows shared mailboxes via "anyone"
func TestLIST_SharedMailboxes_AnyoneIdentifier(t *testing.T) {
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

	// Connect as user1 (owner)
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, password1).Wait(); err != nil {
		t.Fatalf("User1 login failed: %v", err)
	}

	// Create shared mailbox
	sharedMailbox := fmt.Sprintf("Shared/AnyoneACL-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}

	// Grant "anyone" lookup right (domain-wide sharing)
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(db.AnyoneIdentifier), imap.RightModificationReplace, imap.RightSet("lr")).Wait(); err != nil {
		t.Fatalf("SETACL for 'anyone' failed: %v", err)
	}

	// Connect as user2
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server as user2: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}

	// LIST should show the shared mailbox via "anyone" access
	mboxes, err := c2.List("", "*", nil).Collect()
	if err != nil {
		t.Fatalf("LIST failed for user2: %v", err)
	}

	// Verify shared mailbox is visible
	found := false
	for _, mbox := range mboxes {
		if mbox.Mailbox == sharedMailbox {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("User2 should see shared mailbox '%s' via 'anyone' ACL in LIST response", sharedMailbox)
		t.Logf("Mailboxes visible to user2: %v", mboxes)
	}
}

// TestLIST_SharedMailboxes_CrossDomain tests that "anyone" doesn't grant cross-domain access
func TestLIST_SharedMailboxes_CrossDomain(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account1 := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second user in DIFFERENT domain
	email1 := account1.Email
	email2 := fmt.Sprintf("user-%d@%s", common.GetTimestamp(), "otherdomain.com")
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

	// Connect as user1 (owner)
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, password1).Wait(); err != nil {
		t.Fatalf("User1 login failed: %v", err)
	}

	// Create shared mailbox
	sharedMailbox := fmt.Sprintf("Shared/CrossDomain-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}

	// Grant "anyone" lookup right
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(db.AnyoneIdentifier), imap.RightModificationReplace, imap.RightSet("lr")).Wait(); err != nil {
		t.Fatalf("SETACL for 'anyone' failed: %v", err)
	}

	// Connect as user2 from different domain
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server as user2: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}

	// LIST should NOT show the shared mailbox (different domain)
	mboxes, err := c2.List("", "*", nil).Collect()
	if err != nil {
		t.Fatalf("LIST failed for user2: %v", err)
	}

	// Verify shared mailbox is NOT visible
	for _, mbox := range mboxes {
		if mbox.Mailbox == sharedMailbox {
			t.Errorf("User2 from different domain should NOT see shared mailbox '%s' via 'anyone' ACL", sharedMailbox)
			break
		}
	}
}

// TestLIST_SharedMailboxes_NoLookupRight tests that mailboxes without 'l' right are hidden
func TestLIST_SharedMailboxes_NoLookupRight(t *testing.T) {
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

	// Connect as user1 (owner)
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(email1, password1).Wait(); err != nil {
		t.Fatalf("User1 login failed: %v", err)
	}

	// Create shared mailbox
	sharedMailbox := fmt.Sprintf("Shared/NoLookup-%d", common.GetTimestamp())
	if err := c1.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("Failed to create shared mailbox: %v", err)
	}

	// Grant user2 rights WITHOUT 'l' (lookup)
	if err := c1.SetACL(sharedMailbox, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("r")).Wait(); err != nil {
		t.Fatalf("SETACL failed: %v", err)
	}

	// Connect as user2
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server as user2: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("User2 login failed: %v", err)
	}

	// LIST should NOT show the mailbox (no 'l' right)
	mboxes, err := c2.List("", "*", nil).Collect()
	if err != nil {
		t.Fatalf("LIST failed for user2: %v", err)
	}

	// Verify shared mailbox is NOT visible
	for _, mbox := range mboxes {
		if mbox.Mailbox == sharedMailbox {
			t.Errorf("User2 should NOT see mailbox '%s' without 'l' (lookup) right", sharedMailbox)
			break
		}
	}
}
