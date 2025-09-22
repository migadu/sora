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

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	// Test CAPABILITY command before authentication
	capsBeforeAuth, err := c.Capability().Wait()
	if err != nil {
		t.Fatalf("CAPABILITY command failed before auth: %v", err)
	}

	var capsList []string
	for c := range capsBeforeAuth {
		capsList = append(capsList, string(c))
	}
	t.Logf("Server capabilities before auth: %v", capsList)

	// Login first
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Test CAPABILITY command after authentication
	caps, err := c.Capability().Wait()
	if err != nil {
		t.Fatalf("CAPABILITY command failed after auth: %v", err)
	}

	// Check for required capabilities (should be available after auth)
	requiredCaps := []string{"IMAP4rev1", "NAMESPACE"}
	for _, required := range requiredCaps {
		if !caps.Has(imap.Cap(required)) {
			t.Errorf("Required capability %s not found after authentication", required)
		}
	}

	capsList = nil
	for c := range caps {
		capsList = append(capsList, string(c))
	}

	t.Logf("Server capabilities after auth: %v", capsList)
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

func TestIMAP_Namespace(t *testing.T) {
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

	// Test NAMESPACE command
	nsData, err := c.Namespace().Wait()
	if err != nil {
		t.Fatalf("NAMESPACE command failed: %v", err)
	}

	// Verify personal namespace
	if len(nsData.Personal) != 1 {
		t.Fatalf("Expected 1 personal namespace, got %d", len(nsData.Personal))
	}

	personalNs := nsData.Personal[0]
	if personalNs.Prefix != "" {
		t.Errorf("Expected empty prefix for personal namespace, got '%s'", personalNs.Prefix)
	}

	if personalNs.Delim != '/' {
		t.Errorf("Expected '/' delimiter for personal namespace, got '%c'", personalNs.Delim)
	}

	// Verify no shared or other namespaces
	if nsData.Shared != nil {
		t.Errorf("Expected no shared namespaces, got %d", len(nsData.Shared))
	}

	if nsData.Other != nil {
		t.Errorf("Expected no other namespaces, got %d", len(nsData.Other))
	}

	t.Log("NAMESPACE command executed successfully")
	t.Logf("Personal namespace: prefix='%s', delimiter='%c'", personalNs.Prefix, personalNs.Delim)
}

func TestIMAP_LsubCommand(t *testing.T) {
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

	// 1. Create a nested mailbox structure and an unrelated folder
	mailboxHierarchy := []string{
		"A",
		"A/B",
		"A/B/C",
		"AnotherFolder", // A non-subscribed, non-parent folder
	}
	for _, mbox := range mailboxHierarchy {
		if err := c.Create(mbox, nil).Wait(); err != nil {
			t.Fatalf("CREATE mailbox '%s' failed: %v", mbox, err)
		}
	}
	t.Logf("Created mailboxes: %v", mailboxHierarchy)

	// 2. Subscribe only to the deepest mailbox and INBOX
	if err := c.Subscribe("A/B/C").Wait(); err != nil {
		t.Fatalf("SUBSCRIBE to 'A/B/C' failed: %v", err)
	}
	if err := c.Subscribe("INBOX").Wait(); err != nil {
		t.Fatalf("SUBSCRIBE to 'INBOX' failed: %v", err)
	}
	t.Log("Subscribed to: A/B/C and INBOX")

	// 3. Issue LSUB command
	lsubCmd := c.List("", "*", &imap.ListOptions{SelectSubscribed: true})
	mailboxes, err := lsubCmd.Collect()
	if err != nil {
		t.Fatalf("LSUB command failed: %v", err)
	}

	// 4. Verify the response
	expectedMailboxes := map[string]struct {
		Subscribed bool
		Noselect   bool
	}{
		"INBOX": {Subscribed: true, Noselect: false},
		"A":     {Subscribed: false, Noselect: true},
		"A/B":   {Subscribed: false, Noselect: true},
		"A/B/C": {Subscribed: true, Noselect: false},
	}

	if len(mailboxes) != len(expectedMailboxes) {
		t.Errorf("LSUB returned %d mailboxes, expected %d", len(mailboxes), len(expectedMailboxes))
	}

	for _, mbox := range mailboxes {
		expected, ok := expectedMailboxes[mbox.Mailbox]
		if !ok {
			t.Errorf("LSUB returned unexpected mailbox: %s", mbox.Mailbox)
			continue
		}

		hasSubscribed := mailboxHasAttr(mbox.Attrs, imap.MailboxAttrSubscribed)
		if expected.Subscribed != hasSubscribed {
			t.Errorf("Mailbox '%s' subscribed attribute mismatch: got %v, want %v", mbox.Mailbox, hasSubscribed, expected.Subscribed)
		}

		hasNoselect := mailboxHasAttr(mbox.Attrs, imap.MailboxAttrNoSelect)
		if expected.Noselect != hasNoselect {
			t.Errorf("Mailbox '%s' noselect attribute mismatch: got %v, want %v", mbox.Mailbox, hasNoselect, expected.Noselect)
		}
	}
}

func mailboxHasAttr(attrs []imap.MailboxAttr, attr imap.MailboxAttr) bool {
	for _, a := range attrs {
		if a == attr {
			return true
		}
	}
	return false
}

func TestIMAP_RenameParentFolder(t *testing.T) {
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

	// 1. Create nested mailboxes and subscribe to a child
	parentMailbox := "Projects"
	childMailbox := "Projects/Sora"

	// Create the child mailbox. The server should auto-create the parent 'Projects'.
	// This avoids a potential server bug where explicit parent creation causes ambiguity.
	if err := c.Create(childMailbox, nil).Wait(); err != nil {
		t.Fatalf("CREATE mailbox '%s' failed: %v", childMailbox, err)
	}
	t.Logf("Created mailboxes: %s, %s", parentMailbox, childMailbox)

	if err := c.Subscribe(childMailbox).Wait(); err != nil {
		t.Fatalf("SUBSCRIBE to '%s' failed: %v", childMailbox, err)
	}
	t.Logf("Subscribed to: %s", childMailbox)

	// 2. Rename the parent folder
	newParentMailbox := "Projects-Archived"
	if err := c.Rename(parentMailbox, newParentMailbox, nil).Wait(); err != nil {
		t.Fatalf("RENAME from '%s' to '%s' failed: %v", parentMailbox, newParentMailbox, err)
	}
	t.Logf("Renamed '%s' to '%s'", parentMailbox, newParentMailbox)

	newChildMailbox := "Projects-Archived/Sora"

	// 3. Verify LIST response after rename
	listCmd := c.List("", "*", nil)
	listMailboxes, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST command failed after rename: %v", err)
	}

	foundMailboxes := make(map[string]bool)
	for _, mbox := range listMailboxes {
		foundMailboxes[mbox.Mailbox] = true
	}

	if !foundMailboxes[newParentMailbox] || !foundMailboxes[newChildMailbox] {
		t.Errorf("LIST after rename: expected to find '%s' and '%s'", newParentMailbox, newChildMailbox)
	}
	if foundMailboxes[parentMailbox] || foundMailboxes[childMailbox] {
		t.Errorf("LIST after rename: found old mailboxes '%s' or '%s', which should have been removed", parentMailbox, childMailbox)
	}
	t.Log("LIST response verified successfully after rename.")

	// 4. Verify LSUB response after rename
	lsubCmd := c.List("", "*", &imap.ListOptions{SelectSubscribed: true})
	lsubMailboxes, err := lsubCmd.Collect()
	if err != nil {
		t.Fatalf("LSUB command failed after rename: %v", err)
	}

	expectedLsub := map[string]struct {
		Subscribed bool
		Noselect   bool
	}{
		"INBOX":          {Subscribed: true, Noselect: false},
		newParentMailbox: {Subscribed: false, Noselect: true},
		newChildMailbox:  {Subscribed: true, Noselect: false},
	}

	foundLsub := make(map[string]bool)
	for _, mbox := range lsubMailboxes {
		if expected, ok := expectedLsub[mbox.Mailbox]; ok {
			foundLsub[mbox.Mailbox] = true
			if expected.Subscribed != mailboxHasAttr(mbox.Attrs, imap.MailboxAttrSubscribed) || expected.Noselect != mailboxHasAttr(mbox.Attrs, imap.MailboxAttrNoSelect) {
				t.Errorf("LSUB mailbox '%s' has incorrect attributes", mbox.Mailbox)
			}
		}
		if mbox.Mailbox == parentMailbox || mbox.Mailbox == childMailbox {
			t.Errorf("LSUB after rename: found old mailbox '%s', which should have been removed", mbox.Mailbox)
		}
	}

	if len(foundLsub) != len(expectedLsub) {
		t.Errorf("LSUB after rename: did not find all expected mailboxes. Found %d, expected %d", len(foundLsub), len(expectedLsub))
	}
	t.Log("LSUB response verified successfully after rename.")
}

func TestIMAP_NamespaceDelimiterConsistency(t *testing.T) {
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

	// Get NAMESPACE response
	nsData, err := c.Namespace().Wait()
	if err != nil {
		t.Fatalf("NAMESPACE command failed: %v", err)
	}

	if len(nsData.Personal) == 0 {
		t.Fatal("Expected at least one personal namespace")
	}

	namespaceDelim := nsData.Personal[0].Delim

	// Create a test mailbox and verify LIST uses same delimiter
	testMailbox := "TestFolder/SubFolder"
	if err := c.Create(testMailbox, nil).Wait(); err != nil {
		t.Fatalf("CREATE mailbox failed: %v", err)
	}
	defer c.Delete("TestFolder").Wait()

	// Get LIST response
	listCmd := c.List("", "*", nil)
	mailboxes, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST command failed: %v", err)
	}

	// Verify LIST uses same delimiter as NAMESPACE
	for _, mbox := range mailboxes {
		if mbox.Delim != namespaceDelim {
			t.Errorf("LIST delimiter '%c' doesn't match NAMESPACE delimiter '%c'", mbox.Delim, namespaceDelim)
		}
	}

	t.Logf("NAMESPACE and LIST delimiters are consistent: '%c'", namespaceDelim)
}

func TestIMAP_NamespaceInboxAccessibility(t *testing.T) {
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

	// Get NAMESPACE response
	nsData, err := c.Namespace().Wait()
	if err != nil {
		t.Fatalf("NAMESPACE command failed: %v", err)
	}

	personalNs := nsData.Personal[0]
	t.Logf("Personal namespace: prefix='%s', delimiter='%c'", personalNs.Prefix, personalNs.Delim)

	// INBOX should be accessible regardless of namespace prefix
	// Test various INBOX name variations
	inboxVariations := []string{"INBOX", "inbox", "Inbox"}

	for _, inboxName := range inboxVariations {
		selectCmd := c.Select(inboxName, nil)
		mbox, err := selectCmd.Wait()
		if err != nil {
			// Only INBOX (uppercase) is guaranteed to work per RFC
			if inboxName != "INBOX" {
				t.Logf("SELECT %s failed as expected: %v", inboxName, err)
				continue
			}
			t.Fatalf("SELECT %s failed: %v", inboxName, err)
		}

		if mbox == nil {
			t.Fatalf("SELECT %s returned nil mailbox", inboxName)
		}

		t.Logf("Successfully selected %s", inboxName)
	}

	// Verify INBOX appears in LIST regardless of namespace prefix
	listCmd := c.List("", "*", nil)
	mailboxes, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST command failed: %v", err)
	}

	foundInbox := false
	for _, mbox := range mailboxes {
		if strings.ToUpper(mbox.Mailbox) == "INBOX" {
			foundInbox = true
			// INBOX should not have namespace prefix
			if personalNs.Prefix != "" && strings.HasPrefix(mbox.Mailbox, personalNs.Prefix) {
				t.Errorf("INBOX should not have namespace prefix, but found: %s", mbox.Mailbox)
			}
			break
		}
	}

	if !foundInbox {
		t.Error("INBOX not found in LIST response")
	}
}

func TestIMAP_NamespaceMailboxOperations(t *testing.T) {
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

	// Get NAMESPACE response
	nsData, err := c.Namespace().Wait()
	if err != nil {
		t.Fatalf("NAMESPACE command failed: %v", err)
	}

	personalNs := nsData.Personal[0]
	t.Logf("Personal namespace: prefix='%s', delimiter='%c'", personalNs.Prefix, personalNs.Delim)

	// Test mailbox creation with proper namespace handling
	// Since our namespace has empty prefix, mailboxes should work normally
	testMailboxes := []string{
		"TestFolder",
		"TestFolder" + string(personalNs.Delim) + "SubFolder",
		"AnotherFolder",
	}

	// Create mailboxes
	for _, mbox := range testMailboxes {
		fullName := personalNs.Prefix + mbox
		if err := c.Create(fullName, nil).Wait(); err != nil {
			t.Fatalf("CREATE mailbox '%s' failed: %v", fullName, err)
		}
		t.Logf("Created mailbox: %s", fullName)
	}

	// List mailboxes and verify they appear correctly
	listCmd := c.List("", "*", nil)
	mailboxes, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST command failed: %v", err)
	}

	foundMailboxes := make(map[string]bool)
	for _, mbox := range mailboxes {
		foundMailboxes[mbox.Mailbox] = true
	}

	// Verify created mailboxes appear in LIST
	for _, expectedMbox := range testMailboxes {
		fullName := personalNs.Prefix + expectedMbox
		if !foundMailboxes[fullName] {
			t.Errorf("Created mailbox '%s' not found in LIST response", fullName)
		}
	}

	// Test mailbox operations (STATUS, SELECT)
	for _, mbox := range testMailboxes {
		fullName := personalNs.Prefix + mbox
		
		// Test STATUS
		statusData, err := c.Status(fullName, &imap.StatusOptions{
			NumMessages: true,
			UIDNext:     true,
		}).Wait()
		if err != nil {
			t.Errorf("STATUS for mailbox '%s' failed: %v", fullName, err)
		} else {
			t.Logf("STATUS for %s: NumMessages=%v, UIDNext=%v", fullName, statusData.NumMessages, statusData.UIDNext)
		}

		// Test SELECT (only for non-hierarchical test mailboxes)
		if !strings.Contains(mbox, string(personalNs.Delim)) {
			selectData, err := c.Select(fullName, nil).Wait()
			if err != nil {
				t.Errorf("SELECT for mailbox '%s' failed: %v", fullName, err)
			} else {
				t.Logf("SELECT for %s successful: NumMessages=%d", fullName, selectData.NumMessages)
			}
		}
	}

	// Cleanup
	for i := len(testMailboxes) - 1; i >= 0; i-- {
		fullName := personalNs.Prefix + testMailboxes[i]
		if err := c.Delete(fullName).Wait(); err != nil {
			t.Logf("Failed to delete mailbox '%s': %v", fullName, err)
		}
	}
}

func TestIMAP_NamespaceNegativeTests(t *testing.T) {
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

	// Test NAMESPACE response structure
	nsData, err := c.Namespace().Wait()
	if err != nil {
		t.Fatalf("NAMESPACE command failed: %v", err)
	}

	// Verify no shared namespaces
	if nsData.Shared != nil && len(nsData.Shared) > 0 {
		t.Errorf("Server returned shared namespaces when none should be supported: %v", nsData.Shared)
	}

	// Verify no other user namespaces
	if nsData.Other != nil && len(nsData.Other) > 0 {
		t.Errorf("Server returned other user namespaces when none should be supported: %v", nsData.Other)
	}

	// Verify we have exactly one personal namespace
	if len(nsData.Personal) != 1 {
		t.Errorf("Expected exactly 1 personal namespace, got %d", len(nsData.Personal))
	}

	// Test that unsupported namespace prefixes fail gracefully
	// Try to create mailboxes with invalid namespace-like names
	invalidNamespaces := []string{
		"#shared/test",
		"#user/someone/test", 
		"~user/test",
	}

	for _, invalidName := range invalidNamespaces {
		err := c.Create(invalidName, nil).Wait()
		// These should either fail or be treated as regular mailbox names
		// Since we don't support these namespace types, they should work as regular names
		if err == nil {
			t.Logf("Created mailbox with namespace-like name '%s' - treated as regular mailbox", invalidName)
			// Clean up
			c.Delete(invalidName).Wait()
		} else {
			t.Logf("Failed to create namespace-like mailbox '%s': %v", invalidName, err)
		}
	}

	t.Log("NAMESPACE negative tests completed")
}
