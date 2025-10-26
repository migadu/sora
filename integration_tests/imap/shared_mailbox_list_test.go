//go:build integration

package imap

import (
	"context"
	"fmt"
	"testing"

	"github.com/emersion/go-imap/v2"
	imapClient "github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSharedMailbox_OwnerCanList tests that the owner can see their own shared mailboxes in LIST
// This is a regression test for the bug where shared mailboxes were excluded from the owner's LIST response
func TestSharedMailbox_OwnerCanList(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect as owner
	c, err := imapClient.DialInsecure(server.Address, nil)
	require.NoError(t, err, "Failed to connect to IMAP")
	defer c.Logout()

	err = c.Login(owner.Email, owner.Password).Wait()
	require.NoError(t, err, "Login failed")

	// Create shared mailbox
	sharedMailbox := fmt.Sprintf("Shared/TestLIST-%d", common.GetTimestamp())
	err = c.Create(sharedMailbox, nil).Wait()
	require.NoError(t, err, "Failed to create shared mailbox")

	// Verify mailbox is marked as shared in database
	ctx := context.Background()
	var isShared bool
	err = server.ResilientDB.QueryRowWithRetry(ctx, `
		SELECT COALESCE(is_shared, false)
		FROM mailboxes m
		JOIN credentials cr ON m.account_id = cr.account_id AND cr.primary_identity = true
		WHERE m.name = $1 AND cr.address = $2
	`, sharedMailbox, owner.Email).Scan(&isShared)
	require.NoError(t, err, "Failed to query mailbox")
	assert.True(t, isShared, "Mailbox should be marked as shared in database")

	// LIST all mailboxes - shared mailbox MUST appear
	mailboxes, err := c.List("", "*", nil).Collect()
	require.NoError(t, err, "LIST command failed")

	// Find the shared mailbox in LIST response
	found := false
	t.Logf("LIST response contains %d mailboxes:", len(mailboxes))
	for _, mbox := range mailboxes {
		t.Logf("  - %s (attrs: %v)", mbox.Mailbox, mbox.Attrs)
		if mbox.Mailbox == sharedMailbox {
			found = true
		}
	}

	assert.True(t, found, "Owner should see their own shared mailbox '%s' in LIST response", sharedMailbox)

	// Also verify with specific LIST pattern
	sharedOnly, err := c.List("", "Shared/*", nil).Collect()
	require.NoError(t, err, "LIST Shared/* failed")

	foundInPattern := false
	for _, mbox := range sharedOnly {
		if mbox.Mailbox == sharedMailbox {
			foundInPattern = true
			break
		}
	}
	assert.True(t, foundInPattern, "Shared mailbox should appear in 'LIST \"\" Shared/*'")

	t.Logf("✓ Owner can see their shared mailbox in LIST responses")

	// Cleanup
	c.Delete(sharedMailbox).Wait()
}

// TestSharedMailbox_OtherUserWithACLCanList tests that users granted ACL can see shared mailboxes
func TestSharedMailbox_OtherUserWithACLCanList(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second user
	user2 := common.CreateTestAccount(t, server.ResilientDB)

	// Owner creates shared mailbox
	c1, err := imapClient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c1.Logout()

	err = c1.Login(owner.Email, owner.Password).Wait()
	require.NoError(t, err)

	sharedMailbox := fmt.Sprintf("Shared/TestACLList-%d", common.GetTimestamp())
	err = c1.Create(sharedMailbox, nil).Wait()
	require.NoError(t, err)

	// Grant user2 access via ACL
	ownerID, _ := server.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), owner.Email)
	err = server.ResilientDB.GrantMailboxAccessByIdentifierWithRetry(context.Background(), ownerID, user2.Email, sharedMailbox, "lr")
	require.NoError(t, err, "Failed to grant ACL")

	// User2 should now see the shared mailbox in LIST
	c2, err := imapClient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c2.Logout()

	err = c2.Login(user2.Email, user2.Password).Wait()
	require.NoError(t, err)

	mailboxes, err := c2.List("", "*", nil).Collect()
	require.NoError(t, err)

	foundByUser2 := false
	t.Logf("User2 LIST response:")
	for _, mbox := range mailboxes {
		t.Logf("  - %s", mbox.Mailbox)
		if mbox.Mailbox == sharedMailbox {
			foundByUser2 = true
		}
	}

	assert.True(t, foundByUser2, "User2 should see shared mailbox after being granted ACL access")

	t.Logf("✓ User with ACL can see shared mailbox in LIST")

	// Cleanup
	c1.Delete(sharedMailbox).Wait()
}

// TestSharedMailbox_UserWithoutACLCannotList tests that users without ACL cannot see shared mailboxes
func TestSharedMailbox_UserWithoutACLCannotList(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second user (no ACL granted)
	user2 := common.CreateTestAccount(t, server.ResilientDB)

	// Owner creates shared mailbox
	c1, err := imapClient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c1.Logout()

	err = c1.Login(owner.Email, owner.Password).Wait()
	require.NoError(t, err)

	sharedMailbox := fmt.Sprintf("Shared/TestNoACL-%d", common.GetTimestamp())
	err = c1.Create(sharedMailbox, nil).Wait()
	require.NoError(t, err)

	// User2 should NOT see the mailbox (no ACL granted)
	c2, err := imapClient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c2.Logout()

	err = c2.Login(user2.Email, user2.Password).Wait()
	require.NoError(t, err)

	mailboxes, err := c2.List("", "*", nil).Collect()
	require.NoError(t, err)

	for _, mbox := range mailboxes {
		assert.NotEqual(t, sharedMailbox, mbox.Mailbox, "User2 should NOT see shared mailbox without ACL")
	}

	t.Logf("✓ User without ACL cannot see shared mailbox in LIST")

	// Cleanup
	c1.Delete(sharedMailbox).Wait()
}

// TestSharedMailbox_OwnerCanSelect tests that the owner can SELECT their own shared mailbox
// This is a regression test for the bug where owners couldn't SELECT shared mailboxes
func TestSharedMailbox_OwnerCanSelect(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect as owner
	c, err := imapClient.DialInsecure(server.Address, nil)
	require.NoError(t, err, "Failed to connect to IMAP")
	defer c.Logout()

	err = c.Login(owner.Email, owner.Password).Wait()
	require.NoError(t, err, "Login failed")

	// Create shared mailbox
	sharedMailbox := fmt.Sprintf("Shared/TestSELECT-%d", common.GetTimestamp())
	err = c.Create(sharedMailbox, nil).Wait()
	require.NoError(t, err, "Failed to create shared mailbox")

	// SELECT the shared mailbox - this should work for the owner
	selectData, err := c.Select(sharedMailbox, nil).Wait()
	require.NoError(t, err, "Owner should be able to SELECT their own shared mailbox")
	assert.NotNil(t, selectData, "SELECT should return mailbox data")

	t.Logf("✓ Owner can SELECT their shared mailbox")

	// Cleanup
	c.Delete(sharedMailbox).Wait()
}

// TestSharedNamespaceRoot tests that the "Shared" root folder has \Noselect attribute
// This prevents clients from trying to SELECT "Shared" itself
func TestSharedNamespaceRoot(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect as owner
	c, err := imapClient.DialInsecure(server.Address, nil)
	require.NoError(t, err, "Failed to connect to IMAP")
	defer c.Logout()

	err = c.Login(owner.Email, owner.Password).Wait()
	require.NoError(t, err, "Login failed")

	// Create a shared mailbox to ensure "Shared" parent exists
	sharedMailbox := fmt.Sprintf("Shared/TestRoot-%d", common.GetTimestamp())
	err = c.Create(sharedMailbox, nil).Wait()
	require.NoError(t, err, "Failed to create shared mailbox")

	// LIST to get mailbox attributes
	mailboxes, err := c.List("", "Shared", nil).Collect()
	require.NoError(t, err, "LIST Shared failed")

	// Find the "Shared" mailbox
	var sharedRoot *imap.ListData
	for i := range mailboxes {
		if mailboxes[i].Mailbox == "Shared" {
			sharedRoot = mailboxes[i]
			break
		}
	}

	require.NotNil(t, sharedRoot, "Shared namespace root should exist in LIST")

	// Verify it has \Noselect attribute
	hasNoselect := false
	hasChildren := false
	for _, attr := range sharedRoot.Attrs {
		if attr == imap.MailboxAttrNoSelect {
			hasNoselect = true
		}
		if attr == imap.MailboxAttrHasChildren {
			hasChildren = true
		}
	}

	assert.True(t, hasNoselect, "Shared namespace root should have \\Noselect attribute")
	assert.True(t, hasChildren, "Shared namespace root should have \\HasChildren attribute")

	// Try to SELECT it - should fail
	_, err = c.Select("Shared", nil).Wait()
	assert.Error(t, err, "SELECT on Shared namespace root should fail")

	t.Logf("✓ Shared namespace root correctly has \\Noselect attribute")

	// Cleanup
	c.Delete(sharedMailbox).Wait()
}
