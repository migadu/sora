//go:build integration

package imap

import (
	"context"
	"os/exec"
	"testing"
	"time"

	imapClient "github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSharedMailboxE2E tests the complete flow of shared mailbox creation and ACL management
// This is an end-to-end test that verifies:
// 1. Config is properly loaded and passed to IMAP server
// 2. Mailboxes with "Shared/" prefix are marked as is_shared=true in database
// 3. sora-admin ACL commands work with shared mailboxes created via IMAP
func TestSharedMailboxE2E(t *testing.T) {
	// Setup: Create IMAP server with full config
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	// Create second test account
	user := common.CreateTestAccount(t, server.ResilientDB)

	// Connect to IMAP as owner (non-TLS for testing)
	client, err := imapClient.DialInsecure(server.Address, nil)
	require.NoError(t, err, "Failed to connect to IMAP server")
	defer client.Close()

	// Authenticate as owner
	err = client.Login(owner.Email, owner.Password).Wait()
	require.NoError(t, err, "Failed to authenticate")

	// Test 1: Create shared mailbox via IMAP
	sharedMailboxName := "Shared/TestE2E"
	t.Run("CreateSharedMailboxViaIMAP", func(t *testing.T) {
		err := client.Create(sharedMailboxName, nil).Wait()
		require.NoError(t, err, "Failed to create shared mailbox via IMAP")

		// Verify mailbox exists and is marked as shared in database
		ctx := context.Background()
		var isShared bool
		var ownerDomain string
		err = server.ResilientDB.QueryRowWithRetry(ctx, `
			SELECT COALESCE(is_shared, false), owner_domain
			FROM mailboxes m
			JOIN credentials c ON m.account_id = c.account_id AND c.primary_identity = true
			WHERE m.name = $1 AND c.address = $2
		`, sharedMailboxName, owner.Email).Scan(&isShared, &ownerDomain)

		require.NoError(t, err, "Failed to query mailbox from database")
		assert.True(t, isShared, "Mailbox should be marked as shared in database")
		assert.NotEmpty(t, ownerDomain, "Mailbox should have owner domain set")
		t.Logf("Created shared mailbox: is_shared=%v, owner_domain=%s", isShared, ownerDomain)
	})

	// Test 2: Grant ACL via sora-admin command
	t.Run("GrantACLViaSoraAdmin", func(t *testing.T) {
		// Run sora-admin acl grant command
		cmd := exec.Command("../../sora-admin",
			"acl", "grant",
			"--config", "../../config-test.toml",
			"--email", owner.Email,
			"--mailbox", sharedMailboxName,
			"--user", user.Email,
			"--rights", "lrs",
		)

		output, err := cmd.CombinedOutput()
		t.Logf("sora-admin output: %s", string(output))

		// This should succeed, not fail with "mailbox is not shared"
		require.NoError(t, err, "sora-admin acl grant should succeed")
		assert.Contains(t, string(output), "Successfully granted", "Should show success message")
		assert.NotContains(t, string(output), "not shared", "Should not have 'not shared' error")
	})

	// Test 3: List ACL via sora-admin command
	t.Run("ListACLViaSoraAdmin", func(t *testing.T) {
		cmd := exec.Command("../../sora-admin",
			"acl", "list",
			"--config", "../../config-test.toml",
			"--email", owner.Email,
			"--mailbox", sharedMailboxName,
		)

		output, err := cmd.CombinedOutput()
		t.Logf("sora-admin list output: %s", string(output))

		require.NoError(t, err, "sora-admin acl list should succeed")
		assert.Contains(t, string(output), user.Email, "Should show user in ACL list")
		assert.Contains(t, string(output), "lrs", "Should show granted rights")
	})

	// Test 4: User can access the shared mailbox via IMAP
	t.Run("UserCanAccessSharedMailbox", func(t *testing.T) {
		// Connect as the user who was granted access
		userClient, err := imapClient.DialInsecure(server.Address, nil)
		require.NoError(t, err, "Failed to connect as user")
		defer userClient.Close()

		err = userClient.Login(user.Email, user.Password).Wait()
		require.NoError(t, err, "Failed to authenticate as user")

		// List mailboxes - should see the shared mailbox
		mailboxes, err := userClient.List("", "*", nil).Collect()
		require.NoError(t, err, "Failed to list mailboxes")

		// Find the shared mailbox in the list
		found := false
		for _, mbox := range mailboxes {
			if mbox.Mailbox == sharedMailboxName {
				found = true
				t.Logf("User can see shared mailbox: %s", mbox.Mailbox)
				break
			}
		}
		assert.True(t, found, "User should be able to see the shared mailbox")
	})

	// Test 5: Revoke ACL via sora-admin command
	t.Run("RevokeACLViaSoraAdmin", func(t *testing.T) {
		cmd := exec.Command("../../sora-admin",
			"acl", "revoke",
			"--config", "../../config-test.toml",
			"--email", owner.Email,
			"--mailbox", sharedMailboxName,
			"--user", user.Email,
		)

		output, err := cmd.CombinedOutput()
		t.Logf("sora-admin revoke output: %s", string(output))

		require.NoError(t, err, "sora-admin acl revoke should succeed")
		assert.Contains(t, string(output), "Successfully revoked", "Should show success message")
	})

	// Test 6: Verify user can no longer access the shared mailbox
	t.Run("UserCannotAccessAfterRevoke", func(t *testing.T) {
		userClient, err := imapClient.DialInsecure(server.Address, nil)
		require.NoError(t, err, "Failed to connect as user")
		defer userClient.Close()

		err = userClient.Login(user.Email, user.Password).Wait()
		require.NoError(t, err, "Failed to authenticate as user")

		// List mailboxes - should NOT see the shared mailbox anymore
		mailboxes, err := userClient.List("", "*", nil).Collect()
		require.NoError(t, err, "Failed to list mailboxes")

		// Shared mailbox should not be in the list
		for _, mbox := range mailboxes {
			assert.NotEqual(t, sharedMailboxName, mbox.Mailbox,
				"User should not see shared mailbox after ACL revocation")
		}
		t.Log("User correctly cannot see shared mailbox after revocation")
	})

	// Test 7: Create regular (non-shared) mailbox and verify it's NOT marked as shared
	t.Run("RegularMailboxNotMarkedAsShared", func(t *testing.T) {
		regularMailboxName := "RegularFolder"
		err := client.Create(regularMailboxName, nil).Wait()
		require.NoError(t, err, "Failed to create regular mailbox")

		// Verify mailbox is NOT marked as shared
		ctx := context.Background()
		var isShared bool
		err = server.ResilientDB.QueryRowWithRetry(ctx, `
			SELECT COALESCE(is_shared, false)
			FROM mailboxes m
			JOIN credentials c ON m.account_id = c.account_id AND c.primary_identity = true
			WHERE m.name = $1 AND c.address = $2
		`, regularMailboxName, owner.Email).Scan(&isShared)

		require.NoError(t, err, "Failed to query mailbox from database")
		assert.False(t, isShared, "Regular mailbox should NOT be marked as shared")
		t.Log("Regular mailbox correctly not marked as shared")
	})

	t.Log("✅ End-to-end shared mailbox and ACL test completed successfully!")
}

// TestSharedMailboxConfigPropagation specifically tests that config is properly passed to IMAP server
func TestSharedMailboxConfigPropagation(t *testing.T) {
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect and authenticate
	client, err := imapClient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer client.Close()

	err = client.Login(owner.Email, owner.Password).Wait()
	require.NoError(t, err)

	// Test multiple shared mailbox patterns
	testCases := []struct {
		name           string
		mailbox        string
		shouldBeShared bool
		skipCreate     bool // Skip creation if mailbox auto-created (INBOX, Shared)
	}{
		{"Shared prefix", "Shared/Sales", true, false},
		{"Shared nested", "Shared/Sales/Q4", true, false},
		{"Not shared - custom", "MyFolder", false, false},
		{"Not shared - similar name", "SharedNotes", false, false}, // Doesn't start with "Shared/"
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mailbox (unless it's auto-created)
			if !tc.skipCreate {
				err := client.Create(tc.mailbox, nil).Wait()
				require.NoError(t, err, "Failed to create mailbox: %s", tc.mailbox)
			}

			// Check database
			ctx := context.Background()
			var isShared bool
			err = server.ResilientDB.QueryRowWithRetry(ctx, `
				SELECT COALESCE(is_shared, false)
				FROM mailboxes m
				JOIN credentials c ON m.account_id = c.account_id AND c.primary_identity = true
				WHERE m.name = $1 AND c.address = $2
			`, tc.mailbox, owner.Email).Scan(&isShared)

			require.NoError(t, err, "Failed to query mailbox")

			if tc.shouldBeShared {
				assert.True(t, isShared, "Mailbox '%s' should be marked as shared", tc.mailbox)
			} else {
				assert.False(t, isShared, "Mailbox '%s' should NOT be marked as shared", tc.mailbox)
			}

			// Cleanup - delete mailbox for next test
			time.Sleep(100 * time.Millisecond) // Small delay to avoid race conditions
		})
	}
}

// TestSoraAdminACLWithoutConfigFails tests that sora-admin fails gracefully if config is missing
func TestSoraAdminACLWithoutConfigFails(t *testing.T) {
	t.Run("GrantWithoutConfig", func(t *testing.T) {
		cmd := exec.Command("../../sora-admin",
			"acl", "grant",
			"--config", "/nonexistent/config.toml",
			"--email", "owner@example.com",
			"--mailbox", "Shared/Test",
			"--user", "user@example.com",
			"--rights", "lrs",
		)

		output, err := cmd.CombinedOutput()
		t.Logf("Output: %s", string(output))

		// Should fail because config doesn't exist
		assert.Error(t, err, "Should fail with missing config")
		assert.Contains(t, string(output), "Failed to load configuration",
			"Should show config loading error")
	})

	t.Run("GrantWithMissingParameters", func(t *testing.T) {
		cmd := exec.Command("../../sora-admin",
			"acl", "grant",
			"--config", "../../config-test.toml",
			// Missing required parameters
		)

		output, err := cmd.CombinedOutput()
		t.Logf("Output: %s", string(output))

		// Should fail due to missing parameters
		assert.Error(t, err, "Should fail with missing parameters")
	})
}
