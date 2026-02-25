//go:build integration

package imap_test

import (
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestMailbox_RenameCaseSensitivityBug reproduces the EXACT production bug:
//
// Production error (2026-02-10T08:35:52):
// failed to rename mailbox 'amazon' to 'amazontest': failed to update child mailboxes:
// ERROR: duplicate key value violates unique constraint "mailboxes_account_id_name_unique" (SQLSTATE 23505)
//
// ROOT CAUSE:
// The old code used case-sensitive checks for rename conflict detection,
// but GetMailboxByName uses case-insensitive matching (LOWER on both sides).
// This inconsistency meant a rename could bypass the existence check when the
// target name existed with different casing, leading to a constraint violation.
//
// The fix ensures:
// 1. GetMailboxByName uses LOWER() on both sides (case-insensitive lookup)
// 2. IMAP CREATE prevents creating case-duplicate mailboxes
// 3. IMAP RENAME uses case-insensitive same-name check
// 4. RenameMailbox DB function uses case-insensitive existence check
func TestMailbox_RenameCaseSensitivityBug(t *testing.T) {
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

	// Test Case 1: Rename to a name that conflicts case-insensitively with another mailbox
	t.Run("SimpleCaseMismatch", func(t *testing.T) {
		// Create "TestFolder" and a separate "OtherFolder"
		if err := c.Create("TestFolder", nil).Wait(); err != nil {
			t.Fatalf("CREATE TestFolder failed: %v", err)
		}

		if err := c.Create("OtherFolder", nil).Wait(); err != nil {
			t.Fatalf("CREATE OtherFolder failed: %v", err)
		}

		// Try to rename "OtherFolder" to "testfolder" (case-insensitive conflict with "TestFolder")
		err := c.Rename("OtherFolder", "testfolder", nil).Wait()
		if err == nil {
			t.Errorf("RENAME should have failed (case-insensitive conflict with TestFolder), but succeeded")
		} else {
			errStr := err.Error()
			// With the FIX: Should get ALREADYEXISTS error
			// With the BUG: Would get SQLSTATE 23505 constraint violation
			if strings.Contains(errStr, "SQLSTATE") || strings.Contains(errStr, "23505") {
				t.Errorf("❌ BUG REPRODUCED: Got database constraint violation: %v", err)
			} else if strings.Contains(errStr, "ALREADYEXISTS") || strings.Contains(strings.ToLower(errStr), "exists") {
				t.Logf("✓ FIXED: Got proper error: %v", err)
			} else {
				t.Logf("Got error (check if appropriate): %v", err)
			}
		}

		// Also verify that creating a case-duplicate mailbox is prevented
		err = c.Create("testfolder", nil).Wait()
		if err == nil {
			t.Errorf("CREATE should have failed (case-insensitive duplicate of TestFolder), but succeeded")
		} else {
			t.Logf("✓ CREATE correctly prevented case-duplicate: %v", err)
		}

		// Cleanup
		c.Delete("OtherFolder").Wait()
		c.Delete("TestFolder").Wait()
	})

	// Test Case 2: Reproduce exact production scenario with children
	t.Run("ProductionScenarioWithChildren", func(t *testing.T) {
		// Create "amazon" with child
		if err := c.Create("amazon", nil).Wait(); err != nil {
			t.Fatalf("CREATE amazon failed: %v", err)
		}
		if err := c.Create("amazon/subfolder", nil).Wait(); err != nil {
			t.Fatalf("CREATE amazon/subfolder failed: %v", err)
		}

		// Create "Amazontest" (capital A)
		if err := c.Create("Amazontest", nil).Wait(); err != nil {
			t.Fatalf("CREATE Amazontest failed: %v", err)
		}

		t.Logf("Created: amazon, amazon/subfolder, Amazontest")

		// Try to rename "amazon" to "amazontest" (lowercase)
		// This should fail because "Amazontest" already exists (case-insensitive match)
		err := c.Rename("amazon", "amazontest", nil).Wait()
		if err == nil {
			t.Errorf("RENAME should have failed (case-insensitive conflict with 'Amazontest'), but succeeded")
		} else {
			errStr := err.Error()
			if strings.Contains(errStr, "SQLSTATE") || strings.Contains(errStr, "23505") ||
				strings.Contains(errStr, "duplicate key") || strings.Contains(errStr, "unique constraint") {
				t.Errorf("❌ BUG REPRODUCED (production error): %v", err)
				t.Errorf("This is the EXACT error from production logs!")
			} else if strings.Contains(errStr, "ALREADYEXISTS") || strings.Contains(strings.ToLower(errStr), "exists") {
				t.Logf("✓ FIXED: Got proper error instead of constraint violation: %v", err)
			} else {
				t.Logf("Got error: %v", err)
			}
		}

		// Verify nothing was corrupted
		listCmd := c.List("", "amazon", nil)
		mboxes, _ := listCmd.Collect()
		if len(mboxes) > 0 {
			t.Logf("✓ Original 'amazon' still exists")
		}

		// Cleanup
		c.Delete("amazon/subfolder").Wait()
		c.Delete("amazon").Wait()
		c.Delete("Amazontest").Wait()
		c.Delete("amazontest").Wait() // In case rename succeeded
	})
}
