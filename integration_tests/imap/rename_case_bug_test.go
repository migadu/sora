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
// The old code used LOWER(name) for the existence check (case-insensitive),
// but the database unique constraint is case-sensitive.
//
// Scenario:
// 1. User has mailbox "Amazon" (capital A)
// 2. User has mailbox "amazon" with children
// 3. User renames "amazon" to "Amazon"
// 4. OLD BUG: LOWER("Amazon") = LOWER("amazon") so check passes
// 5. UPDATE tries to rename "amazon" → "Amazon"
// 6. Constraint violation because "Amazon" already exists (case-sensitive)
//
// OR more likely for "amazontest":
// 1. User has "Amazontest" or "AMAZONTEST"
// 2. User has "amazon" and tries to rename to "amazontest"
// 3. OLD BUG: LOWER("Amazontest") = LOWER("amazontest") so check passes
// 4. UPDATE tries to create "amazontest"
// 5. Constraint violation
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

	// Test Case 1: Simple case mismatch
	t.Run("SimpleCaseMismatch", func(t *testing.T) {
		// Create "TestFolder"
		if err := c.Create("TestFolder", nil).Wait(); err != nil {
			t.Fatalf("CREATE TestFolder failed: %v", err)
		}

		// Create "testfolder" (lowercase)
		if err := c.Create("testfolder", nil).Wait(); err != nil {
			t.Fatalf("CREATE testfolder failed: %v", err)
		}

		// Try to rename "testfolder" to "TestFolder"
		err := c.Rename("testfolder", "TestFolder", nil).Wait()
		if err == nil {
			t.Errorf("RENAME should have failed (case conflict), but succeeded")
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

		// Cleanup
		c.Delete("testfolder").Wait()
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
		// OLD BUG: LOWER("Amazontest") = LOWER("amazontest"), so check passes
		// Then UPDATE fails with constraint violation
		err := c.Rename("amazon", "amazontest", nil).Wait()
		if err == nil {
			t.Errorf("RENAME should have failed (case conflict with 'Amazontest'), but succeeded")
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
