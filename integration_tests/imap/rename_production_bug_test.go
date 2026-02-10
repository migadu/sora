//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestMailbox_RenameProductionBug reproduces the exact production error:
// User tries to rename "amazon" to "amazontest" but "amazontest" already exists.
//
// Production error log:
// failed to rename mailbox 'amazon' to 'amazontest': failed to update child mailboxes:
// ERROR: duplicate key value violates unique constraint "mailboxes_account_id_name_unique" (SQLSTATE 23505)
//
// This happens because:
// 1. User has mailbox "amazon" (possibly with children like "amazon/subfolder")
// 2. User also has mailbox "amazontest" (created separately)
// 3. User tries to rename "amazon" to "amazontest"
// 4. BUG: The existence check uses wrong AccountID and doesn't detect the conflict
// 5. The UPDATE then fails with duplicate key constraint violation
func TestMailbox_RenameProductionBug(t *testing.T) {
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

	// Reproduce the exact production scenario:
	// 1. Create "amazon" mailbox
	if err := c.Create("amazon", nil).Wait(); err != nil {
		t.Fatalf("CREATE amazon failed: %v", err)
	}
	t.Logf("✓ Created mailbox: amazon")

	// 2. Create "amazon/subfolder" (child)
	if err := c.Create("amazon/subfolder", nil).Wait(); err != nil {
		t.Fatalf("CREATE amazon/subfolder failed: %v", err)
	}
	t.Logf("✓ Created mailbox: amazon/subfolder")

	// 3. Create "amazontest" (the conflict target)
	if err := c.Create("amazontest", nil).Wait(); err != nil {
		t.Fatalf("CREATE amazontest failed: %v", err)
	}
	t.Logf("✓ Created mailbox: amazontest")

	// 4. Try to rename "amazon" to "amazontest"
	// BUG: This should fail cleanly with "already exists" error
	// but instead fails with database constraint violation
	err = c.Rename("amazon", "amazontest", nil).Wait()

	if err == nil {
		t.Errorf("RENAME should have failed because 'amazontest' already exists, but succeeded")
	} else {
		t.Logf("✓ RENAME correctly failed: %v", err)

		// Check that it's the right kind of error (not a database constraint violation)
		errStr := err.Error()
		if containsAny(errStr, []string{"SQLSTATE", "23505", "duplicate key", "unique constraint"}) {
			t.Errorf("Got database constraint violation (BUG!): %v", err)
			t.Errorf("Expected user-friendly 'already exists' error instead")
		} else if !containsAny(errStr, []string{"exists", "ALREADYEXISTS"}) {
			t.Errorf("Expected 'already exists' error, got: %v", err)
		}
	}

	// Verify that nothing was corrupted
	listCmd := c.List("", "amazon", nil)
	mboxes, err := listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST amazon failed: %v", err)
	}
	if len(mboxes) == 0 {
		t.Errorf("Original mailbox 'amazon' disappeared after failed rename")
	} else {
		t.Logf("✓ Original mailbox 'amazon' still exists")
	}

	listCmd = c.List("", "amazon/subfolder", nil)
	mboxes, err = listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST amazon/subfolder failed: %v", err)
	}
	if len(mboxes) == 0 {
		t.Errorf("Child mailbox 'amazon/subfolder' disappeared after failed rename")
	} else {
		t.Logf("✓ Child mailbox 'amazon/subfolder' still exists")
	}

	listCmd = c.List("", "amazontest", nil)
	mboxes, err = listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST amazontest failed: %v", err)
	}
	if len(mboxes) == 0 {
		t.Errorf("Existing mailbox 'amazontest' disappeared")
	} else {
		t.Logf("✓ Existing mailbox 'amazontest' unchanged")
	}
}

// Helper function to check if string contains any of the substrings
func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if containsStr(s, substr) {
			return true
		}
	}
	return false
}

// Helper function to check if a string contains a substring (case-insensitive)
func containsStr(s, substr string) bool {
	// Simple substring search (could be improved with strings.Contains)
	sLen := len(s)
	subLen := len(substr)
	if subLen == 0 {
		return true
	}
	if subLen > sLen {
		return false
	}
	for i := 0; i <= sLen-subLen; i++ {
		match := true
		for j := 0; j < subLen; j++ {
			// Case-insensitive comparison
			c1 := s[i+j]
			c2 := substr[j]
			if c1 >= 'A' && c1 <= 'Z' {
				c1 = c1 + ('a' - 'A')
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 = c2 + ('a' - 'A')
			}
			if c1 != c2 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
