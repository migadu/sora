//go:build integration

package imap_test

import (
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestSTORE_CONDSTORE_ModifiedResponse tests that STORE with UNCHANGEDSINCE
// returns a NO [MODIFIED <uid-set>] response when the precondition fails.
// RFC 7162 §3.1.3 requires this response.
func TestSTORE_CONDSTORE_ModifiedResponse(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// First client: append and modify message to establish a known MODSEQ
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Append a message
	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: CONDSTORE Test\r\nDate: Thu, 01 Jan 2026 00:00:00 +0000\r\nMessage-ID: <condstore-test@example.com>\r\n\r\nTest body.\r\n"
	appendCmd := c1.Append("INBOX", int64(len(msg)), nil)
	if _, err := appendCmd.Write([]byte(msg)); err != nil {
		t.Fatalf("Failed to write: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// SELECT with CONDSTORE
	selectData, err := c1.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}
	if selectData.NumMessages != 1 {
		t.Fatalf("Expected 1 message, got %d", selectData.NumMessages)
	}

	// First STORE: set \Seen flag (this establishes a MODSEQ > 1)
	storeCmd := c1.Store(imap.UIDSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("First STORE failed: %v", err)
	}
	t.Log("First STORE succeeded (set \\Seen)")

	// Second STORE: try with UNCHANGEDSINCE=1 (stale — message was modified above)
	// This should fail with MODIFIED for UID 1
	storeCmd2 := c1.Store(imap.UIDSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagFlagged},
	}, &imap.StoreOptions{
		UnchangedSince: 1, // Stale MODSEQ — message has been modified
	})
	err = storeCmd2.Close()

	// The server SHOULD return a NO [MODIFIED 1] or the store should indicate
	// which UIDs were not modified. The error response should contain MODIFIED.
	if err != nil {
		t.Logf("STORE with stale UNCHANGEDSINCE returned error (expected): %v", err)
		// Check if error mentions MODIFIED
		errStr := err.Error()
		if stringContains(errStr, "MODIFIED") || stringContains(errStr, "modified") {
			t.Log("✓ Server correctly returned MODIFIED response code")
		} else {
			t.Errorf("Expected MODIFIED response code in error, got: %s", errStr)
		}
	} else {
		// If no error, the STORE may have silently skipped the message.
		// RFC 7162 requires the server to report which UIDs were not modified.
		t.Error("STORE with stale UNCHANGEDSINCE should return MODIFIED response, but succeeded silently")
	}
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
