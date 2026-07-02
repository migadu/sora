//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_RenameInbox_HierarchicalDest_CreatesParent is a regression test for a
// Medium audit finding (Unit 2, 2026-07-01).
//
// server/imap/rename.go's INBOX-special branch always creates the destination
// with a nil parent, so RENAME INBOX "Parent/Child" persists a flat mailbox
// literally named "Parent/Child" with no "Parent" node — inconsistent with both
// CREATE and the non-INBOX RENAME path, which auto-create missing parents.
//
// Expected: after RENAME INBOX "MArch/2026", the parent "MArch" exists in LIST.
// Actual (bug): only the flat "MArch/2026" row exists; "MArch" is missing.
func TestIMAP_RenameInbox_HierarchicalDest_CreatesParent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if err := c.Rename("INBOX", "MArch/2026", nil).Wait(); err != nil {
		t.Fatalf("RENAME INBOX \"MArch/2026\" failed: %v", err)
	}

	mboxes, err := c.List("", "*", nil).Collect()
	if err != nil {
		t.Fatalf("LIST failed: %v", err)
	}
	names := make(map[string]bool)
	for _, m := range mboxes {
		names[m.Mailbox] = true
	}
	t.Logf("mailboxes after RENAME INBOX \"MArch/2026\": %v", keysOf(names))

	if !names["MArch/2026"] {
		t.Fatalf("sanity: expected the renamed destination \"MArch/2026\" to exist, got: %v", keysOf(names))
	}
	if !names["MArch"] {
		t.Errorf("REGRESSION: RENAME INBOX \"MArch/2026\" did not auto-create the parent "+
			"\"MArch\" (INBOX branch passes a nil parent); CREATE and non-INBOX RENAME both auto-create "+
			"parents. Got: %v", keysOf(names))
	}
}
