//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_Create_TrailingSeparator_StripsToBareName is a regression test for a
// Medium audit finding (Unit 2, 2026-07-01).
//
// server/imap/create.go strips the trailing hierarchy separator only for parent
// detection, then creates the mailbox under the ORIGINAL name. So CREATE "foo/"
// persists a mailbox literally named "foo/". RFC 3501 §6.3.3 treats a trailing
// separator as an intent marker ("this mailbox may have inferiors"), not part of
// the stored name — the result should be a mailbox named "foo".
//
// Expected: LIST shows "MTrail" (no trailing separator).
// Actual (bug): a mailbox literally named "MTrail/" is created.
func TestIMAP_Create_TrailingSeparator_StripsToBareName(t *testing.T) {
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

	if err := c.Create("MTrail/", nil).Wait(); err != nil {
		t.Fatalf("CREATE \"MTrail/\" failed: %v", err)
	}

	mboxes, err := c.List("", "*", nil).Collect()
	if err != nil {
		t.Fatalf("LIST failed: %v", err)
	}
	names := make(map[string]bool)
	for _, m := range mboxes {
		names[m.Mailbox] = true
	}
	t.Logf("mailboxes after CREATE \"MTrail/\": %v", keysOf(names))

	if names["MTrail/"] && !names["MTrail"] {
		t.Errorf("REGRESSION: CREATE \"MTrail/\" produced a mailbox named %q; "+
			"RFC 3501 §6.3.3 — the trailing separator is an intent marker, the stored name should be \"MTrail\".",
			"MTrail/")
	} else if !names["MTrail"] {
		t.Errorf("expected a mailbox named \"MTrail\" after CREATE \"MTrail/\", got: %v", keysOf(names))
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
