//go:build integration

package imap_test

import (
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestCreateRenameRefuseEmptyHierarchyLevel is issue #566. CREATE and RENAME create
// the superior names a new name needs (RFC 9051 §6.3.4, §6.3.6), so a name with an
// empty level ("x//y", "/lead") made a parent "x/" or "" on the way. Such a name is
// refused with NO [CANNOT], as "." and ".." levels are, and creates nothing. A
// trailing delimiter on RENAME names the same mailbox as without it, as on CREATE:
// "the name created is without the trailing hierarchy delimiter" (RFC 9051 §6.3.4).
func TestCreateRenameRefuseEmptyHierarchyLevel(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer c.Close()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// A TAB, which the database refuses in any name, is refused as cleanly, not with
	// NO [SERVERBUG] once the database refuses it.
	for _, name := range []string{"x//y", "/lead", "x//y/", "a/b//c", "t/tab\tname"} {
		t.Run("CREATE "+name, func(t *testing.T) {
			requireResponseCode(t, c.Create(name, nil).Wait(), imap.ResponseCodeCannot, "CREATE "+name)
		})
	}

	if err := c.Create("Plain", nil).Wait(); err != nil {
		t.Fatalf("CREATE Plain: %v", err)
	}
	for _, to := range []string{"u/tab\tname", "r//s", "/lead2", "p//q/"} {
		t.Run("RENAME Plain "+to, func(t *testing.T) {
			requireResponseCode(t, c.Rename("Plain", to, nil).Wait(), imap.ResponseCodeCannot, "RENAME Plain "+to)
		})
	}
	t.Run("RENAME INBOX i//j", func(t *testing.T) {
		requireResponseCode(t, c.Rename("INBOX", "i//j", nil).Wait(), imap.ResponseCodeCannot, "RENAME INBOX i//j")
	})

	if err := c.Create("Plain2", nil).Wait(); err != nil {
		t.Fatalf("CREATE Plain2: %v", err)
	}
	if err := c.Rename("Plain2", "Foo/", nil).Wait(); err != nil {
		t.Fatalf("RENAME Plain2 Foo/: %v", err)
	}

	mboxes, err := c.List("", "*", nil).Collect()
	if err != nil {
		t.Fatalf("LIST failed: %v", err)
	}
	names := make(map[string]bool, len(mboxes))
	for _, mbox := range mboxes {
		names[mbox.Mailbox] = true
		for _, level := range strings.Split(mbox.Mailbox, "/") {
			if level == "" {
				t.Errorf("mailbox with an empty hierarchy level was created: %q", mbox.Mailbox)
				break
			}
		}
	}
	// No refused name may have created a parent on the way.
	for _, parent := range []string{"x", "a", "a/b", "r", "p", "i", "t", "u"} {
		if names[parent] {
			t.Errorf("refused name created the parent %q", parent)
		}
	}
	if !names["Plain"] {
		t.Errorf("Plain is gone after refused RENAMEs")
	}
	if !names["Foo"] || names["Plain2"] {
		t.Errorf(`RENAME Plain2 "Foo/" must rename Plain2 to Foo; LIST: %v`, names)
	}
}
