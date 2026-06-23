//go:build integration

package imap_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestCreateRejectsPathTraversal verifies that mailbox names containing "."/".."
// path segments are rejected over the wire by CREATE and RENAME (security audit
// M5). Such names would otherwise let the maildir exporter escape its target
// directory and write arbitrary files on disk. The server must return NO and
// must not persist the mailbox.
func TestCreateRejectsPathTraversal(t *testing.T) {
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

	// Sanity: a legitimately nested name must still be creatable (control).
	if err := c.Create("Archive/2024", nil).Wait(); err != nil {
		t.Fatalf("Control CREATE \"Archive/2024\" should succeed: %v", err)
	}

	traversalNames := []string{
		"..",
		".",
		"../evil",
		"../../tmp/evil",
		"../../../tmp/evil",
		"foo/../bar",
		"foo/..",
		"Archive/../../secret",
	}

	for _, name := range traversalNames {
		t.Run("create "+name, func(t *testing.T) {
			err := c.Create(name, nil).Wait()
			if err == nil {
				t.Fatalf("CREATE %q should be rejected, but it succeeded", name)
			}
			var imapErr *imap.Error
			if !errors.As(err, &imapErr) {
				t.Fatalf("CREATE %q: expected *imap.Error, got %T: %v", name, err, err)
			}
			if imapErr.Type != imap.StatusResponseTypeNo {
				t.Fatalf("CREATE %q: expected NO response, got %v: %v", name, imapErr.Type, err)
			}
			if imapErr.Code != imap.ResponseCodeCannot {
				t.Errorf("CREATE %q: expected [CANNOT] code, got [%v]", name, imapErr.Code)
			}
			t.Logf("CREATE %q correctly rejected: %v", name, err)
		})
	}

	// RENAME must reject traversal targets too.
	t.Run("rename to traversal target", func(t *testing.T) {
		if err := c.Create("RenameSource", nil).Wait(); err != nil {
			t.Fatalf("Failed to create RenameSource: %v", err)
		}
		err := c.Rename("RenameSource", "../evil", nil).Wait()
		if err == nil {
			t.Fatalf("RENAME to \"../evil\" should be rejected, but it succeeded")
		}
		var imapErr *imap.Error
		if !errors.As(err, &imapErr) || imapErr.Type != imap.StatusResponseTypeNo {
			t.Fatalf("RENAME to \"../evil\": expected NO response, got %T: %v", err, err)
		}
		if imapErr.Code != imap.ResponseCodeCannot {
			t.Errorf("RENAME to \"../evil\": expected [CANNOT] code, got [%v]", imapErr.Code)
		}
		t.Logf("RENAME to \"../evil\" correctly rejected: %v", err)
	})

	// None of the rejected names may have been persisted. List everything and
	// assert no name carries a ".."/"." segment.
	mboxes, err := c.List("", "*", nil).Collect()
	if err != nil {
		t.Fatalf("LIST failed: %v", err)
	}
	for _, mbox := range mboxes {
		for _, seg := range strings.Split(mbox.Mailbox, "/") {
			if seg == "." || seg == ".." {
				t.Errorf("traversal mailbox was persisted: %q", mbox.Mailbox)
			}
		}
	}
}
