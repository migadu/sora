//go:build integration

package imap_test

import (
	"errors"
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// listAttrs returns the LIST attributes for a single mailbox by exact name.
func listAttrs(t *testing.T, c *imapclient.Client, mailbox string) []imap.MailboxAttr {
	t.Helper()
	mboxes, err := c.List("", mailbox, nil).Collect()
	if err != nil {
		t.Fatalf("LIST %q failed: %v", mailbox, err)
	}
	for _, m := range mboxes {
		if m.Mailbox == mailbox {
			return m.Attrs
		}
	}
	t.Fatalf("mailbox %q not found in LIST", mailbox)
	return nil
}

// TestIMAP_CreateSpecialUse_Persisted verifies that CREATE ... USE (\Sent)
// (RFC 6154) is honored: the special-use attribute is stored and reported by
// LIST, even when the mailbox name is not a well-known folder name.
//
// Currently special-use is derived by uppercasing the mailbox name
// (server/imap/list.go), and Create ignores options.SpecialUse entirely, so a
// mailbox named "MySent" created with USE (\Sent) gets no \Sent attribute.
func TestIMAP_CreateSpecialUse_Persisted(t *testing.T) {
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

	// Free the \Sent role first: the default "Sent" holds it, and special-use is
	// unique per account (RFC 6154 §5), so CREATE ... USE (\Sent) would otherwise
	// be rejected. Default folders can't be deleted under their protected names, so
	// rename it off "Sent" and then delete it (which soft-deletes, freeing \Sent).
	if err := c.Rename("Sent", "TempSent", nil).Wait(); err != nil {
		t.Fatalf("RENAME Sent -> TempSent failed: %v", err)
	}
	if err := c.Delete("TempSent").Wait(); err != nil {
		t.Fatalf("DELETE TempSent failed: %v", err)
	}

	if err := c.Create("MySent", &imap.CreateOptions{
		SpecialUse: []imap.MailboxAttr{imap.MailboxAttrSent},
	}).Wait(); err != nil {
		t.Fatalf("CREATE MySent (USE (\\Sent)) failed: %v", err)
	}

	attrs := listAttrs(t, c, "MySent")
	t.Logf("MySent attrs: %v", attrs)
	if !hasAttr(attrs, imap.MailboxAttrSent) {
		t.Errorf("CREATE ... USE (\\Sent) not honored: LIST %q has no \\Sent attribute (got %v)", "MySent", attrs)
	}
}

// TestIMAP_SpecialUse_SurvivesRename verifies that a folder's special-use
// attribute survives a RENAME. With name-based derivation, renaming the default
// "Sent" to a localized name loses \Sent; with a persisted attribute it must be
// preserved.
func TestIMAP_SpecialUse_SurvivesRename(t *testing.T) {
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

	// Sanity: the default "Sent" carries \Sent.
	if !hasAttr(listAttrs(t, c, "Sent"), imap.MailboxAttrSent) {
		t.Fatalf("sanity: default \"Sent\" does not carry \\Sent")
	}

	if err := c.Rename("Sent", "Gesendet", nil).Wait(); err != nil {
		t.Fatalf("RENAME Sent -> Gesendet failed: %v", err)
	}

	attrs := listAttrs(t, c, "Gesendet")
	t.Logf("Gesendet attrs after rename: %v", attrs)
	if !hasAttr(attrs, imap.MailboxAttrSent) {
		t.Errorf("special-use lost on RENAME: \"Gesendet\" has no \\Sent attribute (got %v)", attrs)
	}
}

// TestIMAP_CreateSpecialUse_DuplicateRejected verifies RFC 6154 §5 uniqueness:
// a special-use attribute is assigned to at most one mailbox. The default "Sent"
// already holds \Sent, so creating a second \Sent mailbox must be rejected with
// NO [USEATTR].
func TestIMAP_CreateSpecialUse_DuplicateRejected(t *testing.T) {
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

	// The default "Sent" already carries \Sent; a second one must be refused.
	err = c.Create("MySent", &imap.CreateOptions{
		SpecialUse: []imap.MailboxAttr{imap.MailboxAttrSent},
	}).Wait()
	if err == nil {
		t.Fatalf("CREATE ... USE (\\Sent) should be rejected as a duplicate (default Sent holds \\Sent)")
	}
	var imapErr *imap.Error
	if errors.As(err, &imapErr) {
		t.Logf("rejected with: NO [%s] %s", imapErr.Code, imapErr.Text)
		if string(imapErr.Code) != "USEATTR" {
			t.Errorf("expected response code USEATTR, got %q", imapErr.Code)
		}
	} else {
		t.Errorf("expected *imap.Error, got %T: %v", err, err)
	}

	// The duplicate is rejected before creation, so MySent must not exist at all
	// (no half-created mailbox left behind).
	mboxes, lerr := c.List("", "MySent", nil).Collect()
	if lerr != nil {
		t.Fatalf("LIST failed: %v", lerr)
	}
	for _, m := range mboxes {
		if m.Mailbox == "MySent" {
			t.Errorf("MySent should not exist after a rejected duplicate CREATE ... USE")
		}
	}
}

// TestIMAP_CreateSpecialUse_UnsupportedRejected verifies that CREATE with an
// unsupported special-use attribute is rejected with NO [USEATTR] (RFC 6154 §3)
// rather than silently creating the mailbox without the attribute.
func TestIMAP_CreateSpecialUse_UnsupportedRejected(t *testing.T) {
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

	// \All is not a special-use Sora supports.
	err = c.Create("VirtualAll", &imap.CreateOptions{
		SpecialUse: []imap.MailboxAttr{imap.MailboxAttrAll},
	}).Wait()
	if err == nil {
		t.Fatalf("CREATE ... USE (\\All) should be rejected with NO [USEATTR] (unsupported attr), but succeeded")
	}
	var imapErr *imap.Error
	if errors.As(err, &imapErr) {
		t.Logf("rejected with: NO [%s] %s", imapErr.Code, imapErr.Text)
		if string(imapErr.Code) != "USEATTR" {
			t.Errorf("expected response code USEATTR, got %q", imapErr.Code)
		}
	} else {
		t.Errorf("expected *imap.Error, got %T: %v", err, err)
	}
}
