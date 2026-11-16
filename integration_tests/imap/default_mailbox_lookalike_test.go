//go:build integration

package imap_test

import (
	"errors"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func listMailboxNames(t *testing.T, c *imapclient.Client, opts *imap.ListOptions) map[string]bool {
	t.Helper()
	mboxes, err := c.List("", "*", opts).Collect()
	if err != nil {
		t.Fatalf("LIST failed: %v", err)
	}
	names := make(map[string]bool, len(mboxes))
	for _, m := range mboxes {
		names[m.Mailbox] = true
	}
	return names
}

// TestIMAP_DefaultMailboxLookalikesAreOrdinaryMailboxes is issue #1584. Mailbox
// identity is LOWER(name) in PostgreSQL, and lower('ſent') is 'ſent': U+017F LATIN
// SMALL LETTER LONG S is already lower case, so "ſent" is a mailbox of its own next
// to "Sent". DELETE refused it as a special mailbox, and UNSUBSCRIBE answered OK but
// kept the subscription, because both matched it with "Sent" by case folding, which
// puts ſ together with s.
func TestIMAP_DefaultMailboxLookalikesAreOrdinaryMailboxes(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	for _, tc := range []struct{ name, def string }{
		{"ſent", "Sent"},
		{"Draftſ", "Drafts"},
		{"Traſh", "Trash"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := c.Create(tc.name, nil).Wait(); err != nil {
				t.Fatalf("CREATE %q: %v", tc.name, err)
			}
			if err := c.Subscribe(tc.name).Wait(); err != nil {
				t.Fatalf("SUBSCRIBE %q: %v", tc.name, err)
			}

			if err := c.Unsubscribe(tc.name).Wait(); err != nil {
				t.Fatalf("UNSUBSCRIBE %q: %v", tc.name, err)
			}
			subscribed := listMailboxNames(t, c, &imap.ListOptions{SelectSubscribed: true})
			if subscribed[tc.name] {
				t.Errorf("UNSUBSCRIBE %q answered OK but kept the subscription", tc.name)
			}
			if !subscribed[tc.def] {
				t.Errorf("UNSUBSCRIBE %q unsubscribed %q", tc.name, tc.def)
			}

			if err := c.Delete(tc.name).Wait(); err != nil {
				t.Errorf("DELETE %q: %v, want OK: it is not the %s mailbox", tc.name, err, tc.def)
			}
			all := listMailboxNames(t, c, nil)
			if all[tc.name] {
				t.Errorf("%q still listed after DELETE", tc.name)
			}
			if !all[tc.def] {
				t.Errorf("DELETE %q removed %q", tc.name, tc.def)
			}
		})
	}
}

// TestIMAP_DefaultMailboxNamesInAnyCaseAreProtected keeps DELETE and UNSUBSCRIBE
// from removing a default mailbox or its subscription under any name the database
// takes for it. Which names those are depends on the collation's lower():
// "Jun\u212A" ends in U+212A KELVIN SIGN, which lower() maps to "k" under a libc or
// ICU UTF-8 collation, so a match that folded only ASCII letters would let DELETE
// remove Junk; "\u0130NBOX" starts with U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE,
// which a libc collation maps to "i" (ICU keeps it apart), and strings.EqualFold,
// which did not take it for INBOX, let DELETE remove the INBOX there. So DELETE must
// answer NO (NOPERM, or NONEXISTENT where the collation keeps the name apart and no
// such mailbox exists) and the default mailbox must stay, listed and subscribed.
func TestIMAP_DefaultMailboxNamesInAnyCaseAreProtected(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	for _, tc := range []struct{ name, def string }{
		{"sent", "Sent"},
		{"DRAFTS", "Drafts"},
		{"inbox", "INBOX"},
		{"Jun\u212A", "Junk"},
		{"\u0130NBOX", "INBOX"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var imapErr *imap.Error
			if err := c.Delete(tc.name).Wait(); !errors.As(err, &imapErr) || imapErr.Type != imap.StatusResponseTypeNo {
				t.Errorf("DELETE %q: %v, want NO", tc.name, err)
			}
			if !listMailboxNames(t, c, nil)[tc.def] {
				t.Fatalf("DELETE %q removed %q", tc.name, tc.def)
			}

			if err := c.Unsubscribe(tc.name).Wait(); err != nil {
				t.Fatalf("UNSUBSCRIBE %q: %v", tc.name, err)
			}
			if !listMailboxNames(t, c, &imap.ListOptions{SelectSubscribed: true})[tc.def] {
				t.Errorf("UNSUBSCRIBE %q unsubscribed default mailbox %q", tc.name, tc.def)
			}
		})
	}
}
