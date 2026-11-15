//go:build integration

package imap_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// Mailbox identity is PostgreSQL's LOWER(name) (the unique index of migration
// 000041), and lower() depends on the database collation. These tests ask the
// database which of their names it takes for one mailbox and expect RENAME and
// LIST (SUBSCRIBED) to agree, so they hold under any collation. The names are
// those where Go's case folding and lower() part ways:
//
//   - "ſx" / "sx": U+017F LATIN SMALL LETTER LONG S is lower case already, so
//     lower() keeps the names apart under every collation; strings.EqualFold
//     matches them.
//   - "İx" / "ix": U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE. strings.ToLower
//     and a libc collation give "i"; ICU gives "i̇", keeping the names apart.
//   - "ΑΣ" / "ας": ICU's lower() writes a word-final sigma as "ς" and takes the
//     names for one; strings.ToLower and a libc collation give "ασ".

// sameMailboxName reports whether the database takes a and b for one mailbox name.
func sameMailboxName(t *testing.T, server *common.TestServer, a, b string) bool {
	t.Helper()
	var same bool
	if err := server.ResilientDB.GetDatabase().GetWritePool().QueryRow(context.Background(),
		`SELECT LOWER($1::text) = LOWER($2::text)`, a, b).Scan(&same); err != nil {
		t.Fatalf("comparing %q and %q in the database: %v", a, b, err)
	}
	return same
}

func dialIdentityTestClient(t *testing.T, server *common.TestServer, email, password string) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	t.Cleanup(func() { c.Logout() })
	if err := c.Login(email, password).Wait(); err != nil {
		t.Fatalf("login as %s failed: %v", email, err)
	}
	return c
}

func listByName(t *testing.T, c *imapclient.Client, pattern string, opts *imap.ListOptions) map[string]*imap.ListData {
	t.Helper()
	mboxes, err := c.List("", pattern, opts).Collect()
	if err != nil {
		t.Fatalf("LIST %q failed: %v", pattern, err)
	}
	byName := make(map[string]*imap.ListData, len(mboxes))
	for _, m := range mboxes {
		if byName[m.Mailbox] != nil {
			t.Errorf("LIST %q answered %q twice", pattern, m.Mailbox)
		}
		byName[m.Mailbox] = m
	}
	return byName
}

func isIMAPCode(err error, code imap.ResponseCode) bool {
	var imapErr *imap.Error
	return errors.As(err, &imapErr) && imapErr.Type == imap.StatusResponseTypeNo && imapErr.Code == code
}

// TestIMAP_RenameSameNameIsTheDatabasesCall is issue #1622: RENAME refused
// `RENAME "ſx" "sx"` as a rename to the current name, because strings.EqualFold
// matched the names, although no mailbox "sx" exists.
func TestIMAP_RenameSameNameIsTheDatabasesCall(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialIdentityTestClient(t, server, account.Email, account.Password)

	for _, tc := range []struct{ from, to string }{
		{"ſx", "sx"},
		{"\u0130x", "ix"},
		{"ΑΣ", "ας"},
		{"Foo", "foo"},
	} {
		t.Run(tc.from+"→"+tc.to, func(t *testing.T) {
			same := sameMailboxName(t, server, tc.from, tc.to)
			if err := c.Create(tc.from, nil).Wait(); err != nil {
				t.Fatalf("CREATE %q: %v", tc.from, err)
			}
			err := c.Rename(tc.from, tc.to, nil).Wait()
			listed := listByName(t, c, "*", nil)
			if same {
				if !isIMAPCode(err, imap.ResponseCodeAlreadyExists) {
					t.Errorf("RENAME %q %q: %v, want NO [ALREADYEXISTS]: the database takes them for one mailbox", tc.from, tc.to, err)
				}
				if listed[tc.from] == nil {
					t.Errorf("%q not listed after the refused RENAME", tc.from)
				}
			} else {
				if err != nil {
					t.Errorf("RENAME %q %q: %v, want OK: no mailbox %q exists", tc.from, tc.to, err, tc.to)
				}
				if listed[tc.to] == nil || listed[tc.from] != nil {
					t.Errorf("after RENAME %q %q: %q listed %v, %q listed %v, want only %q", tc.from, tc.to,
						tc.from, listed[tc.from] != nil, tc.to, listed[tc.to] != nil, tc.to)
				}
			}
			c.Delete(tc.from).Wait()
			c.Delete(tc.to).Wait()
		})
	}
}

// TestIMAP_RenameBelowItselfIsTheDatabasesCall: RENAME refuses to move a mailbox
// below itself before creating the missing levels of the new name. Which level is
// the mailbox is the database's call. Under ICU, strings.ToLower took "İx/z/y" for
// a name below "ix" (refusing a legitimate RENAME) and "ας/z/y" for one that is not
// below "ΑΣ", so RENAME created "ας/z" below the mailbox and then failed.
func TestIMAP_RenameBelowItselfIsTheDatabasesCall(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialIdentityTestClient(t, server, account.Email, account.Password)

	for _, tc := range []struct{ mailbox, top string }{
		{"ix", "\u0130x"},
		{"ΑΣ", "ας"},
		{"sx", "ſx"},
	} {
		t.Run(tc.mailbox+"→"+tc.top, func(t *testing.T) {
			below := sameMailboxName(t, server, tc.mailbox, tc.top)
			if err := c.Create(tc.mailbox, nil).Wait(); err != nil {
				t.Fatalf("CREATE %q: %v", tc.mailbox, err)
			}
			middle := tc.top + "/z"
			target := middle + "/y"
			err := c.Rename(tc.mailbox, target, nil).Wait()
			listed := listByName(t, c, "*", nil)
			if below {
				if !isIMAPCode(err, imap.ResponseCodeCannot) {
					t.Errorf("RENAME %q %q: %v, want NO [CANNOT]: the database takes %q for the mailbox itself", tc.mailbox, target, err, tc.top)
				}
				if listed[tc.mailbox] == nil {
					t.Errorf("%q not listed after the refused RENAME", tc.mailbox)
				}
				for name := range listed {
					if sameMailboxName(t, server, name, middle) {
						t.Errorf("the refused RENAME created %q", name)
					}
				}
			} else {
				if err != nil {
					t.Errorf("RENAME %q %q: %v, want OK: %q is not %q to the database", tc.mailbox, target, err, tc.top, tc.mailbox)
				}
				if listed[target] == nil || listed[tc.mailbox] != nil {
					t.Errorf("after RENAME %q %q: %q listed %v, %q listed %v, want only %q", tc.mailbox, target,
						tc.mailbox, listed[tc.mailbox] != nil, target, listed[target] != nil, target)
				}
			}
			for _, name := range []string{target, middle, tc.top, tc.mailbox + "/z/y", tc.mailbox + "/z", tc.mailbox} {
				c.Delete(name).Wait()
			}
		})
	}
}

// TestIMAP_RenameInboxIsTheDatabasesCall: RFC 3501 §6.3.5 "Renaming INBOX is
// permitted, and has special behavior. It moves all messages in INBOX to a new
// mailbox with the given name, leaving INBOX empty." Which mailbox the client
// named is the database's call: under a libc collation "İNBOX" is the INBOX, which
// strings.EqualFold does not say, so RENAME renamed the INBOX itself away.
func TestIMAP_RenameInboxIsTheDatabasesCall(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialIdentityTestClient(t, server, account.Email, account.Password)

	name := "\u0130NBOX"
	isInbox := sameMailboxName(t, server, name, "INBOX")
	if !isInbox {
		if err := c.Create(name, nil).Wait(); err != nil {
			t.Fatalf("CREATE %q: %v", name, err)
		}
	}
	if err := c.Rename(name, "Moved", nil).Wait(); err != nil {
		t.Fatalf("RENAME %q Moved: %v", name, err)
	}
	listed := listByName(t, c, "*", nil)
	if listed["INBOX"] == nil {
		t.Errorf("RENAME %q Moved removed INBOX (the database takes %q for INBOX: %v)", name, name, isInbox)
	}
	if listed["Moved"] == nil {
		t.Errorf("RENAME %q Moved: Moved not listed", name)
	}
	if !isInbox && listed[name] != nil {
		t.Errorf("RENAME %q Moved: %q still listed", name, name)
	}
}

// TestIMAP_RenameParentComparedByDatabase: RFC 4314 §4 makes RENAME to another
// parent need the "k" right on it. "Shared/ſp" and "Shared/sp" are two mailboxes,
// but strings.EqualFold took them for the same parent, so a user without "k" on
// "Shared/sp" could move a mailbox into it.
func TestIMAP_RenameParentComparedByDatabase(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	email2, password2 := createSecondUser(t, server, "example.com", "renameparent")

	c1 := dialIdentityTestClient(t, server, owner.Email, owner.Password)

	ts := common.GetTimestamp()
	oldParent := fmt.Sprintf("Shared/ſp-%d", ts)
	newParent := fmt.Sprintf("Shared/sp-%d", ts)
	movable := oldParent + "/M"
	for _, mb := range []string{oldParent, movable, newParent} {
		if err := c1.Create(mb, nil).Wait(); err != nil {
			t.Fatalf("CREATE %q: %v", mb, err)
		}
	}
	defer func() {
		for _, mb := range []string{newParent + "/N", oldParent + "/N", movable, newParent, oldParent} {
			c1.Delete(mb).Wait()
		}
	}()
	if sameMailboxName(t, server, oldParent, newParent) {
		t.Fatalf("the database takes %q and %q for one mailbox", oldParent, newParent)
	}
	if err := c1.SetACL(movable, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lrx")).Wait(); err != nil {
		t.Fatalf("SETACL %q: %v", movable, err)
	}

	c2 := dialIdentityTestClient(t, server, email2, password2)

	moved := newParent + "/N"
	if err := c2.Rename(movable, moved, nil).Wait(); !isIMAPCode(err, imap.ResponseCodeNoPerm) {
		t.Errorf("RENAME %q %q without \"k\" on %q: %v, want NO [NOPERM]", movable, moved, newParent, err)
	}
	listed := listByName(t, c1, "Shared/*", nil)
	if listed[moved] != nil || listed[movable] == nil {
		t.Fatalf("after the RENAME into %q: %q listed %v, %q listed %v", newParent, movable, listed[movable] != nil, moved, listed[moved] != nil)
	}

	// Under the same parent the RENAME needs no "k".
	renamed := oldParent + "/N"
	if err := c2.Rename(movable, renamed, nil).Wait(); err != nil {
		t.Errorf("RENAME %q %q under the same parent: %v, want OK", movable, renamed, err)
	}
}

// TestIMAP_ListSubscribedKeysNamesAsTheDatabaseDoes is issue #1622: LIST
// (SUBSCRIBED) matched subscriptions with mailboxes by strings.ToLower, so two
// mailboxes the database keeps apart shared one entry (under ICU "İx" hid "ix"),
// and one mailbox subscribed under another spelling was listed twice (under ICU,
// "ΑΣ" subscribed as "ας" was also answered as a \NonExistent "ας", and got no
// STATUS from LIST-STATUS).
func TestIMAP_ListSubscribedKeysNamesAsTheDatabaseDoes(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialIdentityTestClient(t, server, account.Email, account.Password)

	subscribedOpts := &imap.ListOptions{
		SelectSubscribed: true,
		ReturnStatus:     &imap.StatusOptions{NumMessages: true},
	}
	for _, tc := range []struct{ mailbox, subscribed string }{
		{"ix", "\u0130x"},
		{"\u0130x", "ix"},
		{"ΑΣ", "ας"},
		{"sx", "ſx"},
	} {
		t.Run(tc.mailbox+"+"+tc.subscribed, func(t *testing.T) {
			same := sameMailboxName(t, server, tc.mailbox, tc.subscribed)
			mailboxes := []string{tc.mailbox}
			if !same {
				mailboxes = append(mailboxes, tc.subscribed)
			}
			for _, mb := range mailboxes {
				if err := c.Create(mb, nil).Wait(); err != nil {
					t.Fatalf("CREATE %q: %v", mb, err)
				}
				defer func(mb string) { c.Delete(mb).Wait() }(mb)
			}
			if err := c.Subscribe(tc.subscribed).Wait(); err != nil {
				t.Fatalf("SUBSCRIBE %q: %v", tc.subscribed, err)
			}
			defer func() { c.Unsubscribe(tc.subscribed).Wait() }()

			// The mailbox the database takes the subscribed name for, listed by its name.
			want := tc.subscribed
			if same {
				want = tc.mailbox
			}
			listed := listByName(t, c, "*", subscribedOpts)
			got := listed[want]
			if got == nil {
				t.Fatalf("LIST (SUBSCRIBED): %q not listed; listed %v", want, mapKeys(listed))
			}
			if !slices.Contains(got.Attrs, imap.MailboxAttrSubscribed) || slices.Contains(got.Attrs, imap.MailboxAttrNonExistent) {
				t.Errorf("LIST (SUBSCRIBED): %q has %v, want \\Subscribed without \\NonExistent", want, got.Attrs)
			}
			if got.Status == nil {
				t.Errorf("LIST (SUBSCRIBED) RETURN (STATUS): no STATUS for subscribed mailbox %q", want)
			}
			for _, name := range append(mailboxes, tc.subscribed) {
				if name != want && listed[name] != nil {
					t.Errorf("LIST (SUBSCRIBED) also listed %q (%v); only %q is subscribed", name, listed[name].Attrs, want)
				}
			}
		})
	}

	// The issue's own steps: "İNBOX" subscribed next to the INBOX, where the database
	// keeps the two apart (ICU). Both are subscribed, so both are listed.
	t.Run("İNBOX next to INBOX", func(t *testing.T) {
		name := "İNBOX"
		if sameMailboxName(t, server, name, "INBOX") {
			t.Skipf("the database takes %q for INBOX", name)
		}
		if err := c.Create(name, nil).Wait(); err != nil {
			t.Fatalf("CREATE %q: %v", name, err)
		}
		defer func() { c.Delete(name).Wait() }()
		if err := c.Subscribe(name).Wait(); err != nil {
			t.Fatalf("SUBSCRIBE %q: %v", name, err)
		}
		defer func() { c.Unsubscribe(name).Wait() }()

		listed := listByName(t, c, "*", &imap.ListOptions{SelectSubscribed: true})
		for _, want := range []string{"INBOX", name} {
			if got := listed[want]; got == nil || !slices.Contains(got.Attrs, imap.MailboxAttrSubscribed) || slices.Contains(got.Attrs, imap.MailboxAttrNonExistent) {
				t.Errorf("LIST (SUBSCRIBED) \"\" *: want live %q listed \\Subscribed; got %+v; listed %v", want, got, mapKeys(listed))
			}
		}
	})

	// RECURSIVEMATCH reports a parent of a subscribed name with CHILDINFO, and the
	// parent is the mailbox the database takes the subscribed name's top level for.
	t.Run("RECURSIVEMATCH", func(t *testing.T) {
		same := sameMailboxName(t, server, "ir", "\u0130r")
		mailboxes := []string{"ir"}
		if !same {
			mailboxes = append(mailboxes, "\u0130r")
		}
		for _, mb := range mailboxes {
			if err := c.Create(mb, nil).Wait(); err != nil {
				t.Fatalf("CREATE %q: %v", mb, err)
			}
			defer func(mb string) { c.Delete(mb).Wait() }(mb)
		}
		if err := c.Subscribe("ir/c").Wait(); err != nil {
			t.Fatalf("SUBSCRIBE ir/c: %v", err)
		}
		defer func() { c.Unsubscribe("ir/c").Wait() }()

		listed := listByName(t, c, "%", &imap.ListOptions{SelectSubscribed: true, SelectRecursiveMatch: true})
		got := listed["ir"]
		if got == nil || got.ChildInfo == nil || !got.ChildInfo.Subscribed {
			t.Errorf("LIST (SUBSCRIBED RECURSIVEMATCH) \"\" %%: want ir with CHILDINFO (SUBSCRIBED), got %+v; listed %v", got, mapKeys(listed))
		}
		if !same && listed["\u0130r"] != nil {
			t.Errorf("LIST (SUBSCRIBED RECURSIVEMATCH) \"\" %%: listed \u0130r (%+v), which has no subscribed child", listed["\u0130r"])
		}
	})
}

func mapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
