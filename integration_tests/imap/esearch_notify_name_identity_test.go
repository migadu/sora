//go:build integration

package imap_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// The tests of this file are issue #1649: ESEARCH (RFC 7377 MULTISEARCH)
// resolved its sources, and NOTIFY (RFC 5465) matched its mailbox specifiers
// and diffed its snapshots, by names compared in Go. Which names are one
// mailbox is the database's LOWER(name) under its collation (see
// mailbox_name_identity_test.go), so the tests ask the database and hold under
// any collation.

// identityNamePairs are pairs of names where Go's case mapping and lower() part
// ways under some collation.
var identityNamePairs = []struct{ mailbox, other string }{
	{"ix", "\u0130x"}, // U+0130: one mailbox under libc, two under ICU
	{"\u0130x", "ix"},
	{"ΑΣ", "ας"}, // word-final sigma: one mailbox under ICU, two under libc
	{"sx", "ſx"}, // U+017F: two mailboxes under every collation
	{"ſx", "sx"},
	{"Kx", "\u212Ax"}, // U+212A KELVIN SIGN: one mailbox under libc and ICU
}

func identityAppend(t *testing.T, c *imapclient.Client, mailbox string) {
	t.Helper()
	msg := "From: sender@example.com\r\nTo: user@example.com\r\nSubject: identity\r\n\r\nbody\r\n"
	cmd := c.Append(mailbox, int64(len(msg)), nil)
	if _, err := cmd.Write([]byte(msg)); err != nil {
		t.Fatalf("APPEND %q: %v", mailbox, err)
	}
	if err := cmd.Close(); err != nil {
		t.Fatalf("APPEND %q: %v", mailbox, err)
	}
	if _, err := cmd.Wait(); err != nil {
		t.Fatalf("APPEND %q: %v", mailbox, err)
	}
}

// esearchSourceMailboxes runs ESEARCH IN (source) ALL and returns the mailboxes it
// answered an ESEARCH response for.
func esearchSourceMailboxes(t *testing.T, c *imapclient.Client, source *imap.SearchSource) []string {
	t.Helper()
	results, err := c.MultiSearch(source, &imap.SearchCriteria{}, &imap.SearchOptions{ReturnAll: true}).Wait()
	if err != nil {
		t.Fatalf("ESEARCH IN (%+v) ALL: %v", source, err)
	}
	var names []string
	for _, r := range results {
		names = append(names, r.Mailbox)
	}
	slices.Sort(names)
	return names
}

// TestIMAP_ESearchSourcesResolveNamesAsTheDatabaseDoes: ESEARCH IN (...) keyed
// the account's mailboxes by strings.ToLower, so under ICU "İNBOX" stood in for
// the INBOX, and SUBTREE "ix" also searched below "İx" while SUBTREE "ας" found
// nothing below "ΑΣ".
func TestIMAP_ESearchSourcesResolveNamesAsTheDatabaseDoes(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialIdentityTestClient(t, server, account.Email, account.Password)

	// The issue's steps.
	t.Run("İNBOX next to INBOX", func(t *testing.T) {
		name := "İNBOX"
		if sameMailboxName(t, server, name, "INBOX") {
			t.Skipf("the database takes %q for INBOX", name)
		}
		if err := c.Create(name, nil).Wait(); err != nil {
			t.Fatalf("CREATE %q: %v", name, err)
		}
		defer func() { c.Delete(name).Wait() }()
		identityAppend(t, c, "INBOX")
		if _, err := c.Select("INBOX", nil).Wait(); err != nil {
			t.Fatalf("SELECT INBOX: %v", err)
		}
		defer func() { c.Unselect().Wait() }()

		for _, tc := range []struct {
			name   string
			source *imap.SearchSource
		}{
			{"INBOXES", &imap.SearchSource{Inboxes: true}},
			{"SELECTED", &imap.SearchSource{Selected: true}},
			{`MAILBOXES "INBOX"`, &imap.SearchSource{Mailboxes: []string{"INBOX"}}},
		} {
			if got := esearchSourceMailboxes(t, c, tc.source); !slices.Equal(got, []string{"INBOX"}) {
				t.Errorf("ESEARCH IN (%s) ALL answered for %q, want INBOX", tc.name, got)
			}
		}
	})

	for _, tc := range identityNamePairs {
		t.Run(tc.mailbox+"/"+tc.other, func(t *testing.T) {
			same := sameMailboxName(t, server, tc.mailbox, tc.other)
			child := tc.mailbox + "/x"
			if err := c.Create(child, nil).Wait(); err != nil {
				t.Fatalf("CREATE %q: %v", child, err)
			}
			defer func() { c.Delete(tc.mailbox).Wait() }()
			defer func() { c.Delete(child).Wait() }()
			identityAppend(t, c, child)

			// Searched only when the database takes tc.other for tc.mailbox.
			var want []string
			if same {
				want = []string{child}
			}
			for _, src := range []struct {
				name   string
				source *imap.SearchSource
			}{
				{"SUBTREE " + tc.other, &imap.SearchSource{Subtree: []string{tc.other}}},
				{"SUBTREE-ONE " + tc.other, &imap.SearchSource{SubtreeOne: []string{tc.other}}},
				{"MAILBOXES " + tc.other + "/x", &imap.SearchSource{Mailboxes: []string{tc.other + "/x"}}},
			} {
				if got := esearchSourceMailboxes(t, c, src.source); !slices.Equal(got, want) {
					t.Errorf("ESEARCH IN (%s) ALL answered for %q, want %q (database takes %q for %q: %v)",
						src.name, got, want, tc.other, tc.mailbox, same)
				}
			}
		})
	}
}

// TestIMAP_ESearchIgnoresUnstorableMailboxName: a MAILBOXES name PostgreSQL cannot
// hold (here bytes that are not UTF-8, which UTF8=ACCEPT lets through) names no
// mailbox and is ignored like any other name of no mailbox: RFC 7377 §5 warns
// that telling a missing mailbox from an inaccessible one, which §2.2 has
// ignored, exposes the hierarchy. The read-only ACL fallback queried the
// database with it, which refused it with SQLSTATE 22021, and the whole ESEARCH
// answered NO [SERVERBUG].
func TestIMAP_ESearchIgnoresUnstorableMailboxName(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	identityAppend(t, dialIdentityTestClient(t, server, account.Email, account.Password), "INBOX")

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %q %q", account.Email, account.Password))
	c.do("ENABLE UTF8=ACCEPT")
	for _, cmd := range []string{
		"ESEARCH IN (MAILBOXES (INBOX \"a\xffb\")) ALL",
		"ESEARCH IN (MAILBOXES (\"\xff\" INBOX)) ALL",
	} {
		untagged, tagged := c.read(c.send(cmd), cmd)
		if !strings.Contains(tagged, " OK ") {
			t.Errorf("%q: %s, want OK", cmd, tagged)
			continue
		}
		if len(untagged) != 1 || !strings.Contains(untagged[0], "MAILBOX INBOX") {
			t.Errorf("%q answered %q, want one ESEARCH response for INBOX", cmd, untagged)
		}
	}
}

// TestIMAP_NotifyMailboxesMatchNamesAsTheDatabaseDoes: NOTIFY matched its
// MAILBOXES and SUBTREE specifiers with strings.EqualFold, so MAILBOXES "sx"
// also watched "ſx", a mailbox of its own under every collation.
func TestIMAP_NotifyMailboxesMatchNamesAsTheDatabaseDoes(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	rec := newNotifyRecorder()
	c := notifyLoginAndSelect(t, server.Address, account, rec.options(), "")
	defer c.Logout()

	for _, tc := range identityNamePairs {
		t.Run(tc.mailbox+"/"+tc.other, func(t *testing.T) {
			same := sameMailboxName(t, server, tc.mailbox, tc.other)
			child := tc.mailbox + "/x"
			if err := c.Create(child, nil).Wait(); err != nil {
				t.Fatalf("CREATE %q: %v", child, err)
			}
			defer func() { c.Delete(tc.mailbox).Wait() }()
			defer func() { c.Delete(child).Wait() }()

			for _, subtree := range []bool{false, true} {
				// NOTIFY SET STATUS answers a STATUS for every watched mailbox
				// (RFC 5465 §3.1) before its tagged OK.
				cmd, err := c.Notify(&imap.NotifyOptions{
					Status: true,
					Items: []imap.NotifyItem{{
						Mailboxes: []string{tc.other},
						Subtree:   subtree,
						Events:    []imap.NotifyEvent{imap.NotifyEventMessageNew, imap.NotifyEventMessageExpunge},
					}},
				})
				if err != nil {
					t.Fatalf("NOTIFY: %v", err)
				}
				if err := cmd.Wait(); err != nil {
					t.Fatalf("NOTIFY: %v", err)
				}
				var got []string
			drain:
				for {
					select {
					case data := <-rec.status:
						got = append(got, data.Mailbox)
					default:
						break drain
					}
				}
				slices.Sort(got)

				var want []string
				if same {
					want = []string{tc.mailbox}
					if subtree {
						want = append(want, child)
					}
				}
				if !slices.Equal(got, want) {
					t.Errorf("NOTIFY SET STATUS (%s %q ...): STATUS for %q, want %q (database takes %q for %q: %v)",
						map[bool]string{false: "MAILBOXES", true: "SUBTREE"}[subtree], tc.other, got, want, tc.other, tc.mailbox, same)
				}
			}
			cmd, err := c.Notify(nil)
			if err != nil {
				t.Fatalf("NOTIFY NONE: %v", err)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("NOTIFY NONE: %v", err)
			}
		})
	}
}

// TestIMAP_NotifyTreeEventsKeyNamesAsTheDatabaseDoes: the NOTIFY snapshot diff
// keyed names by strings.ToLower, so under ICU a mailbox "ix" created next to
// "İx/a" was announced \HasChildren, its "child" being "İx/a".
func TestIMAP_NotifyTreeEventsKeyNamesAsTheDatabaseDoes(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	if sameMailboxName(t, server, "ix", "\u0130x") {
		t.Skip("the database takes İx for ix")
	}

	other := notifyLoginAndSelect(t, server.Address, account, nil, "")
	defer other.Logout()
	if err := other.Create("\u0130x/a", nil).Wait(); err != nil {
		t.Fatalf("CREATE İx/a: %v", err)
	}

	rec := newNotifyRecorder()
	watcher := notifyLoginAndSelect(t, server.Address, account, rec.options(), "")
	defer watcher.Logout()
	cmd, err := watcher.Notify(&imap.NotifyOptions{
		Items: []imap.NotifyItem{{
			MailboxSpec: imap.NotifyMailboxSpecPersonal,
			Events:      []imap.NotifyEvent{imap.NotifyEventMailboxName},
		}},
	})
	if err != nil {
		t.Fatalf("NOTIFY: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("NOTIFY: %v", err)
	}

	collect := func(want ...string) map[string]*imap.ListData {
		t.Helper()
		got := make(map[string]*imap.ListData)
		deadline := time.After(15 * time.Second)
		var settle <-chan time.Time
		for {
			select {
			case data := <-rec.list:
				got[data.Mailbox] = data
				if settle == nil && hasAllNames(got, want) {
					settle = time.After(4 * notifyTestPollInterval)
				}
			case <-settle:
				return got
			case <-deadline:
				return got
			}
		}
	}

	if err := other.Create("ix", nil).Wait(); err != nil {
		t.Fatalf("CREATE ix: %v", err)
	}
	got := collect("ix")
	if data := got["ix"]; data == nil {
		t.Errorf("no LIST for the created ix; got %v", mapKeys(got))
	} else if !listHasAttr(data, imap.MailboxAttrHasNoChildren) {
		t.Errorf("LIST for the created ix: %v, want \\HasNoChildren (İx/a is not below ix)", data.Attrs)
	}

	if err := other.Create("ix/c", nil).Wait(); err != nil {
		t.Fatalf("CREATE ix/c: %v", err)
	}
	got = collect("ix/c", "ix")
	for _, name := range []string{"ix/c", "ix"} {
		if got[name] == nil {
			t.Errorf("no LIST for %q; got %v", name, mapKeys(got))
		}
	}
	if data := got["ix"]; data != nil && !listHasAttr(data, imap.MailboxAttrHasChildren) {
		t.Errorf("LIST for the parent ix: %v, want \\HasChildren", data.Attrs)
	}
	for name := range got {
		if name != "ix" && name != "ix/c" {
			t.Errorf("unexpected LIST for %q: %+v", name, got[name])
		}
	}
}
