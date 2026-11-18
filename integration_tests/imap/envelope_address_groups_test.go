//go:build integration

package imap_test

import (
	"slices"
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_EnvelopeAddressGroups checks that FETCH ENVELOPE keeps RFC 5322 group syntax
// (#2012). RFC 3501 §7.4.2: a group start is an address with a NIL host and the group
// name as its mailbox, a group end has both NIL; an empty group is a start immediately
// followed by its end. Message 1 is message 4 of imaptest's fetch-envelope.mbox, whose
// fetch-envelope test expects exactly these To and Cc lists.
func TestIMAP_EnvelopeAddressGroups(t *testing.T) {
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

	appendRaw := func(msg string) imap.UID {
		t.Helper()
		ac := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := ac.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		data, err := ac.Wait()
		if err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
		return data.UID
	}

	uid1 := appendRaw("Date: Thu, 15 Feb 2007 01:02:03 +0200\r\n" +
		"From: user@domain (Real Name)\r\n" +
		"To: group: g1@d1.org, g2@d2.org;, group2: g3@d3.org;\r\n" +
		"Cc: group:;, group2: (foo) ;\r\n" +
		"\r\n" +
		"body\r\n")
	// An address before a group, and the common "undisclosed-recipients:;" empty group.
	uid2 := appendRaw("Date: Thu, 15 Feb 2007 01:02:03 +0200\r\n" +
		"From: user@example.com\r\n" +
		"To: Plain <plain@example.com>, \"Team Name\": a@example.com;\r\n" +
		"Cc: undisclosed-recipients:;\r\n" +
		"\r\n" +
		"body\r\n")
	// IPv6 colons in bare domain literals must not consume group boundaries.
	uid3 := appendRaw("From: user@example.com\r\n" +
		"To: outside@[2001:db8::1], team: inside@[2001:db8::2];\r\n\r\nbody\r\n")

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	var set imap.UIDSet
	set.AddNum(uid1, uid2, uid3)
	msgs, err := c.Fetch(set, &imap.FetchOptions{UID: true, Envelope: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH ENVELOPE failed: %v", err)
	}
	byUID := make(map[imap.UID]*imap.Envelope, len(msgs))
	for _, m := range msgs {
		byUID[m.UID] = m.Envelope
	}

	groupEnd := imap.Address{}
	for _, tc := range []struct {
		uid      imap.UID
		from     []imap.Address
		to, cc   []imap.Address
		describe string
	}{
		{
			uid:  uid1,
			from: []imap.Address{{Name: "Real Name", Mailbox: "user", Host: "domain"}},
			to: []imap.Address{
				{Mailbox: "group"},
				{Mailbox: "g1", Host: "d1.org"},
				{Mailbox: "g2", Host: "d2.org"},
				groupEnd,
				{Mailbox: "group2"},
				{Mailbox: "g3", Host: "d3.org"},
				groupEnd,
			},
			cc: []imap.Address{
				{Mailbox: "group"},
				groupEnd,
				{Mailbox: "group2"},
				groupEnd,
			},
			describe: "imaptest fetch-envelope message 4",
		},
		{
			uid:  uid2,
			from: []imap.Address{{Mailbox: "user", Host: "example.com"}},
			to: []imap.Address{
				{Name: "Plain", Mailbox: "plain", Host: "example.com"},
				{Mailbox: "Team Name"},
				{Mailbox: "a", Host: "example.com"},
				groupEnd,
			},
			cc: []imap.Address{
				{Mailbox: "undisclosed-recipients"},
				groupEnd,
			},
			describe: "address before a group, undisclosed-recipients",
		},
		{
			uid:  uid3,
			from: []imap.Address{{Mailbox: "user", Host: "example.com"}},
			to: []imap.Address{
				{Mailbox: "outside", Host: "[2001:db8::1]"},
				{Mailbox: "team"},
				{Mailbox: "inside", Host: "[2001:db8::2]"},
				groupEnd,
			},
			describe: "bare IPv6 literal before and inside a group",
		},
	} {
		env := byUID[tc.uid]
		if env == nil {
			t.Errorf("%s (UID %d): no ENVELOPE", tc.describe, tc.uid)
			continue
		}
		if !slices.Equal(env.From, tc.from) {
			t.Errorf("%s: ENVELOPE From = %+v, want %+v", tc.describe, env.From, tc.from)
		}
		if !slices.Equal(env.To, tc.to) {
			t.Errorf("%s: ENVELOPE To = %+v, want %+v", tc.describe, env.To, tc.to)
		}
		if !slices.Equal(env.Cc, tc.cc) {
			t.Errorf("%s: ENVELOPE Cc = %+v, want %+v", tc.describe, env.Cc, tc.cc)
		}
	}
}
