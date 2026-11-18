//go:build integration

package imap_test

import (
	"slices"
	"strings"
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// searchAddressesFixture is dovecot/imaptest's src/tests/search-addresses.mbox (pinned at
// 0682be5f3617149e55cb6a2f4de4b23be8092c53), one string per message in source order.
var searchAddressesFixture = []string{
	"From: user-from@domain.org\nTo: user-to@domain.org\nCc: user-cc@domain.org\nBcc: user-bcc@domain.org\n\nbody\n",
	"From: RealFrom <user-from@domain.org>\nTo: RealTo <user-to@domain.org>\nCc: RealCc <user-cc@domain.org>\nBcc: RealBcc <user-bcc@domain.org>\n\nbody2\n",
	"From: <user-from (comment)@ (comment) domain.org>\nTo: <user-to@domain.org>\nCc: <user-cc@domain.org>\nBcc: <user-bcc@domain.org>\n\nbody3\n",
	"From: user-from@domain.org (RealFrom)\nTo: user-to@domain.org (RealTo)\nCc: user-cc@domain.org (RealCc)\nBcc: user-bcc@domain.org (RealBcc)\n\nbody4\n",
	"From: user-from1@domain.org, user-from2@domain.org\nCc: user-cc@domain.org\n\nbody5\n",
	"From: RealFrom <user-from@domain.org>\nTo: groupname: groupuser1@domain.org, groupuser2@domain.org;,\n  groupname2: groupuser3@domain.org;\n\nbody6\n",
	"From: RealFrom <user-from@domain.org>\nTo: groupname:;\n\nbody7\n",
}

// TestIMAP_SearchAddressWithComments: an addr-spec may carry comments and folding white
// space around its "@" (RFC 5322 §3.4.1: local-part and domain are dot-atoms, which allow
// CFWS on either side), and that address is still the envelope's FROM. RFC 9051 §6.4.4
// defines FROM as a substring of "the envelope structure's FROM field", so message 3 of
// imaptest's search-addresses scenario, From: <user-from (comment)@ (comment) domain.org>,
// matches FROM user-from@domain.org (#2014). The other address assertions of that scenario
// run on the same mailbox so the fix is shown not to move any of them.
func TestIMAP_SearchAddressWithComments(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	for i, raw := range searchAddressesFixture {
		msg := strings.ReplaceAll(raw, "\n", "\r\n")
		cmd := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := cmd.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND %d write: %v", i+1, err)
		}
		if err := cmd.Close(); err != nil {
			t.Fatalf("APPEND %d close: %v", i+1, err)
		}
		if _, err := cmd.Wait(); err != nil {
			t.Fatalf("APPEND %d: %v", i+1, err)
		}
	}

	header := func(key, value string) imap.SearchCriteria {
		return imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: key, Value: value}}}
	}
	cases := []struct {
		name     string
		criteria imap.SearchCriteria
		want     []imap.UID
	}{
		{"FROM full address", header("From", "user-from@domain.org"), []imap.UID{1, 2, 3, 4, 6, 7}},
		{"TO full address", header("To", "user-to@domain.org"), []imap.UID{1, 2, 3, 4}},
		{"CC full address", header("Cc", "user-cc@domain.org"), []imap.UID{1, 2, 3, 4, 5}},
		{"BCC full address", header("Bcc", "user-bcc@domain.org"), []imap.UID{1, 2, 3, 4}},
		{"FROM realname", header("From", "realfrom"), []imap.UID{2, 4, 6, 7}},
		{"TO realname", header("To", "realto"), []imap.UID{2, 4}},
		{"CC realname", header("Cc", "realcc"), []imap.UID{2, 4}},
		{"BCC realname", header("Bcc", "realbcc"), []imap.UID{2, 4}},
		{"FROM substring address", header("From", "ser-fro"), []imap.UID{1, 2, 3, 4, 5, 6, 7}},
		{"TO substring address", header("To", "ser-t"), []imap.UID{1, 2, 3, 4}},
		{"CC substring address", header("Cc", "ser-c"), []imap.UID{1, 2, 3, 4, 5}},
		{"BCC substring address", header("Bcc", "ser-bc"), []imap.UID{1, 2, 3, 4}},
		{"FROM substring realname", header("From", "ealfro"), []imap.UID{2, 4, 6, 7}},
		{"FROM first of two", header("From", "user-from1"), []imap.UID{5}},
		{"FROM second of two", header("From", "user-from2"), []imap.UID{5}},
		// RFC 9051 §6.4.4: the empty string tests for the field's presence.
		{"FROM present", header("From", ""), []imap.UID{1, 2, 3, 4, 5, 6, 7}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := c.UIDSearch(&tc.criteria, nil).Wait()
			if err != nil {
				t.Fatalf("UID SEARCH: %v", err)
			}
			got := data.AllUIDs()
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("UID SEARCH = %v, want %v", got, tc.want)
			}
		})
	}

	// The same parse feeds FETCH ENVELOPE (RFC 9051 §7.5.2), whose FROM was NIL.
	fetched, err := c.Fetch(imap.UIDSetNum(3), &imap.FetchOptions{Envelope: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH 3 ENVELOPE: %v", err)
	}
	if len(fetched) != 1 || fetched[0].Envelope == nil {
		t.Fatalf("FETCH 3 ENVELOPE returned %d messages", len(fetched))
	}
	from := fetched[0].Envelope.From
	if len(from) != 1 || from[0].Mailbox != "user-from" || from[0].Host != "domain.org" {
		t.Errorf("ENVELOPE FROM of message 3 = %+v, want one address user-from@domain.org", from)
	}
}
