//go:build integration

package imap_test

import (
	"slices"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_SearchBccReplyToAndMessageIDHeaders: RFC 3501 §6.4.4: "In all search
// keys that use strings, a message matches the key if the string is a substring
// of the field. The matching is case-insensitive." BCC and Reply-To compared the
// whole stored address, case-sensitively; In-Reply-To and References kept the
// angle brackets of the term although the columns store message IDs without
// them, and In-Reply-To compared for equality (#281).
func TestIMAP_SearchBccReplyToAndMessageIDHeaders(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}

	appendMsg := func(msg string) imap.UID {
		t.Helper()
		ac := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := ac.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write: %v", err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("APPEND close: %v", err)
		}
		data, err := ac.Wait()
		if err != nil {
			t.Fatalf("APPEND: %v", err)
		}
		return data.UID
	}
	// The message from the issue.
	reply := appendMsg("From: Alice <alice@example.com>\r\n" +
		"To: carol@example.com, bob@example.com\r\n" +
		"Bcc: Dave@Example.com\r\n" +
		"Reply-To: Replies Desk <Replies@Example.org>\r\n" +
		"Sender: Mailer <mailer@example.net>\r\n" +
		"Subject: test\r\n" +
		"Message-ID: <m1@example.com>\r\n" +
		"In-Reply-To: <a1@example.com>\r\n" +
		"References: <a0@example.com> <a1@example.com>\r\n" +
		"\r\nbody\r\n")
	// Two parents in In-Reply-To (RFC 5322 §3.6.4 allows several).
	twoParents := appendMsg("From: erin@example.com\r\n" +
		"To: carol@example.com\r\n" +
		"Subject: two parents\r\n" +
		"Message-ID: <m2@example.com>\r\n" +
		"In-Reply-To: <b1@example.com> <b2@example.com>\r\n" +
		"\r\nbody\r\n")
	// Absent headers must not match a positive search, and must match its NOT.
	plain := appendMsg("From: frank@example.com\r\nTo: carol@example.com\r\nSubject: plain\r\nMessage-ID: <m3@example.com>\r\n\r\nbody\r\n")

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT: %v", err)
	}

	header := func(key, value string) *imap.SearchCriteria {
		return &imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: key, Value: value}}}
	}
	notHeader := func(key, value string) *imap.SearchCriteria {
		return &imap.SearchCriteria{Not: []imap.SearchCriteria{*header(key, value)}}
	}
	for _, tc := range []struct {
		name     string
		criteria *imap.SearchCriteria
		want     []imap.UID
	}{
		{"BCC full address, other case", header("Bcc", "dave@example.com"), []imap.UID{reply}},
		{"BCC part of the address", header("Bcc", "dave"), []imap.UID{reply}},
		{"BCC is not To", header("Bcc", "carol"), nil},
		{"Reply-To address", header("Reply-To", "replies@example"), []imap.UID{reply}},
		{"Reply-To display name", header("Reply-To", "DESK"), []imap.UID{reply}},
		{"Sender", header("Sender", "mailer@"), []imap.UID{reply}},
		{"In-Reply-To with brackets", header("In-Reply-To", "<a1@example.com>"), []imap.UID{reply}},
		{"In-Reply-To without brackets", header("In-Reply-To", "a1@example.com"), []imap.UID{reply}},
		{"In-Reply-To second of two IDs", header("In-Reply-To", "<b2@example.com>"), []imap.UID{twoParents}},
		{"In-Reply-To substring", header("In-Reply-To", "@example.com>"), []imap.UID{reply, twoParents}},
		{"In-Reply-To is not References", header("In-Reply-To", "<a0@example.com>"), nil},
		{"In-Reply-To present (empty string)", header("In-Reply-To", ""), []imap.UID{reply, twoParents}},
		{"References first ID with brackets", header("References", "<a0@example.com>"), []imap.UID{reply}},
		{"References two IDs", header("References", "<a0@example.com> <a1@example.com>"), []imap.UID{reply}},
		{"References substring", header("References", "a1@EXAMPLE"), []imap.UID{reply}},
		{"NOT In-Reply-To includes absent header", notHeader("In-Reply-To", "<a1@example.com>"), []imap.UID{twoParents, plain}},
		{"NOT References includes absent headers", notHeader("References", "<a0@example.com>"), []imap.UID{twoParents, plain}},
		{"NOT In-Reply-To presence", notHeader("In-Reply-To", ""), []imap.UID{plain}},
		{"NOT References presence", notHeader("References", ""), []imap.UID{twoParents, plain}},
	} {
		data, err := c.UIDSearch(tc.criteria, nil).Wait()
		if err != nil {
			t.Errorf("%s: UID SEARCH failed: %v", tc.name, err)
			continue
		}
		got := data.AllUIDs()
		slices.Sort(got)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: UID SEARCH = %v, want %v", tc.name, got, tc.want)
		}
	}
}
