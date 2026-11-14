//go:build integration

package imap_test

import (
	"slices"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_SearchEveryAddress: FROM, TO and CC match any address of their header, not only
// the first one. RFC 9051 §6.4.4: "FROM <string> Messages that contain the specified string
// in the envelope structure's FROM field", and the envelope's FROM, TO and CC fields list
// every address of the header.
func TestIMAP_SearchEveryAddress(t *testing.T) {
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

	date := time.Now().Format(time.RFC1123Z)
	messages := []string{
		// UID 1: the message from the issue, with a second From address and two Cc.
		"From: Alice <alice@example.com>, Frank Author <frank@example.com>\r\n" +
			"Sender: alice@example.com\r\n" +
			"To: carol@example.com, Bob Example <bob@example.com>\r\n" +
			"Cc: Dave Copy <dave@example.org>, erin@example.org\r\n" +
			"Subject: test\r\n" +
			"Date: " + date + "\r\n" +
			"\r\n" +
			"body\r\n",
		// UID 2: the same people in other headers.
		"From: bob@example.com\r\n" +
			"To: frank@example.com\r\n" +
			"Cc: carol@example.com\r\n" +
			"Subject: control\r\n" +
			"Date: " + date + "\r\n" +
			"\r\n" +
			"body\r\n",
	}
	for i, msg := range messages {
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
	notCrit := func(c imap.SearchCriteria) imap.SearchCriteria {
		return imap.SearchCriteria{Not: []imap.SearchCriteria{c}}
	}
	cases := []struct {
		name     string
		criteria imap.SearchCriteria
		want     []imap.UID
	}{
		{"TO second address (issue a1)", header("To", "bob@example.com"), []imap.UID{1}},
		{"TO second display name", header("To", "Bob Example"), []imap.UID{1}},
		{"FROM second address", header("From", "frank@example.com"), []imap.UID{1}},
		{"FROM second display name", header("From", "frank author"), []imap.UID{1}},
		{"CC first display name", header("Cc", "Dave Copy"), []imap.UID{1}},
		{"CC second address", header("Cc", "erin@example.org"), []imap.UID{1}},
		{"TEXT second Cc address", imap.SearchCriteria{Text: []string{"erin@example.org"}}, []imap.UID{1}},
		{"FROM bob is message 2 only", header("From", "bob"), []imap.UID{2}},
		{"TO frank is message 2 only", header("To", "frank"), []imap.UID{2}},
		{"CC carol is message 2 only", header("Cc", "carol"), []imap.UID{2}},
		{"NOT TO bob", notCrit(header("To", "bob")), []imap.UID{2}},
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
}
