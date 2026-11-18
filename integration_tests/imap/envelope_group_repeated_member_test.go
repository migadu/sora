//go:build integration

package imap_test

import (
	"slices"
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_EnvelopeGroupRepeatedMember checks that each group of an ENVELOPE address list
// keeps its own members when an address repeats across groups (#2079): the list is the
// header as written (RFC 3501 §7.4.2), not one with every address once.
func TestIMAP_EnvelopeGroupRepeatedMember(t *testing.T) {
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

	msg := "Date: Thu, 15 Feb 2007 01:02:03 +0200\r\n" +
		"From: user@example.com\r\n" +
		"To: a: x@example.com;, b: x@example.com, y@example.com;\r\n" +
		"\r\n" +
		"body\r\n"
	ac := c.Append("INBOX", int64(len(msg)), nil)
	if _, err := ac.Write([]byte(msg)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := ac.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := ac.Wait(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Envelope: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH ENVELOPE failed: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Envelope == nil {
		t.Fatalf("FETCH ENVELOPE returned %d messages", len(msgs))
	}
	want := []imap.Address{
		{Mailbox: "a"}, {Mailbox: "x", Host: "example.com"}, {},
		{Mailbox: "b"}, {Mailbox: "x", Host: "example.com"}, {Mailbox: "y", Host: "example.com"}, {},
	}
	if got := msgs[0].Envelope.To; !slices.Equal(got, want) {
		t.Errorf("ENVELOPE To = %+v, want %+v", got, want)
	}
}
