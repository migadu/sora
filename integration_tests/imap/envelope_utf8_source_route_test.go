//go:build integration

package imap_test

import (
	"slices"
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_EnvelopeUTF8SourceRouteMatchesAttached: a message's own ENVELOPE (built by
// Sora from the stored recipients) and its ENVELOPE as a message/rfc822 attachment (built
// by go-imap's ExtractEnvelope) are the same parse of the same headers. A source route
// whose hop domain is internationalized (RFC 6532 §3.2 extends atext with
// UTF8-non-ascii) was accepted only by go-imap, so the top-level ENVELOPE lost the
// address the attached one kept (#2124).
func TestIMAP_EnvelopeUTF8SourceRouteMatchesAttached(t *testing.T) {
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

	headers := "From: Sender <@bücher.example:sender@example.com>\r\n" +
		"To: <@routé.example (hop) , @例え.example:to@example.com>, plain@example.com\r\n" +
		"Cc: team: <@[例え:literal]:member@example.com>;, <@ascii.example:last@example.com>\r\n" +
		"Subject: routed\r\nDate: Thu, 18 Jul 1996 00:00:00 +0000\r\n"
	inner := headers + "\r\nbody\r\n"
	outer := "From: outer@example.com\r\nTo: outer@example.com\r\nSubject: fwd\r\n" +
		"Date: Thu, 18 Jul 1996 00:00:00 +0000\r\n" +
		"Content-Type: message/rfc822\r\n\r\n" + inner
	for _, msg := range []string{inner, outer} {
		ac := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := ac.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write: %v", err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("APPEND close: %v", err)
		}
		if _, err := ac.Wait(); err != nil {
			t.Fatalf("APPEND: %v", err)
		}
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT: %v", err)
	}
	msgs, err := c.Fetch(imap.SeqSetNum(1, 2), &imap.FetchOptions{Envelope: true, BodyStructure: &imap.FetchItemBodyStructure{Extended: true}}).Collect()
	if err != nil || len(msgs) != 2 {
		t.Fatalf("FETCH = %d messages, %v", len(msgs), err)
	}
	top := msgs[0].Envelope
	rfc822, ok := msgs[1].BodyStructure.(*imap.BodyStructureSinglePart)
	if !ok || rfc822.MessageRFC822 == nil || rfc822.MessageRFC822.Envelope == nil {
		t.Fatalf("message 2 has no attached ENVELOPE: %+v", msgs[1].BodyStructure)
	}
	attached := rfc822.MessageRFC822.Envelope

	want := map[string][]imap.Address{
		"From": {{Name: "Sender", Mailbox: "sender", Host: "example.com", Route: "@bücher.example"}},
		"To": {{Mailbox: "to", Host: "example.com", Route: "@routé.example,@例え.example"},
			{Mailbox: "plain", Host: "example.com"}},
		"Cc": {{Mailbox: "team"}, {Mailbox: "member", Host: "example.com", Route: "@[例え:literal]"}, {},
			{Mailbox: "last", Host: "example.com", Route: "@ascii.example"}},
	}
	for _, f := range []struct {
		name          string
		top, attached []imap.Address
	}{
		{"From", top.From, attached.From},
		{"Sender", top.Sender, attached.Sender},
		{"Reply-To", top.ReplyTo, attached.ReplyTo},
		{"To", top.To, attached.To},
		{"Cc", top.Cc, attached.Cc},
	} {
		if !slices.Equal(f.top, f.attached) {
			t.Errorf("%s: top-level ENVELOPE %+v, attached ENVELOPE %+v", f.name, f.top, f.attached)
		}
		if w, ok := want[f.name]; ok && !slices.Equal(f.top, w) {
			t.Errorf("%s: top-level ENVELOPE %+v, want %+v", f.name, f.top, w)
		}
	}
}
