package db

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/emersion/go-message/mail"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/helpers"
)

// groupHeaderRecipients is message 4 of imaptest's fetch-envelope.mbox plus a Bcc group,
// as stored in recipients_json.
func groupHeaderRecipients(t *testing.T) []byte {
	t.Helper()
	hdr := mail.HeaderFromMap(map[string][]string{
		"From": {"user@domain (Real Name)"},
		"To":   {"group: g1@d1.org, g2@d2.org;, group2: g3@d3.org;"},
		"Cc":   {"group:;, group2: (foo) ;"},
		"Bcc":  {"hidden: bcc@example.com;"},
		// Stored decoded, sent RFC 2047 encoded like an addr-name.
		"Reply-To": {"=?utf-8?q?Caf=C3=A9?= list:;"},
	})
	raw, err := json.Marshal(helpers.ExtractRecipients(hdr.Header))
	if err != nil {
		t.Fatalf("marshal recipients: %v", err)
	}
	return raw
}

// TestBuildEnvelopeAddressGroups checks the RFC 3501 §7.4.2 group records (#2012): a
// start is (NIL NIL "name" NIL), an end (NIL NIL NIL NIL).
func TestBuildEnvelopeAddressGroups(t *testing.T) {
	env, err := BuildEnvelope(&Message{UID: 1, MailboxID: 10, RecipientsJSON: groupHeaderRecipients(t)})
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	end := imap.Address{}
	wantTo := []imap.Address{
		{Mailbox: "group"}, {Mailbox: "g1", Host: "d1.org"}, {Mailbox: "g2", Host: "d2.org"}, end,
		{Mailbox: "group2"}, {Mailbox: "g3", Host: "d3.org"}, end,
	}
	if !slices.Equal(env.To, wantTo) {
		t.Errorf("To = %+v, want %+v", env.To, wantTo)
	}
	wantCc := []imap.Address{{Mailbox: "group"}, end, {Mailbox: "group2"}, end}
	if !slices.Equal(env.Cc, wantCc) {
		t.Errorf("Cc = %+v, want %+v", env.Cc, wantCc)
	}
	wantBcc := []imap.Address{{Mailbox: "hidden"}, {Mailbox: "bcc", Host: "example.com"}, end}
	if !slices.Equal(env.Bcc, wantBcc) {
		t.Errorf("Bcc = %+v, want %+v", env.Bcc, wantBcc)
	}
	wantReplyTo := []imap.Address{{Mailbox: "=?utf-8?q?Caf=C3=A9_list?="}, end}
	if !slices.Equal(env.ReplyTo, wantReplyTo) {
		t.Errorf("ReplyTo = %+v, want %+v", env.ReplyTo, wantReplyTo)
	}
	wantFrom := []imap.Address{{Name: "Real Name", Mailbox: "user", Host: "domain"}}
	if !slices.Equal(env.From, wantFrom) || !slices.Equal(env.Sender, wantFrom) {
		t.Errorf("From = %+v, Sender = %+v, want both %+v", env.From, env.Sender, wantFrom)
	}
}

// TestUserAPIRecipientsSkipGroupMarkers checks that the User API's address lists carry
// only addresses: a group boundary is no recipient, and an address in two groups is one
// recipient (#2079).
func TestUserAPIRecipientsSkipGroupMarkers(t *testing.T) {
	var recipients []helpers.Recipient
	if err := json.Unmarshal(groupHeaderRecipients(t), &recipients); err != nil {
		t.Fatalf("unmarshal recipients: %v", err)
	}
	recipients = append(recipients,
		helpers.Recipient{AddressType: "to", Group: "again"},
		helpers.Recipient{AddressType: "to", EmailAddress: "g1@d1.org"},
		helpers.Recipient{AddressType: "to", GroupEnd: true})
	raw, err := json.Marshal(recipients)
	if err != nil {
		t.Fatalf("marshal recipients: %v", err)
	}
	msg := &DBMessage{}
	msg.setRecipients(raw)
	if want := []string{"g1@d1.org", "g2@d2.org", "g3@d3.org"}; !slices.Equal(msg.To, want) {
		t.Errorf("To = %q, want %q", msg.To, want)
	}
	if len(msg.Cc) != 0 {
		t.Errorf("Cc = %q, want none", msg.Cc)
	}
	if want := []string{"bcc@example.com"}; !slices.Equal(msg.Bcc, want) {
		t.Errorf("Bcc = %q, want %q", msg.Bcc, want)
	}
	if msg.From != "user@domain" {
		t.Errorf("From = %q, want user@domain", msg.From)
	}
}
