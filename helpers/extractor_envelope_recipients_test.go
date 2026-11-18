package helpers

import (
	"slices"
	"strings"
	"testing"

	"github.com/emersion/go-message"
)

func parseEnvelopeRecipientHeader(t *testing.T, raw string) message.Header {
	t.Helper()
	e, err := message.Read(strings.NewReader(raw + "\r\nbody\r\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return e.Header
}

// TestExtractEnvelopeRecipients: To, Cc and Bcc in order, each address once whatever its
// case; From, Sender and Reply-To are not recipients.
func TestExtractEnvelopeRecipients(t *testing.T) {
	h := parseEnvelopeRecipientHeader(t, "From: alice@example.com\r\n"+
		"Sender: alice@example.com\r\n"+
		"Reply-To: replies@example.com\r\n"+
		"To: Bob <bob@example.com>, carol@example.com\r\n"+
		"Cc: BOB@example.com, dave@example.com\r\n"+
		"Bcc: alice@example.com, carol@example.com\r\n")

	got := ExtractEnvelopeRecipients(h)
	want := []string{"bob@example.com", "carol@example.com", "dave@example.com", "alice@example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("ExtractEnvelopeRecipients = %v, want %v", got, want)
	}

	if got := ExtractEnvelopeRecipients(parseEnvelopeRecipientHeader(t, "From: alice@example.com\r\nSubject: none\r\n")); len(got) != 0 {
		t.Errorf("a message with only From has recipients %v", got)
	}
}

// TestExtractRecipientsKeepsEveryAddressHeader: the recipients metadata still covers
// From, Sender and Reply-To, once per address and header.
func TestExtractRecipientsKeepsEveryAddressHeader(t *testing.T) {
	h := parseEnvelopeRecipientHeader(t, "From: alice@example.com\r\nSender: alice@example.com\r\n"+
		"Reply-To: alice@example.com\r\nTo: bob@example.com, bob@example.com\r\nCc: bob@example.com\r\n")

	var got []string
	for _, r := range ExtractRecipients(h) {
		got = append(got, r.AddressType+":"+r.EmailAddress)
	}
	want := []string{"to:bob@example.com", "cc:bob@example.com", "from:alice@example.com", "sender:alice@example.com", "reply-to:alice@example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("ExtractRecipients = %v, want %v", got, want)
	}
}
