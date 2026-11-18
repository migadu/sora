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

// TestExtractEnvelopeRecipientsSkipsGroupMarkers: an RFC 5322 §3.4 group contributes
// its members, never its start and end markers (stored for the ENVELOPE with an empty
// address), and an empty group contributes nothing (#2012).
func TestExtractEnvelopeRecipientsSkipsGroupMarkers(t *testing.T) {
	h := parseEnvelopeRecipientHeader(t, "From: ignored@example.com\r\n"+
		"Sender: sender@example.com\r\nReply-To: replies@example.com\r\n"+
		"To: team: a@example.com;, undisclosed:;\r\n"+
		"Cc: Colleagues: A@example.com, carol@example.com;\r\n"+
		"Bcc: Hidden: dave@example.com;, Nobody:;\r\n")
	want := []string{"a@example.com", "carol@example.com", "dave@example.com"}
	if got := ExtractEnvelopeRecipients(h); !slices.Equal(got, want) {
		t.Errorf("ExtractEnvelopeRecipients = %q, want %q", got, want)
	}
	if got := ExtractEnvelopeRecipients(parseEnvelopeRecipientHeader(t, "To: undisclosed:;\r\nCc: Nobody:;\r\nBcc: Hidden:;\r\n")); len(got) != 0 {
		t.Errorf("only empty groups, yet recipients %q", got)
	}
}

// TestExtractRecipientsKeepsEveryAddressHeader: the recipients metadata still covers
// From, Sender and Reply-To. It lists each header as written, a repeated address each
// time (the ENVELOPE does, #2079); DistinctAddresses gives each once per header.
func TestExtractRecipientsKeepsEveryAddressHeader(t *testing.T) {
	h := parseEnvelopeRecipientHeader(t, "From: alice@example.com\r\nSender: alice@example.com\r\n"+
		"Reply-To: alice@example.com\r\nTo: bob@example.com, bob@example.com\r\nCc: bob@example.com\r\n")

	list := func(recipients []Recipient) []string {
		var got []string
		for _, r := range recipients {
			got = append(got, r.AddressType+":"+r.EmailAddress)
		}
		return got
	}
	all := ExtractRecipients(h)
	want := []string{"to:bob@example.com", "to:bob@example.com", "cc:bob@example.com", "from:alice@example.com", "sender:alice@example.com", "reply-to:alice@example.com"}
	if got := list(all); !slices.Equal(got, want) {
		t.Errorf("ExtractRecipients = %v, want %v", got, want)
	}
	want = slices.Delete(want, 1, 2)
	if got := list(DistinctAddresses(all)); !slices.Equal(got, want) {
		t.Errorf("DistinctAddresses = %v, want %v", got, want)
	}
}
