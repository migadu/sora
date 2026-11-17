package db

import (
	"slices"
	"strings"
	"testing"

	"github.com/emersion/go-message/mail"
)

// go-message keeps the quoting an obsolete local part needs (RFC 5322 §3.6.4), so a
// parsed id can hold white space inside quotes; in_reply_to joins ids with spaces.
func TestBuildEnvelopeInReplyToQuotedLocalPart(t *testing.T) {
	for stored, want := range map[string][]string{
		`"foo bar"@example.com b@example.com`: {`"foo bar"@example.com`, "b@example.com"},
		// A domain literal may hold '>' (RFC 5322 §3.6.4 no-fold-literal).
		`a@[x>y] z@example.com`: {"a@[x>y]", "z@example.com"},
	} {
		env, err := BuildEnvelope(&Message{InReplyTo: stored, RecipientsJSON: []byte("[]")})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(env.InReplyTo, want) {
			t.Errorf("InReplyTo(%q) = %q, want %q", stored, env.InReplyTo, want)
		}
	}
}

func TestBuildEnvelopeInReplyToParsedIDs(t *testing.T) {
	for _, id := range []string{
		"non\u00a0breaking@example.com",
		"em\u2003part@dom\u00a0ain.example",
		`literal@[<inner>]`,
		`"quoted local"@[<inner>]`,
		`literal@["<inner>"]`,
		"literal@[non\u00a0breaking]",
	} {
		t.Run(id, func(t *testing.T) {
			h := mail.HeaderFromMap(map[string][]string{"In-Reply-To": {"<" + id + "> <next@example.com>"}})
			parsed, err := h.MsgIDList("In-Reply-To")
			if err != nil {
				t.Fatalf("MsgIDList: %v", err)
			}
			want := []string{id, "next@example.com"}
			if !slices.Equal(parsed, want) {
				t.Fatalf("parsed ids = %q, want %q", parsed, want)
			}
			env, err := BuildEnvelope(&Message{InReplyTo: strings.Join(parsed, " "), RecipientsJSON: []byte("[]")})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(env.InReplyTo, want) {
				t.Fatalf("InReplyTo = %q, want %q", env.InReplyTo, want)
			}
		})
	}
}
