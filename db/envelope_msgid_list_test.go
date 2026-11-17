package db

import (
	"slices"
	"testing"
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
