package db

import (
	"testing"
)

// go-message keeps the quoting an obsolete local part needs (RFC 5322 §3.6.4), so a
// parsed id can hold white space inside quotes; in_reply_to joins ids with spaces.
func TestBuildEnvelopeInReplyToQuotedLocalPart(t *testing.T) {
	msg := &Message{InReplyTo: `"foo bar"@example.com b@example.com`, RecipientsJSON: []byte("[]")}
	env, err := BuildEnvelope(msg)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`"foo bar"@example.com`, "b@example.com"}
	if len(env.InReplyTo) != len(want) || env.InReplyTo[0] != want[0] || env.InReplyTo[1] != want[1] {
		t.Fatalf("InReplyTo = %q, want %q", env.InReplyTo, want)
	}
}
