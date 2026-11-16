package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestDateISO8601ZeroOffset is issue #1375: the iso8601 date-part of a zero
// offset was "+00:00", so the issue's script kept the message. RFC 5260 §4.2:
// "a time zone offset of zero MUST be represented by "Z" and not "+00:00"".
func TestDateISO8601ZeroOffset(t *testing.T) {
	const script = `require ["date", "fileinto"];
if date :originalzone "date" "iso8601" "1996-07-17T02:23:25Z" { fileinto "match"; }
elsif date :zone "+0000" "date" "iso8601" "1996-07-17T02:23:25Z" { fileinto "zone"; }
`
	// What ManageSieve PUTSCRIPT checks, with the default [sieve] enabled_extensions.
	if err := ValidateScript(script, nil); err != nil {
		t.Fatalf("ValidateScript: %v", err)
	}
	executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, tc := range []struct {
		date string
		want []string
	}{
		{"Wed, 17 Jul 1996 02:23:25 +0000", []string{"match"}},
		{"Wed, 17 Jul 1996 04:23:25 +0200", []string{"zone"}},
	} {
		result, err := executor.Evaluate(context.Background(), Context{
			EnvelopeFrom: "sender@example.com",
			EnvelopeTo:   "user@example.com",
			Header:       map[string][]string{"Date": {tc.date}, "From": {"sender@example.com"}},
			Message:      bodyOnly("body"),
		})
		if err != nil {
			t.Fatalf("%q: evaluate: %v", tc.date, err)
		}
		if !slices.Equal(result.Mailboxes, tc.want) {
			t.Errorf("Date: %s: mailboxes = %q, want %q", tc.date, result.Mailboxes, tc.want)
		}
	}
}
