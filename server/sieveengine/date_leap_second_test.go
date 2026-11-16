package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestDateLeapSecond is issue #1384: a Date: header whose time-of-day is a leap
// second (RFC 5322 §3.3: "00:00:00 through 23:59:60") was not a date-time to the
// date test, so the test was false (RFC 5260 §4) and the issue's script filed the
// message into n.
func TestDateLeapSecond(t *testing.T) {
	const script = `require ["date", "fileinto"];
if date :originalzone "date" "date" "2016-12-31" { fileinto "y"; } else { fileinto "n"; }
`
	// What ManageSieve PUTSCRIPT checks, with the default [sieve] enabled_extensions.
	if err := ValidateScript(script, nil); err != nil {
		t.Fatalf("ValidateScript: %v", err)
	}
	executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, date := range []string{
		"Sat, 31 Dec 2016 23:59:59 +0000",
		"Sat, 31 Dec 2016 23:59:60 +0000",
	} {
		result, err := executor.Evaluate(context.Background(), Context{
			EnvelopeFrom: "sender@example.com",
			EnvelopeTo:   "user@example.com",
			Header:       map[string][]string{"Date": {date}, "From": {"sender@example.com"}},
			Message:      bodyOnly("body"),
		})
		if err != nil {
			t.Fatalf("%q: evaluate: %v", date, err)
		}
		if want := []string{"y"}; !slices.Equal(result.Mailboxes, want) {
			t.Errorf("Date: %s: mailboxes = %q, want %q", date, result.Mailboxes, want)
		}
	}
}
