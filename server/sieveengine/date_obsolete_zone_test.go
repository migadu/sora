package sieveengine

import (
	"context"
	"slices"
	"testing"
	"time"
	_ "time/tzdata" // the zones the test runs in, on hosts without zoneinfo
)

// TestDateObsoleteZone is issue #1257: the date test (RFC 5260 §4) read an
// obsolete alphabetic zone of a Date: header in the server's time zone, so on a
// server in UTC "PDT" was +0000 and a lower-case "pdt" was not a date at all.
// RFC 5322 §4.3: "PDT is semantically equivalent to -0700". The issue's script
// files each message into hour02, wherever the server runs.
func TestDateObsoleteZone(t *testing.T) {
	const script = `require ["date", "fileinto"];
if date :zone "-0700" "date" "hour" "02" { fileinto "hour02"; }
elsif date :originalzone "date" "zone" "-0700" { fileinto "zone0700"; }
else { fileinto "nomatch"; }
`
	// What ManageSieve PUTSCRIPT checks, with the default [sieve] enabled_extensions.
	if err := ValidateScript(script, nil); err != nil {
		t.Fatalf("ValidateScript: %v", err)
	}
	executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	saved := time.Local
	t.Cleanup(func() { time.Local = saved })
	for _, name := range []string{"UTC", "Europe/Berlin", "America/Los_Angeles"} {
		loc, err := time.LoadLocation(name)
		if err != nil {
			t.Fatal(err)
		}
		time.Local = loc // no test in this package runs in parallel
		for _, date := range []string{
			"Wed, 17 Jul 1996 02:23:25 -0700",
			"Wed, 17 Jul 1996 02:23:25 PDT",
			"Wed, 17 Jul 1996 02:23:25 pdt",
		} {
			result, err := executor.Evaluate(context.Background(), Context{
				EnvelopeFrom: "sender@example.com",
				EnvelopeTo:   "user@example.com",
				Header:       map[string][]string{"Date": {date}, "From": {"sender@example.com"}},
				Message:      bodyOnly("body"),
			})
			if err != nil {
				t.Fatalf("TZ=%s %q: evaluate: %v", name, date, err)
			}
			if want := []string{"hour02"}; !slices.Equal(result.Mailboxes, want) {
				t.Errorf("TZ=%s Date: %s: mailboxes = %q, want %q", name, date, result.Mailboxes, want)
			}
		}
	}
}
