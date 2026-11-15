package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestDateCFWS is issue #1385: the date test (RFC 5260 §4) did not read a Date:
// header with comments or white space between the tokens of the obsolete
// date-time syntax, so the issue's script filed each of these into nomatch.
// RFC 5322 §4.3: the obsolete date syntax "also permits comments and folding
// white space between many of the tokens", and §4: such forms "MUST be
// accepted and parsed by a conformant receiver". The stored sent date reads
// them since #1379 (helpers.ParseDateHeader).
func TestDateCFWS(t *testing.T) {
	const script = `require ["date", "fileinto"];
if date :zone "-0700" "date" "hour" "02" { fileinto "hour02"; }
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
	for _, date := range []string{
		"Wed, 17 Jul 1996 02:23:25 -0700",
		"Wed, 17 Jul 1996 02:23:25 (c) -0700",
		"Wed , 17 Jul 1996 02:23:25 -0700",
		"Wed, 17 Jul 1996 02 : 23 : 25 -0700",
		"(Wed) 17 Jul 1996 02:23:25 -0700",
		"Wed, 17 (July) Jul 1996 02:23:25 -0700",
		"Wed, 17 Jul 1996 02:23:25 (Pacific) PDT",
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
		if want := []string{"hour02"}; !slices.Equal(result.Mailboxes, want) {
			t.Errorf("Date: %s: mailboxes = %q, want %q", date, result.Mailboxes, want)
		}
	}
}
