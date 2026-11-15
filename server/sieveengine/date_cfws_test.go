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

// Letters that a numeric offset follows, after white space or a comment, are
// not the zone: "time = time-of-day zone" (RFC 5322 §3.3) has one zone, so none
// of these is a date-time, and RFC 5260 §4: the date test "returns false
// unconditionally if ... the field exists but does not contain a syntactically
// valid date-time specification" (its count is 0). Replacing the letters made
// net/mail discard the offset after them and read a wrong instant. The first
// two were not dates until comments were read as white space; the stored sent
// date (helpers.ParseDateHeader) reads none of them.
func TestDateLettersBeforeOffsetNotADate(t *testing.T) {
	const script = `require ["date", "fileinto", "relational", "comparator-i;ascii-numeric"];
if date :count "eq" :comparator "i;ascii-numeric" "date" "year" "0" { fileinto "nodate"; }
else { fileinto "date"; }
`
	if err := ValidateScript(script, nil); err != nil {
		t.Fatalf("ValidateScript: %v", err)
	}
	executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, date := range []string{
		"Wed, 17 Jul 1996 02:23:25 (c) PDT (c) +0500",
		"Wed, 17 Jul 1996 02:23:25 (x) Wed -0700",
		"Wed, 17 Jul 1996 02:23:25 PDT (c) +0500",
		"Wed, 17 Jul 1996 02:23:25 PM -0700",
		"Wed, 17 Jul 1996 02:23:25 PDT +0500",
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
		if want := []string{"nodate"}; !slices.Equal(result.Mailboxes, want) {
			t.Errorf("Date: %s: mailboxes = %q, want %q", date, result.Mailboxes, want)
		}
	}
}
