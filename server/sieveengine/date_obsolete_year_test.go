package sieveengine

import (
	"context"
	"slices"
	"testing"

	"github.com/migadu/sora/helpers"
)

// TestDateObsoleteYear is issue #1378: the date test (RFC 5260 §4) read a
// two-digit Date: year from 50 to 68 as 20xx and did not parse a three-digit
// year. RFC 5322 §4.3: "If a two digit year is encountered whose value is
// between 00 and 49, the year is interpreted by adding 2000 ... If a two digit
// year is encountered with a value between 50 and 99, or any three digit year
// is encountered, the year is interpreted by adding 1900." The issue's script
// files the first message into y1950 and the second into y2000.
func TestDateObsoleteYear(t *testing.T) {
	const script = `require ["date", "fileinto"];
if date :is "date" "year" "1950" { fileinto "y1950"; }
elsif date :is "date" "year" "2050" { fileinto "y2050"; }
elsif date :is "date" "year" "2000" { fileinto "y2000"; }
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
	for _, tc := range []struct {
		date string
		want []string
	}{
		{"Mon, 17 Jul 50 02:23:25 +0000", []string{"y1950"}},
		{"Mon, 3 Jan 100 10:00:00 +0000", []string{"y2000"}},
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

// TestDateYearMatchesSentDate: the date test reads a two- or three-digit year as
// helpers.ParseDateHeader does for the stored sent date (#1368), so a script and
// the SENT* search keys see the same date.
func TestDateYearMatchesSentDate(t *testing.T) {
	for _, date := range []string{
		"Sat, 17 Jul 49 02:23:25 +0000",
		"Mon, 17 Jul 50 02:23:25 +0000",
		"Wed, 17 Jul 68 02:23:25 -0700",
		"Thu, 17 Jul 69 02:23:25 +0000",
		"17 Jul 50 02:23 PDT",
		"Mon, 3 Jan 100 10:00:00 +0000",
		"Tue, 17 Nov 126 09:00:00 EST",
	} {
		sent, err := helpers.ParseDateHeader(date)
		if err != nil {
			t.Fatalf("ParseDateHeader(%q): %v", date, err)
		}
		script := `require ["date", "fileinto"];
if date :originalzone "date" "date" "` + sent.Format("2006-01-02") + `" { fileinto "same"; }
`
		executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		result, err := executor.Evaluate(context.Background(), Context{
			EnvelopeFrom: "sender@example.com",
			EnvelopeTo:   "user@example.com",
			Header:       map[string][]string{"Date": {date}, "From": {"sender@example.com"}},
			Message:      bodyOnly("body"),
		})
		if err != nil {
			t.Fatalf("%q: evaluate: %v", date, err)
		}
		if want := []string{"same"}; !slices.Equal(result.Mailboxes, want) {
			t.Errorf("Date: %s: mailboxes = %q, want %q (sent date %s)", date, result.Mailboxes, want, sent.Format("2006-01-02"))
		}
	}
}
