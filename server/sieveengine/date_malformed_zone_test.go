package sieveengine

import (
	"context"
	"slices"
	"testing"
	"time"
	_ "time/tzdata" // the zones the test runs in, on hosts without zoneinfo
)

// TestDateMalformedZone covers issues #1514 and #1778: how the date test
// (RFC 5260 §4) reads the zone of a Date: field, in whatever zone the server
// runs.
//
// RFC 5322 §3.3 has zone = (FWS ( "+" / "-" ) 4DIGIT) / obs-zone, and "the
// last two digits of the zone MUST be within the range 00 through 59". A value
// whose zone is not that (GMT+1, UTC-0500, +01, +01:00, CET/CEST, +0060) is not
// a date-time, and RFC 5260 §4 says "The date test returns false
// unconditionally if the specified header field does not exist, the field
// exists but does not contain a syntactically valid date-time specification",
// so every date test is false and :count is 0. RFC 5256 §2.2's "If the time
// zone is invalid, the date and time SHOULD be treated as UTC" is for the sent
// date of IMAP SORT, not for Sieve.
//
// An alphabetic zone whose meaning is not known (CET, XYZ, a military letter)
// is a zone: RFC 5322 §4.3 has it "considered equivalent to "-0000"", so it is
// the time of day as written at offset zero, which RFC 5260 §4.2 writes as
// "+0000" ("An offset of 0 (Zulu) always has a positive sign").
func TestDateMalformedZone(t *testing.T) {
	const script = `require ["date", "fileinto", "variables", "relational", "comparator-i;ascii-numeric"];
if date :count "eq" :comparator "i;ascii-numeric" "date" "year" "0" {
  if date :matches "date" "year" "*" { fileinto "counted 0 but matched"; }
  else { fileinto "invalid"; }
  stop;
}
if date :matches :originalzone "date" "zone" "*" { set "zone" "${1}"; }
if date :matches :zone "+0100" "date" "time" "*" { set "time" "${1}"; }
fileinto "${zone} ${time}";
`
	// What ManageSieve PUTSCRIPT checks, with the default [sieve] enabled_extensions.
	if err := ValidateScript(script, nil); err != nil {
		t.Fatalf("ValidateScript: %v", err)
	}
	executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// The original zone, and the time of day at +0100, of 12:00:00 in each zone.
	cases := []struct {
		zone string
		want string
	}{
		// Valid zones.
		{"+0000", "+0000 13:00:00"},
		{"-0000", "+0000 13:00:00"},
		{"+0100", "+0100 12:00:00"},
		{"-0530", "-0530 18:30:00"},
		{"GMT", "+0000 13:00:00"},
		{"PDT", "-0700 20:00:00"},
		{"+0000 (UTC)", "+0000 13:00:00"},
		// Alphabetic zones whose meaning is not known: -0000.
		{"XYZ", "+0000 13:00:00"},
		{"CET", "+0000 13:00:00"},
		{"A", "+0000 13:00:00"},
		// Zones that are not RFC 5322 zones: not a date.
		{"GMT+1", "invalid"},
		{"GMT-5", "invalid"},
		{"GMT+0200", "invalid"},
		{"UTC-0500", "invalid"},
		{"PDT+0400", "invalid"},
		{"+01", "invalid"},
		{"+01:00", "invalid"},
		{"CET/CEST", "invalid"},
		{"PDT/UTC", "invalid"},
		{"+0060", "invalid"},
		{"+0000 junk", "invalid"},
		{"-0400 EDT", "invalid"},
		{"PM -0700", "invalid"},
	}
	saved := time.Local
	t.Cleanup(func() { time.Local = saved })
	for _, name := range []string{"UTC", "Africa/Casablanca", "Europe/Berlin", "America/Los_Angeles"} {
		loc, err := time.LoadLocation(name)
		if err != nil {
			t.Fatal(err)
		}
		time.Local = loc // no test in this package runs in parallel
		for _, tc := range cases {
			date := "Tue, 01 Jan 2019 12:00:00 " + tc.zone
			result, err := executor.Evaluate(context.Background(), Context{
				EnvelopeFrom: "sender@example.com",
				EnvelopeTo:   "user@example.com",
				Header:       map[string][]string{"Date": {date}, "From": {"sender@example.com"}},
				Message:      bodyOnly("body"),
			})
			if err != nil {
				t.Fatalf("TZ=%s %q: evaluate: %v", name, date, err)
			}
			if want := []string{tc.want}; !slices.Equal(result.Mailboxes, want) {
				t.Errorf("TZ=%s Date: %s: mailboxes = %q, want %q", name, date, result.Mailboxes, want)
			}
		}
	}
}

// TestDateRFC3339Field: the date test also reads a field holding an RFC 3339
// date-time, by RFC 3339's grammar (section 5.6: time-numoffset = ("+" / "-")
// time-hour ":" time-minute, with time-hour 00-23 and time-minute 00-59). So
// "+01:00" is that field's zone, although after an RFC 5322 date-time it makes
// the field no date (TestDateMalformedZone). docs/SIEVE.md describes both.
func TestDateRFC3339Field(t *testing.T) {
	const script = `require ["date", "fileinto", "variables", "relational", "comparator-i;ascii-numeric"];
if date :count "eq" :comparator "i;ascii-numeric" "date" "year" "0" { fileinto "invalid"; stop; }
if date :matches :originalzone "date" "zone" "*" { set "zone" "${1}"; }
if date :matches :originalzone "date" "time" "*" { set "time" "${1}"; }
fileinto "${zone} ${time}";
`
	executor, err := NewSieveExecutorWithExtensions(script, DefaultSieveExtensions)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, tc := range []struct{ date, want string }{
		{"2019-01-01T12:00:00+01:00", "+0100 12:00:00"},
		{"2019-01-01T12:00:00-05:30", "-0530 12:00:00"},
		{"2019-01-01T12:00:00Z", "+0000 12:00:00"},
		{"2019-01-01T12:00:00+24:00", "invalid"},
		{"2019-01-01T12:00:00+01:60", "invalid"},
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
		if want := []string{tc.want}; !slices.Equal(result.Mailboxes, want) {
			t.Errorf("Date: %s: mailboxes = %q, want %q", tc.date, result.Mailboxes, want)
		}
	}
}
