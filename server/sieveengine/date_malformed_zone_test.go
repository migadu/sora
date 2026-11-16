package sieveengine

import (
	"context"
	"slices"
	"testing"
	"time"
	_ "time/tzdata" // the zones the test runs in, on hosts without zoneinfo
)

// TestDateMalformedZone is issue #1514: the date test (RFC 5260 §4) read a
// Date: zone of GMT and a signed hour with the time of day shifted by that
// hour (12:00:00 GMT+1 as 13:00:00 +0100), read +01 and CET/CEST by the
// server's zone, and did not read GMT+0200, UTC-0500 or PDT+0400 at all.
//
// RFC 5322 §3.3 has zone = (FWS ( "+" / "-" ) 4DIGIT) / obs-zone, §4.3 has a
// zone "whose meaning is not known" be "considered equivalent to "-0000"", and
// RFC 5256 §2.2 says "If the time zone is invalid, the date and time SHOULD be
// treated as UTC." So each is the time of day as written at offset zero, which
// RFC 5260 §4.2 writes as zone "+0000" ("An offset of 0 (Zulu) always has a
// positive sign") and with iso8601 "Z" ("a time zone offset of zero MUST be
// represented by "Z""). Letters before a numeric offset are still not a date.
func TestDateMalformedZone(t *testing.T) {
	const script = `require ["date", "fileinto"];
if allof (date :originalzone "date" "hour" "12",
          date :originalzone "date" "zone" "+0000",
          date :originalzone "date" "iso8601" "2019-01-01T12:00:00Z",
          date :originalzone "date" "std11" "Tue, 01 Jan 2019 12:00:00 +0000",
          date :zone "+0100" "date" "time" "13:00:00") { fileinto "written"; }
elsif date :originalzone "date" "hour" "13" { fileinto "hour13"; }
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

	cases := []struct {
		date string
		want []string
	}{
		{"Tue, 01 Jan 2019 12:00:00 +0000", []string{"written"}},
		{"Tue, 01 Jan 2019 12:00:00 -0000", []string{"written"}},
		{"Tue, 01 Jan 2019 12:00:00 GMT+1", []string{"written"}},
		{"Tue, 01 Jan 2019 12:00:00 GMT-5", []string{"written"}},
		{"Tue, 01 Jan 2019 12:00:00 GMT+0200", []string{"written"}},
		{"Tue, 01 Jan 2019 12:00:00 UTC-0500", []string{"written"}},
		{"Tue, 01 Jan 2019 12:00:00 PDT+0400", []string{"written"}},
		{"Tue, 01 Jan 2019 12:00:00 +01", []string{"written"}},
		{"Tue, 01 Jan 2019 12:00:00 CET/CEST", []string{"written"}},
		{"Tue, 01 Jan 2019 12:00:00 PDT/UTC", []string{"written"}},
		{"Tue, 01 Jan 2019 12:00:00 XYZ", []string{"written"}},
		{"Tue, 01 Jan 2019 12:00:00 PM -0700", []string{"nomatch"}},
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
			result, err := executor.Evaluate(context.Background(), Context{
				EnvelopeFrom: "sender@example.com",
				EnvelopeTo:   "user@example.com",
				Header:       map[string][]string{"Date": {tc.date}, "From": {"sender@example.com"}},
				Message:      bodyOnly("body"),
			})
			if err != nil {
				t.Fatalf("TZ=%s %q: evaluate: %v", name, tc.date, err)
			}
			if !slices.Equal(result.Mailboxes, tc.want) {
				t.Errorf("TZ=%s Date: %s: mailboxes = %q, want %q", name, tc.date, result.Mailboxes, tc.want)
			}
		}
	}
}
