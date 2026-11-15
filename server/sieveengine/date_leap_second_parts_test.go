package sieveengine

import (
	"context"
	"fmt"
	"testing"
)

// A representable stored instant can clamp second 60, but RFC 5260's Sieve
// parts must retain the header's second, including after a zone conversion.
func TestDateLeapSecondParts(t *testing.T) {
	const leap = "Sat, 31 Dec 2016 23:59:60 +0000"
	for _, tc := range []struct {
		part, key, zone, date string
		want                  bool
	}{
		{"second", "60", "", leap, true}, {"second", "59", "", leap, false},
		{"time", "23:59:60", "", leap, true}, {"time", "23:59:59", "", leap, false},
		{"iso8601", "2016-12-31T23:59:60Z", "", leap, true}, {"iso8601", "2016-12-31T23:59:59Z", "", leap, false},
		{"std11", "Sat, 31 Dec 2016 23:59:60 +0000", "", leap, true}, {"std11", "Sat, 31 Dec 2016 23:59:59 +0000", "", leap, false},
		{"date", "2017-01-01", "+0100", leap, true}, {"time", "00:59:60", "+0100", leap, true},
		{"iso8601", "2017-01-01T00:59:60+01:00", "+0100", leap, true},
		{"zone", "+0000", "", leap, true},
		{"second", "59", "", "Sat, 31 Dec 2016 23:59:59 +0000", true},
		{"second", "60", "", "Sat, 31 Dec 2016 23:59:59 +0000", false},
		{"second", "60", "", "Sat, 31 Dec 2016 23:59:61 +0000", false},
	} {
		t.Run(fmt.Sprintf("%s_%s_%s_%s", tc.part, tc.key, tc.zone, tc.date), func(t *testing.T) {
			zone := ":originalzone"
			if tc.zone != "" {
				zone = fmt.Sprintf(":zone %q", tc.zone)
			}
			script := fmt.Sprintf(`require ["date","fileinto"]; if date %s "Date" %q %q { fileinto "Hit"; }`, zone, tc.part, tc.key)
			ex, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
			if err != nil {
				t.Fatal(err)
			}
			res, err := ex.Evaluate(context.Background(), Context{EnvelopeFrom: "sender@example.com", EnvelopeTo: "user@example.com", Header: map[string][]string{"Date": {tc.date}}, Message: bodyOnly("body")})
			if err != nil {
				t.Fatal(err)
			}
			if got := len(res.Mailboxes) > 0; got != tc.want {
				t.Errorf("%s %q matched=%v, want %v for %s", tc.part, tc.key, got, tc.want, tc.date)
			}
		})
	}
}

// These features share one parser path: selecting a Received suffix, expanding
// date arguments, and normalizing an obsolete year must retain leap metadata.
func TestDateCombinedLeapMetadata(t *testing.T) {
	for _, tc := range []struct{ name, field, value, condition string }{
		{"received-comment", "Received", "from mx by backend; Sat, 31 Dec 2016 23:59:60 +0000 (route; note)", `date :zone "+0000" "Received" "iso8601" "2016-12-31T23:59:60Z"`},
		{"variable-zone-part", "Date", "Sat, 31 Dec 2016 23:59:60 +0000", `date :zone "${z}" "Date" "${p}" "2017-01-01T00:59:60+01:00"`},
		{"cfws-year-leap", "Date", "Sun (day) , 31 Dec (year) 50 23 : 59 : (sec) 60 +0000", `date :originalzone "Date" "iso8601" "1950-12-31T23:59:60Z"`},
		{"obsolete-year", "Date", "Sun, 31 Dec 50 23:59:60 +0000", `date :originalzone "Date" "iso8601" "1950-12-31T23:59:60Z"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := `require ["date", "fileinto", "variables"]; set "z" "+0100"; set "p" "iso8601"; if ` + tc.condition + ` { fileinto "Hit"; }`
			ex, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
			if err != nil {
				t.Fatal(err)
			}
			res, err := ex.Evaluate(context.Background(), Context{EnvelopeFrom: "sender@example.com", EnvelopeTo: "user@example.com", Header: map[string][]string{tc.field: {tc.value}}, Message: bodyOnly("body")})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Mailboxes) != 1 || res.Mailboxes[0] != "Hit" {
				t.Fatalf("mailboxes = %v, want [Hit]", res.Mailboxes)
			}
		})
	}
}
