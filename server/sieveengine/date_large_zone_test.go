package sieveengine

import (
	"context"
	"testing"
)

func TestDateISO8601LargeZone(t *testing.T) {
	for _, tc := range []struct{ name, value, zoneArg, want string }{
		{"east", "Tue, 01 Jan 2019 12:00:00 +2500", ":originalzone", "2018-12-31T11:00:00Z"},
		{"west", "Tue, 01 Jan 2019 12:00:00 -2500", ":originalzone", "2019-01-02T13:00:00Z"},
		{"boundary", "Tue, 01 Jan 2019 12:00:00 +2400", ":originalzone", "2018-12-31T12:00:00Z"},
		{"representable", "Tue, 01 Jan 2019 12:00:00 +2359", ":originalzone", "2019-01-01T12:00:00+23:59"},
		{"zero", "Tue, 01 Jan 2019 12:00:00 +0000", ":originalzone", "2019-01-01T12:00:00Z"},
		{"leap", "Mon, 02 Jan 2017 00:59:60 +2500", ":originalzone", "2016-12-31T23:59:60Z"},
		{"explicit zone", "Tue, 01 Jan 2019 12:00:00 +0000", `:zone "+2500"`, "2019-01-01T12:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := `require ["date","variables","fileinto"]; if date ` + tc.zoneArg + ` :matches "X-Date" "iso8601" "*" { fileinto "${1}"; }`
			executor, err := NewSieveExecutorWithExtensions(script, DefaultSieveExtensions)
			if err != nil {
				t.Fatal(err)
			}
			result, err := executor.Evaluate(context.Background(), Context{EnvelopeFrom: "sender@example.com", EnvelopeTo: "user@example.com", Header: map[string][]string{"X-Date": {tc.value}}, Message: bodyOnly("body")})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Mailboxes) != 1 || result.Mailboxes[0] != tc.want {
				t.Fatalf("iso8601=%q, want %q", result.Mailboxes, tc.want)
			}
		})
	}
}
