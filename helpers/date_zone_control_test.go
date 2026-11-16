package helpers

import (
	"testing"
	"time"
)

// Unknown-zone recovery may replace an uninterpretable printable token with
// -0000, but must not erase invalid control octets from the Date header.
func TestParseDateHeaderRejectsControlsInZoneToken(t *testing.T) {
	for _, token := range []string{
		"GMT+1\x00junk",
		"CET\x00",
		"CET\x01",
		"CET\x1b",
		"CET\x1f",
		"CET\x7f",
		"GMT\x7f",
		"PDT\x00",
	} {
		value := "Tue, 01 Jan 2019 12:00:00 " + token
		t.Run(token, func(t *testing.T) {
			got, err := ParseDateHeader(value)
			if err == nil || !got.IsZero() {
				t.Fatalf("control-bearing Date %q = %v, %v; want no date and an error", value, got, err)
			}
		})
	}
}

// Validate the zone after normal CFWS handling. FWS, quoted parentheses,
// obsolete comment text and obs-qp's quoted NUL must retain their existing
// meaning; rejecting controls everywhere would break these valid comments.
func TestParseDateHeaderZoneControlValidationPreservesCFWS(t *testing.T) {
	for _, tc := range []struct {
		name, suffix string
		offset       int
	}{
		{"unknown printable", "GMT+1", 0},
		{"unknown punctuation", "CET/CEST", 0},
		{"tab after unknown zone", "GMT+1\t(comment)", 0},
		{"fold after unknown zone", "GMT+1\r\n\t(comment)", 0},
		{"tab before known zone", "\tGMT", 0},
		{"tab in comment", "GMT (with\ttab)", 0},
		{"quoted closing parenthesis", "GMT+1 (quoted \\) close)", 0},
		{"quoted NUL in comment", "GMT+1 (quoted \\\x00)", 0},
		{"obsolete control in comment", "GMT (obsolete \x01 text)", 0},
		{"known nonzero zone", "-0700 (Pacific)", -7 * 60 * 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := "Tue, 01 Jan 2019 12:00:00 " + tc.suffix
			got, err := ParseDateHeader(value)
			want := time.Date(2019, 1, 1, 12, 0, 0, 0, time.FixedZone("", tc.offset))
			if err != nil || !got.Equal(want) {
				t.Fatalf("Date with valid zone/CFWS %q = %v, %v; want %v", value, got, err, want)
			}
		})
	}
}
