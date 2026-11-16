package helpers

import (
	"testing"
	"time"
)

// The RFC 5322 obs-zone names are ASCII case insensitive. Unicode case
// conversion must not turn an unknown token into a known US time zone.
func TestParseDateHeaderUnknownZoneDoesNotFoldUnicode(t *testing.T) {
	want := time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, zone := range []string{"EſT", "eſt", "PſT", "CſT", "MſT"} {
		t.Run(zone, func(t *testing.T) {
			value := "Tue, 01 Jan 2019 12:00:00 " + zone
			got, err := ParseDateHeader(value)
			if err != nil || !got.Equal(want) {
				t.Fatalf("non-ASCII zone %q = %v, %v; want written time as unknown UTC, %v", zone, got, err, want)
			}
		})
	}
}

func TestParseDateHeaderKnownZoneFoldsASCII(t *testing.T) {
	for _, tc := range []struct {
		zone   string
		offset int
	}{
		{"EST", -5 * 60 * 60}, {"est", -5 * 60 * 60}, {"eSt", -5 * 60 * 60},
		{"PST", -8 * 60 * 60}, {"pst", -8 * 60 * 60},
		{"CST", -6 * 60 * 60}, {"cst", -6 * 60 * 60},
		{"MST", -7 * 60 * 60}, {"mst", -7 * 60 * 60},
		{"PdT", -7 * 60 * 60}, {"eDt", -4 * 60 * 60},
	} {
		t.Run(tc.zone, func(t *testing.T) {
			value := "Tue, 01 Jan 2019 12:00:00 " + tc.zone
			got, err := ParseDateHeader(value)
			want := time.Date(2019, 1, 1, 12, 0, 0, 0, time.FixedZone("", tc.offset))
			_, offset := got.Zone()
			if err != nil || !got.Equal(want) || offset != tc.offset {
				t.Fatalf("ASCII known zone %q = %v, %v; want %v", tc.zone, got, err, want)
			}
		})
	}
}
