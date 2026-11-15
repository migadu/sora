package helpers

import (
	"io/fs"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // the zones the test runs ParseDateHeader in, on hosts without zoneinfo

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseDateHeaderObsoleteZone: an alphabetic zone has the offset RFC 5322 section 4.3
// gives it ("PDT is semantically equivalent to -0700"), and a military or unknown zone
// "-0000", in whatever zone the host runs. net/mail.ParseDate gives PDT +0000 on a host in
// UTC, EST in July -0400 on one in America/New_York and CET +0100 on one in Europe/Berlin,
// and does not parse a lower-case or military zone at all.
func TestParseDateHeaderObsoleteZone(t *testing.T) {
	const h = 3600
	cases := []struct {
		value  string
		wall   time.Time // the date and time as written, in UTC
		offset int       // seconds east of UTC
	}{
		{"Wed, 17 Jul 1996 02:23:25 UT", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		{"Wed, 17 Jul 1996 02:23:25 GMT", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		{"Wed, 17 Jul 1996 02:23:25 EDT", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), -4 * h},
		{"Wed, 17 Jul 1996 02:23:25 EST", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), -5 * h},
		{"Wed, 17 Jul 1996 02:23:25 CDT", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), -5 * h},
		{"Wed, 17 Jan 1996 02:23:25 CST", time.Date(1996, 1, 17, 2, 23, 25, 0, time.UTC), -6 * h},
		{"Wed, 17 Jul 1996 02:23:25 MDT", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), -6 * h},
		{"Wed, 17 Jan 1996 02:23:25 MST", time.Date(1996, 1, 17, 2, 23, 25, 0, time.UTC), -7 * h},
		{"Wed, 17 Jul 1996 02:23:25 PDT", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), -7 * h},
		{"Wed, 17 Jan 1996 02:23:25 PST", time.Date(1996, 1, 17, 2, 23, 25, 0, time.UTC), -8 * h},
		{"Wed, 17 Jul 1996 02:23:25 pdt", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), -7 * h},
		{"Wed, 17 Jul 1996 02:23:25 Gmt", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		{"Wed, 17 Jul 1996 02:23:25 PDT (Pacific Daylight Time)", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), -7 * h},
		{"Wed, 17 Jul 1996 02:23:25\r\n PDT", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), -7 * h},
		{"Wed, 17 Jul 1996 02:23:25\r\n\tPdT", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), -7 * h},
		{"Wed, 17 Jul 1996 02:23:25PDT", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), -7 * h},
		{"Wed, 17 Jul 1996 02:23:25 PDT(comment)", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), -7 * h},
		{"Wed, 17 Jul 1996 02:23:25 PDT (-0700)", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), -7 * h},
		{"17 Jul 96 02:23 PDT", time.Date(1996, 7, 17, 2, 23, 0, 0, time.UTC), -7 * h},
		// Military zones and other names: "-0000".
		{"Wed, 17 Jul 1996 02:23:25 Z", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		{"Wed, 17 Jul 1996 02:23:25 z", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		{"Wed, 17 Jul 1996 02:23:25 A", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		{"Wed, 17 Jul 1996 02:23:25 Y", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		{"Wed, 17 Jan 1996 02:23:25 CET", time.Date(1996, 1, 17, 2, 23, 25, 0, time.UTC), 0},
		{"Wed, 17 Jul 1996 02:23:25 CEST", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		{"Wed, 17 Jul 1996 02:23:25 MSK", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		// Numeric zones are net/mail's, unchanged.
		{"Wed, 17 Jul 1996 02:23:25 -0700 (PDT)", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), -7 * h},
		{"Wed, 17 Jul 1996 02:23:25 +0530", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC), 5*h + 30*60},
	}

	saved := time.Local
	t.Cleanup(func() { time.Local = saved })
	for _, name := range []string{"UTC", "America/Los_Angeles", "America/New_York", "Europe/Berlin", "Asia/Kolkata"} {
		loc, err := time.LoadLocation(name)
		require.NoError(t, err)
		time.Local = loc // no test in this package runs in parallel
		for _, tc := range cases {
			got, err := ParseDateHeader(tc.value)
			if !assert.NoError(t, err, "TZ=%s %q", name, tc.value) {
				continue
			}
			want := tc.wall.Add(-time.Duration(tc.offset) * time.Second)
			_, offset := got.Zone()
			assert.True(t, got.Equal(want), "TZ=%s %q: %v, want %v", name, tc.value, got, want.In(time.FixedZone("", tc.offset)))
			assert.Equal(t, tc.offset, offset, "TZ=%s %q: zone offset of %v", name, tc.value, got)
		}
	}
}

// TestParseDateHeaderObsoleteYear: a two- or three-digit year (obs-year) is read by
// RFC 5322 section 4.3: "If a two digit year is encountered whose value is between 00 and
// 49, the year is interpreted by adding 2000 ... If a two digit year is encountered with a
// value between 50 and 99, or any three digit year is encountered, the year is interpreted
// by adding 1900." net/mail.ParseDate reads a two-digit year with time.Parse's "06", which
// puts 50-68 in 20xx, and does not parse a three-digit year at all.
func TestParseDateHeaderObsoleteYear(t *testing.T) {
	const h = 3600
	cases := []struct {
		value  string
		wall   time.Time // the date and time as written, in UTC
		offset int       // seconds east of UTC
	}{
		{"Sat, 1 Jan 00 00:00:00 +0000", time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), 0},
		{"Sat, 17 Jul 49 02:23:25 +0000", time.Date(2049, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		{"Mon, 17 Jul 50 02:23:25 +0000", time.Date(1950, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		{"Wed, 17 Jul 68 02:23:25 +0000", time.Date(1968, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		{"Thu, 17 Jul 69 02:23:25 +0000", time.Date(1969, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		{"Sat, 17 Jul 99 02:23:25 +0000", time.Date(1999, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		{"17 Jul 50 02:23 PDT", time.Date(1950, 7, 17, 2, 23, 0, 0, time.UTC), -7 * h},
		{"Mon, 17 Jul  50  02:23:25 +0000", time.Date(1950, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		{"Mon, 17 Jul\r\n 50\r\n 02:23:25 +0000", time.Date(1950, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		// Three digits: years since 1900.
		{"Mon, 3 Jan 100 10:00:00 +0000", time.Date(2000, 1, 3, 10, 0, 0, 0, time.UTC), 0},
		{"Tue, 17 Nov 126 09:00:00 -0500", time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC), -5 * h},
		{"Sat, 1 Jan 049 00:00:00 +0000", time.Date(1949, 1, 1, 0, 0, 0, 0, time.UTC), 0},
		{"Mon, 1 Jan 000 00:00:00 +0000", time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC), 0},
		{"Thu, 31 Dec 999 23:59:59 +0000", time.Date(2899, 12, 31, 23, 59, 59, 0, time.UTC), 0},
		{"Mon, 3 Jan 100 10:00:00 EST", time.Date(2000, 1, 3, 10, 0, 0, 0, time.UTC), -5 * h},
		// A zone left to net/mail as written still gets the year read by section 4.3.
		{"Mon, 17 Jul 50 02:23:25 GMT+0000", time.Date(1950, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		// Four digits are taken as written.
		{"Sun, 17 Jul 2050 02:23:25 +0000", time.Date(2050, 7, 17, 2, 23, 25, 0, time.UTC), 0},
		{"Wed, 17 Jul 1968 02:23:25 +0000", time.Date(1968, 7, 17, 2, 23, 25, 0, time.UTC), 0},
	}
	for _, tc := range cases {
		got, err := ParseDateHeader(tc.value)
		if !assert.NoError(t, err, "%q", tc.value) {
			continue
		}
		want := tc.wall.Add(-time.Duration(tc.offset) * time.Second)
		_, offset := got.Zone()
		assert.True(t, got.Equal(want), "%q: %v, want %v", tc.value, got, want.In(time.FixedZone("", tc.offset)))
		assert.Equal(t, tc.offset, offset, "%q: zone offset of %v", tc.value, got)
	}
}

// TestParseDateHeaderCFWS: comments and white space between the tokens of a date-time are
// read as separators. RFC 5322 section 4.3: the obsolete syntax "permits comments and
// folding white space between many of the tokens" (obs-day-of-week = [CFWS] day-name
// [CFWS], obs-hour = [CFWS] 2DIGIT [CFWS], ...), and section 4: such forms "MUST be
// accepted and parsed by a conformant receiver". net/mail.ParseDate takes a comment only
// after the zone and white space only where its layouts have one space.
func TestParseDateHeaderCFWS(t *testing.T) {
	const h = 3600
	wall := time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC)
	cases := []struct {
		value  string
		offset int // seconds east of UTC
	}{
		{"Wed, 17 Jul 1996 02:23:25 (c) -0700", -7 * h},
		{"Wed , 17 Jul 1996 02:23:25 -0700", -7 * h},
		{"Wed, 17 Jul 1996 02 : 23 : 25 -0700", -7 * h},
		{"(Wed) 17 Jul 1996 02:23:25 -0700", -7 * h},
		{"Wed, 17 (July) Jul 1996 02:23:25 -0700", -7 * h},
		{"Wed, 17 Jul 1996 02:23:25 (Pacific) PDT", -7 * h},
		{"Wed (Wednesday) , (the) 17 (th) Jul (of) 1996 (at) 02 (h) : (m) 23 (s) : 25 (z) -0700 (PDT)", -7 * h},
		{"Wed, 17 Jul 1996 02(h):(m)23(s):25 -0700", -7 * h},
		{"Wed, 17 Jul 1996 02:23:25 PDT(Pacific)(Daylight Time)", -7 * h},
		// Nested comments and quoted-pairs (RFC 5322 section 3.2.2).
		{"Wed, 17 Jul 1996 02:23:25 (a (nested) \\) comment) -0700", -7 * h},
		{"Wed, 17 Jul 1996 02:23:25 (\\(c) PDT", -7 * h},
		// Obsolete quoted-pair permits an escaped NUL; unquoted NUL is invalid.
		{"Wed, 17 Jul 1996 02:23:25 (quoted\\\x00) -0700", -7 * h},
		// A comment holding the characters the zone and the time are found by.
		{"Wed, 17 Jul 1996 02:23:25 (UTC-7) PDT", -7 * h},
		{"(Wed: 17 Jul) Wed, 17 Jul 1996 02:23:25 PDT", -7 * h},
		// Folding white space: tabs, runs, a fold around a comment.
		{"Wed,\t17\tJul\t1996\t02:23:25\t-0700", -7 * h},
		{"  Wed,   17  Jul   1996  02:23:25    PDT  ", -7 * h},
		{"Wed, 17 Jul 1996 02:23:25\r\n (c)\r\n\t-0700", -7 * h},
		// day = ([FWS] 1*2DIGIT FWS): the white space after the comma is optional.
		{"Wed,17 Jul 1996 02:23:25 -0700", -7 * h},
		{"Wed,(c)17 Jul 1996 02:23:25 +0530", 5*h + 30*60},
		// obs-year = [CFWS] 2*DIGIT [CFWS], read by section 4.3 as well.
		{"Wed, 17 Jul (y) 96 (t) 02:23:25 PDT", -7 * h},
		{"Wed, 17 Jul	96	02:23:25 -0700", -7 * h},
		// A zone left to net/mail as written (an extension it accepts).
		{"Wed , 17 Jul 1996 02:23:25 (c) GMT+0000", 0},
	}
	for _, tc := range cases {
		got, err := ParseDateHeader(tc.value)
		if !assert.NoError(t, err, "%q", tc.value) {
			continue
		}
		want := wall.Add(-time.Duration(tc.offset) * time.Second)
		_, offset := got.Zone()
		assert.True(t, got.Equal(want), "%q: %v, want %v", tc.value, got, want.In(time.FixedZone("", tc.offset)))
		assert.Equal(t, tc.offset, offset, "%q: zone offset of %v", tc.value, got)
	}
}

// TestParseDateHeaderInvalid: a value net/mail does not parse is still an error.
func TestParseDateHeaderInvalid(t *testing.T) {
	for _, value := range []string{
		"", "PDT", "Wed, 17 Jul 1996 PDT", "not a date 12:00 PDT",
		// Replacing only the alphabetic prefix would let net/mail discard the
		// rest after the numeric replacement, turning these errors into dates.
		"Wed, 17 Jul 1996 02:23:25 PDT+0400",
		"Wed, 17 Jul 1996 02:23:25 PDT0",
		"Wed, 17 Jul 1996 02:23:25 PDT-0700",
		"Wed, 17 Jul 1996 02:23:25\r PDT",
		"Wed, 17 Jul 1996 02:23:25\n PDT",
		"Wed, 17 Jul 1996 02:23:25 GMT+0200",
		"Wed, 17 Jul 1996 02:23:25 UTC-0500",
		// Nor are letters a zone when a numeric offset follows them after white space
		// or a comment: the RFC 5322 section 3.3 grammar has one zone after the time of
		// day ("time = time-of-day zone"), and the offset after the letters would be
		// discarded.
		"Wed, 17 Jul 1996 02:23:25 PM -0700",
		"Wed, 17 Jul 1996 02:23:25 PDT +0500",
		"Wed, 17 Jul 1996 02:23:25 PDT\r\n +0500",
		"Wed, 17 Jul 1996 02:23:25 Z\t-0700",
		"Wed, 17 Jul 1996 02:23:25 PDT (c) +0500",
		// year = 4*DIGIT / obs-year, and obs-year is 2*DIGIT (RFC 5322 sections 3.3, 4.3).
		"Mon, 17 Jul 5 02:23:25 +0000",
		"Mon, 17 Jul 50 02:23:25 PDT+0400",
		// NUL is not comment text (ctext or obs-ctext), so removing a
		// malformed comment must not turn a previously invalid value into a date.
		"Wed, 17 Jul 1996 02:23:25 (bad\x00) -0700",
		"Wed, 17 Jul 1996 02:23:25 (outer (bad\x00)) PDT",
		// A comment that does not close, and a zone that is only in a comment.
		"Wed, 17 Jul 1996 02:23:25 -0700 (PDT",
		"Wed, 17 Jul 1996 02:23:25 PDT (Pacific",
		"Wed, 17 Jul 1996 02:23:25 (c -0700",
		"Wed, 17 Jul 1996 02:23:25 -0700 (c\\)",
		"Wed, 17 Jul 1996 02:23:25 (-0700)",
		"Wed, 17 Jul 1996 02:23:25 (PDT)",
	} {
		got, err := ParseDateHeader(value)
		assert.Error(t, err, "%q: parsed as %v", value, got)
	}
}

// An alphabetic prefix that is not a whole obs-zone must retain net/mail's
// behavior, including its accepted GMT extension and permissive suffix handling.
func TestParseDateHeaderPreservesParserExtensions(t *testing.T) {
	for _, value := range []string{
		"Wed, 17 Jul 1996 02:23:25 GMT+0000",
		"Wed, 17 Jul 1996 02:23:25 PDT/UTC",
	} {
		want, err := mail.ParseDate(value)
		require.NoError(t, err)
		got, err := ParseDateHeader(value)
		require.NoError(t, err)
		assert.True(t, got.Equal(want))
		_, wantOffset := want.Zone()
		_, gotOffset := got.Zone()
		assert.Equal(t, wantOffset, gotOffset)
	}
}

// TestNoIngressPathParsesDateWithNetMail: every path that stores a message parses its Date:
// header with ParseDateHeader, and builds its body structure with ExtractBodyStructure,
// which reads an attached message's Date: with it too. go-message's mail.Header.Date() is
// net/mail.ParseDate, which reads an alphabetic zone (PDT, EST, CET, ...) in the host's time
// zone, so the stored instant and offset would depend on the server's TZ; the go-imap
// extractors use it unless given a parser.
func TestNoIngressPathParsesDateWithNetMail(t *testing.T) {
	netMailDate := regexp.MustCompile(`[hH]eader\.Date\(\)|\bmail\.ParseDate\(|\bimapserver\.Extract(BodyStructure|Envelope)\(`)

	var offenders []string
	for _, dir := range []string{"server", "cmd", "db", "pkg"} {
		err := filepath.WalkDir(filepath.Join("..", dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(content), "\n") {
				if trimmed := strings.TrimSpace(line); !strings.HasPrefix(trimmed, "//") && netMailDate.MatchString(line) {
					offenders = append(offenders, filepath.ToSlash(path)+":"+strconv.Itoa(i+1)+": "+trimmed)
				}
			}
			return nil
		})
		require.NoError(t, err)
	}

	assert.Empty(t, offenders, "Date: header parsed with net/mail; use helpers.ParseDateHeader or helpers.ExtractBodyStructure:\n%s",
		strings.Join(offenders, "\n"))
}
