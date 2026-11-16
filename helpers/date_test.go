package helpers

import (
	"io/fs"
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

// TestParseDateHeaderLeapSecond is issue #1384: a time-of-day whose second is 60, a leap
// second, is a date-time. RFC 5322 section 3.3: "the time-of-day MUST be in the range
// 00:00:00 through 23:59:60 (the number of seconds allowing for a leap second ...)".
// net/mail.ParseDate does not parse it, so the message was stored with an unknown sent
// date. time.Time cannot hold second 60: it is read as second 59 of the same minute, as
// Dovecot's message_date_parse does.
func TestParseDateHeaderLeapSecond(t *testing.T) {
	const h = 3600
	leap := time.Date(2016, 12, 31, 23, 59, 59, 0, time.UTC) // 2016-12-31T23:59:60Z, as second 59
	cases := []struct {
		value  string
		want   time.Time
		offset int // seconds east of UTC
	}{
		{"Sat, 31 Dec 2016 23:59:60 +0000", leap, 0},
		{"Sun, 1 Jan 2017 00:59:60 +0100", leap, h},
		{"Sat, 31 Dec 2016 15:59:60 -0800", leap, -8 * h},
		{"Sat, 31 Dec 2016 23:59:60 GMT", leap, 0},
		{"Sat, 31 Dec 2016 15:59:60 PST", leap, -8 * h},
		{"Sat, 31 Dec 2016 23:59:60 GMT+0000", leap, 0},
		{"31 Dec 2016 23:59:60 +0000", leap, 0},
		{"Sat, 31 Dec 16 23:59:60 +0000", leap, 0},
		{"Sat, 31 Dec 116 23:59:60 UT", leap, 0},
		{"Sat, 31 Dec 2016 23:59:60\r\n +0000", leap, 0},
		// Comments and white space around the seconds (obs-second = [CFWS] 2DIGIT [CFWS]).
		{"Sat, 31 Dec 2016 23 : 59 : 60 +0000", leap, 0},
		{"Sat, 31 Dec 2016 23:59:(s)60 (leap second) +0000", leap, 0},
		{"Tue, 30 Jun 2015 23:59:60 +0000", time.Date(2015, 6, 30, 23, 59, 59, 0, time.UTC), 0},
	}
	for _, tc := range cases {
		got, err := ParseDateHeader(tc.value)
		if !assert.NoError(t, err, "%q", tc.value) {
			continue
		}
		_, offset := got.Zone()
		assert.True(t, got.Equal(tc.want), "%q: %v, want %v", tc.value, got, tc.want.In(time.FixedZone("", tc.offset)))
		assert.Equal(t, tc.offset, offset, "%q: zone offset of %v", tc.value, got)
	}

	// Only a second of 60 is a leap second.
	for _, value := range []string{
		"Sat, 31 Dec 2016 23:59:61 +0000",
		"Sat, 31 Dec 2016 23:59:600 +0000",
		"Sat, 31 Dec 2016 23:60:00 +0000",
		"Sat, 31 Dec 2016 24:00:00 +0000",
	} {
		got, err := ParseDateHeader(value)
		assert.Error(t, err, "%q: parsed as %v", value, got)
	}
}

// TestParseDateHeaderInvalid: a value net/mail does not parse is still an error.
func TestParseDateHeaderInvalid(t *testing.T) {
	for _, value := range []string{
		"", "PDT", "Wed, 17 Jul 1996 PDT", "not a date 12:00 PDT",
		"Wed, 17 Jul 1996 02:23:25\r PDT",
		"Wed, 17 Jul 1996 02:23:25\n PDT",
		// Nor are letters a zone when a numeric offset follows them after white space
		// or a comment: the RFC 5322 section 3.3 grammar has one zone after the time of
		// day ("time = time-of-day zone"), the letters can change the time itself (PM),
		// and the offset after the letters would be discarded. The same holds for any
		// zone that is not one of RFC 5322 (TestParseDateHeaderUnknownZone).
		"Wed, 17 Jul 1996 02:23:25 PM -0700",
		"Wed, 17 Jul 1996 02:23:25 PDT +0500",
		"Wed, 17 Jul 1996 02:23:25 PDT\r\n +0500",
		"Wed, 17 Jul 1996 02:23:25 Z\t-0700",
		"Wed, 17 Jul 1996 02:23:25 PDT (c) +0500",
		"Wed, 17 Jul 1996 02:23:25 GMT+1 -0700",
		"Wed, 17 Jul 1996 02:23:25 CET/CEST +0100",
		"Wed, 17 Jul 1996 02:23:25 PDT+0400 (c) -0700",
		"Wed, 17 Jul 1996 02:23:25 +01 +0100",
		// year = 4*DIGIT / obs-year, and obs-year is 2*DIGIT (RFC 5322 sections 3.3, 4.3).
		"Mon, 17 Jul 5 02:23:25 +0000",
		"Mon, 17 Jul 5 02:23:25 GMT+1",
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

// TestParseDateHeaderUnknownZone: a Date: whose zone is malformed or not defined keeps the
// date and time of day as written and reports the zone as explicitly unknown, with the
// instant in UTC. go-imap writes that metadata as "-0000" in ENVELOPE. RFC 5256 section 2.2: "If the time
// zone is invalid, the date and time SHOULD be treated as UTC." RFC 5322 section 4.3: the
// military zones and "Other multi-character (usually between 3 and 5) alphabetic time
// zones" whose meaning is not known "SHOULD be considered equivalent to "-0000"", which
// section 3.3 says "also indicates Universal Time" for a date-time that "contains no
// information about the local time zone". The zone of RFC 5322 is zone = (FWS ( "+" / "-" )
// 4DIGIT) / obs-zone (section 3.3); none of these is one.
//
// Before, GMT with a signed hour (GMT+1, GMT-5) and an alphabetic run with more after it
// (GMT+0200, UTC-0500, PDT+0400, PDT0) were not parsed, so the sent date was unknown, and
// net/mail read a sign with two or three digits (+01, -03) and a name it cut after its T
// (CET/CEST, PDT/UTC) in the server's time zone: +01 was 12:00 UTC on a server in UTC and
// 11:00 UTC on one in Africa/Casablanca, whose tzdata abbreviation is "+01".
func TestParseDateHeaderUnknownZone(t *testing.T) {
	cases := []struct {
		value string
		wall  time.Time // the date and time as written
	}{
		// GMT or UTC with a signed hour: +0100 as an offset, UTC-1 as a POSIX TZ.
		{"Tue, 01 Jan 2019 12:00:00 GMT+1", time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC)},
		{"Tue, 01 Jan 2019 12:00:00 GMT+01", time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC)},
		{"Tue, 01 Jan 2019 12:00:00 GMT-5", time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC)},
		{"Tue, 01 Jan 2019 12:00:00 GMT+23", time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC)},
		{"Tue, 01 Jan 2019 12:00:00 GMT+0001", time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC)},
		{"Tue, 01 Jan 2019 12:00:00 GMT+10 (CET)", time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC)},
		{"Tue, 01 Jan 19 12:00 GMT-1", time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC)},
		{"Tue, 01 Jan 2019 12:00:00 GMT+0200", time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC)},
		{"Tue, 01 Jan 2019 12:00:00 GMT+0", time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC)},
		{"Tue, 01 Jan 2019 12:00:00 GMT-0000", time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC)},
		{"Wed, 17 Jul 1996 02:23:25 GMT+0000", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC)},
		{"Wed, 17 Jul 1996 02:23:25 UTC-0500", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC)},
		// An obs-zone with more after it.
		{"Wed, 17 Jul 1996 02:23:25 PDT+0400", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC)},
		{"Wed, 17 Jul 1996 02:23:25 PDT-0700", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC)},
		{"Wed, 17 Jul 1996 02:23:25 PDT0", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC)},
		{"Wed, 17 Jul 1996 02:23:25 PDT/UTC", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC)},
		{"Mon, 17 Jul 50 02:23:25 PDT+0400", time.Date(1950, 7, 17, 2, 23, 25, 0, time.UTC)},
		// A name cut short, or run into another.
		{"Wed, 17 Jan 1996 02:23:25 CET/CEST", time.Date(1996, 1, 17, 2, 23, 25, 0, time.UTC)},
		{"Wed, 17 Jul 1996 02:23:25 CES", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC)},
		// A sign without four digits.
		{"Tue, 01 Jul 2019 12:00:00 +01", time.Date(2019, 7, 1, 12, 0, 0, 0, time.UTC)},
		{"Tue, 01 Jul 2019 12:00:00 -03", time.Date(2019, 7, 1, 12, 0, 0, 0, time.UTC)},
		{"Tue, 01 Jul 2019 12:00:00 +04 (Gulf)", time.Date(2019, 7, 1, 12, 0, 0, 0, time.UTC)},
		{"Tue, 01 Jul 2019 12:00:00 +001", time.Date(2019, 7, 1, 12, 0, 0, 0, time.UTC)},
		{"Tue, 01 Jul 2019 12:00:00 +1", time.Date(2019, 7, 1, 12, 0, 0, 0, time.UTC)},
		{"Tue, 01 Jul 2019 12:00:00 +01:00", time.Date(2019, 7, 1, 12, 0, 0, 0, time.UTC)},
		// Military and unknown alphabetic zones (RFC 5322 section 4.3).
		{"Wed, 17 Jul 1996 02:23:25 Z", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC)},
		{"Wed, 17 Jul 1996 02:23:25 a", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC)},
		{"Wed, 17 Jan 1996 02:23:25 CET", time.Date(1996, 1, 17, 2, 23, 25, 0, time.UTC)},
		{"Wed, 17 Jul 1996 02:23:25 MSK", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC)},
		{"Wed, 17 Jul 1996 02:23:25 UTC", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC)},
		// "-0000" itself (RFC 5322 section 3.3).
		{"Wed, 17 Jul 1996 02:23:25 -0000", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC)},
		{"Wed, 17 Jul 1996 02:23:25 -0000 (unknown)", time.Date(1996, 7, 17, 2, 23, 25, 0, time.UTC)},
	}

	saved := time.Local
	t.Cleanup(func() { time.Local = saved })
	for _, name := range []string{"UTC", "Africa/Casablanca", "America/Sao_Paulo", "Asia/Dubai", "Europe/Berlin", "America/Los_Angeles"} {
		loc, err := time.LoadLocation(name)
		require.NoError(t, err)
		time.Local = loc // no test in this package runs in parallel
		for _, tc := range cases {
			got, unknown, err := ParseDateHeaderWithZone(tc.value)
			if !assert.NoError(t, err, "TZ=%s %q", name, tc.value) {
				continue
			}
			assert.True(t, got.Equal(tc.wall), "TZ=%s %q: %v, want %v", name, tc.value, got, tc.wall)
			assert.True(t, unknown, "TZ=%s %q: unknown source zone was not reported", name, tc.value)
		}
	}
}

// Known zero-offset zones remain explicitly known even when net/mail returns
// time.UTC. Their metadata must not depend on the application's time.Local.
func TestParseDateHeaderKnownZoneMetadata(t *testing.T) {
	const h = 3600
	cases := []struct {
		value  string
		offset int // seconds east of UTC; the wall time is always 1996-07-17 02:23:25
	}{
		{"Wed, 17 Jul 1996 02:23:25 +0000", 0},
		{"Wed, 17 Jul 1996 02:23:25 +0000 (UTC)", 0},
		{"Wed, 17 Jul 1996 02:23:25 UT", 0},
		{"Wed, 17 Jul 1996 02:23:25 GMT", 0},
		{"Wed, 17 Jul 1996 02:23:25 gmt", 0},
		{"Wed, 17 Jul 1996 02:23:25 -0700", -7 * h},
		{"Wed, 17 Jul 1996 02:23:25 PDT", -7 * h},
		{"Wed, 17 Jul 1996 02:23:25 +0530", 5*h + 30*60},
	}

	saved := time.Local
	t.Cleanup(func() { time.Local = saved })
	for _, loc := range []*time.Location{time.UTC, time.FixedZone("", 0), time.FixedZone("", -7*h)} {
		time.Local = loc // no test in this package runs in parallel
		for _, tc := range cases {
			got, unknown, err := ParseDateHeaderWithZone(tc.value)
			if !assert.NoError(t, err, "Local=%v %q", loc, tc.value) {
				continue
			}
			want := time.Date(1996, 7, 17, 2, 23, 25, 0, time.FixedZone("", tc.offset))
			_, offset := got.Zone()
			assert.True(t, got.Equal(want), "Local=%v %q: %v, want %v", loc, tc.value, got, want)
			assert.Equal(t, tc.offset, offset, "Local=%v %q: zone offset of %v", loc, tc.value, got)
			assert.False(t, unknown, "Local=%v %q: known source zone was reported unknown", loc, tc.value)
		}
	}
}

func TestParseDateHeaderWithZoneCompatibility(t *testing.T) {
	for _, tc := range []struct {
		value   string
		unknown bool
		invalid bool
	}{
		{value: "Tue, 01 Jan 2019 12:00:00 +0000"},
		{value: "Tue, 01 Jan 2019 12:00:00 +0000 (unknown -0000 GMT+1)"},
		{value: "Tue, 01 Jan 2019 12:00:00 GMT (unknown -0000)"},
		{value: "Tue, 01 Jan 2019 12:00:00 -0000 (known +0000)", unknown: true},
		{value: "Tue, 01 Jan 2019 12:00:00 GMT+1", unknown: true},
		{value: "Tue, 01 Jan 2019 12:00:00 UTC", unknown: true},
		{value: "Tue, 01 Jan 2019 12:00:00 EſT", unknown: true},
		{value: "Tue, 01 Jan 2019 12:00:00 -0700"},
		{value: "1 Jan 19 12:00 GMT+1", unknown: true},
		{value: "Tue (day), 01 Jan 2019 12 (hour):00:60 (time) GMT+1", unknown: true},
		{value: "", invalid: true},
		{value: "not a date -0000", invalid: true},
		{value: "Tue, 32 Jan 2019 12:00:00 GMT+1", invalid: true},
		{value: "Tue, 01 Jan 2019 12:00:00 PM -0700", invalid: true},
		{value: "Tue, 01 Jan 2019 12:00:00\n -0000", invalid: true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			date, unknown, err := ParseDateHeaderWithZone(tc.value)
			legacy, legacyErr := ParseDateHeader(tc.value)
			if tc.invalid {
				require.Error(t, err)
				require.Error(t, legacyErr)
				assert.False(t, unknown, "a rejected date must not retain unknown-zone metadata")
				return
			}
			require.NoError(t, err)
			require.NoError(t, legacyErr)
			assert.Equal(t, tc.unknown, unknown, "source-zone metadata")
			assert.True(t, date.Equal(legacy), "compatibility wrapper changed the instant: %v versus %v", date, legacy)
			_, offset := date.Zone()
			_, legacyOffset := legacy.Zone()
			assert.Equal(t, legacyOffset, offset, "compatibility wrapper changed the offset")
		})
	}
}

// TestNoIngressPathParsesDateWithNetMail: every path that stores a message parses its Date:
// header with ParseDateHeaderWithZone, and builds its body structure with ExtractBodyStructure,
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

	assert.Empty(t, offenders, "Date: header parsed with net/mail; use helpers.ParseDateHeaderWithZone or helpers.ExtractBodyStructure:\n%s",
		strings.Join(offenders, "\n"))
}
