package helpers

import (
	"errors"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// obsZones maps the obsolete alphabetic zones RFC 5322 §4.3 gives a meaning to the
// numeric zone each one is "semantically equivalent to". ABNF strings are case
// insensitive (RFC 5234 §2.3), so the keys are upper case and lookups fold case.
var obsZones = map[string]string{
	"UT": "+0000", "GMT": "+0000",
	"EDT": "-0400", "EST": "-0500",
	"CDT": "-0500", "CST": "-0600",
	"MDT": "-0600", "MST": "-0700",
	"PDT": "-0700", "PST": "-0800",
}

// zoneToken matches a date-time (RFC 5322 §3.3) up to the end of its time-of-day (the
// field's first colon is the one after the hour), the white space after it, and the zone:
// the token there, up to white space or a comment, when it begins with a letter or a sign.
var zoneToken = regexp.MustCompile(`^[^:]*\d:\d{2}(?::\d{2})?([ \t]*)([A-Za-z+-][^ \t(]*)`)

// numericZone matches a zone of a sign and four digits (RFC 5322 §3.3), which net/mail
// reads, as it does the digits of one with more after them.
var numericZone = regexp.MustCompile(`^[+-]\d{4}`)

// universalTime is Universal Time, offset zero, as a location of its own: time.UTC marks
// a zone that is unknown (ZoneUnknown).
var universalTime = time.FixedZone("UTC", 0)

// obsYear matches a date-time (RFC 5322 §3.3) up to a year of two or three digits
// (obs-year, §4.3): the digits right before the hour, which the field's first colon
// follows.
var obsYear = regexp.MustCompile(`^[^:]*[ \t](\d{2,3})[ \t]+\d{1,2}:`)

// leapSecond matches a date-time (RFC 5322 §3.3) up to the seconds of its time-of-day
// (the field's first colon is the one after the hour) when they are 60: a leap second.
var leapSecond = regexp.MustCompile(`^[^:]*\d:\d{2}:(60)(?:\D|$)`)

// ParseDateHeader parses the value of a Date: header field (RFC 5322 §3.3), like
// net/mail.ParseDate but reading the zone by RFC 5322 instead of by the host's time zone,
// a two- or three-digit year by §4.3 too, and comments and white space between the
// tokens.
//
// The date of a zone that is unknown is given in UTC (time.UTC; see ZoneUnknown), every
// other date in a location of its own offset. The zone is the token after the time of
// day:
//
//   - A sign and four digits is read by net/mail; "-0000" is the unknown zone (§3.3:
//     "the date-time contains no information about the local time zone").
//   - One of the ten names of §4.3 (UT, GMT, EST, ..., PDT, in any case) is its offset.
//     net/mail gives a name the offset it has in time.Local, and offset zero when
//     time.Local does not know it: PDT is 02:23:25 UTC on a server in UTC, and EST in
//     July is given in EDT on one in America/New_York.
//   - Any other token is unknown: the military zones and other names, which §4.3 says
//     "SHOULD all be considered equivalent to "-0000"" without out-of-band information,
//     and every zone that is not RFC 5322's at all (zone = (FWS ( "+" / "-" ) 4DIGIT) /
//     obs-zone): GMT+1, GMT+0200, UTC-0500, PDT+0400, a sign with fewer than four digits
//     (+01), a name run into another (CET/CEST). RFC 5256 §2.2: "If the time zone is
//     invalid, the date and time SHOULD be treated as UTC." The date and time of day
//     are kept as written: net/mail read +01 and CET/CEST in time.Local, and GMT+1 as
//     the time of day in UTC labelled with +0100, neither reading of GMT+1.
//   - Unless a token with a sign follows it after white space or a comment, as in
//     "02:23:25 PM -0700": the grammar has one zone after the time of day ("time =
//     time-of-day zone"), and the letters before the offset can change the time itself.
//     Such a field is not parsed.
//
// net/mail.ParseDate reads a two-digit year with time.Parse's "06", which puts 00-68 in
// 20xx, and does not parse a three-digit year (tm_year written as is after 1999). §4.3
// adds 2000 to a two-digit year from 00 to 49, and 1900 to one from 50 to 99 "or any
// three digit year", so the year is written out in four digits before parsing.
//
// net/mail.ParseDate also takes a comment only after the zone, and white space only
// where its layouts have a space. §4.3 permits comments and folding white space between
// the tokens (obs-day-of-week, obs-day, obs-year, obs-hour, obs-minute and obs-second
// are each "[CFWS] ... [CFWS]"), so they are first reduced to the separators net/mail's
// layouts have.
//
// A time-of-day whose second is 60, a leap second (§3.3: "the time-of-day MUST be in the
// range 00:00:00 through 23:59:60"), is read as second 59 of the same minute, as Dovecot
// reads it: time.Time cannot hold second 60, and net/mail.ParseDate does not parse it.
func ParseDateHeader(value string) (time.Time, error) {
	// Unfold exactly as net/mail does, without turning an unpaired CR or LF
	// before the zone into valid white space during the replacement below.
	unfolded := strings.ReplaceAll(value, "\r\n", "")
	if strings.ContainsAny(unfolded, "\r\n") {
		return knownZone(mail.ParseDate(value))
	}
	unfolded = normalizeCFWS(unfolded)
	if m := leapSecond.FindStringSubmatchIndex(unfolded); m != nil {
		unfolded = unfolded[:m[2]] + "59" + unfolded[m[3]:]
	}
	if m := obsYear.FindStringSubmatchIndex(unfolded); m != nil {
		year, _ := strconv.Atoi(unfolded[m[2]:m[3]])
		if m[3]-m[2] == 2 && year < 50 {
			year += 2000
		} else {
			year += 1900
		}
		unfolded = unfolded[:m[2]] + strconv.Itoa(year) + unfolded[m[3]:]
	}
	unknown := false
	if m := zoneToken.FindStringSubmatchIndex(unfolded); m != nil {
		token, end := unfolded[m[4]:m[5]], m[5]
		if numericZone.MatchString(token) {
			unknown = strings.HasPrefix(token, "-0000")
		} else {
			if rest := strings.TrimLeft(unfolded[end:], " \t"); rest != "" && (rest[0] == '+' || rest[0] == '-') {
				return time.Time{}, errors.New("mail: a numeric offset after the Date: zone")
			}
			zone, ok := obsZones[strings.ToUpper(token)]
			if !ok {
				zone, unknown = "-0000", true
			}
			// An obs-zone needs no white space before it, a numeric zone does.
			unfolded = unfolded[:m[2]] + " " + zone + unfolded[end:]
		}
	}
	t, err := mail.ParseDate(unfolded)
	if err != nil || !unknown {
		return knownZone(t, err)
	}
	return t.UTC(), nil
}

// ZoneUnknown reports whether a date ParseDateHeader returned has no known zone, RFC 5322
// §3.3 "-0000": it is in UTC (time.UTC). go-imap writes an ENVELOPE date in UTC with the
// zone "-0000", and the binary (gob) encoding of a time.Time keeps time.UTC apart from a
// zone of offset zero, so a stored body structure keeps it too.
func ZoneUnknown(t time.Time) bool {
	return t.Location() == time.UTC
}

// knownZone returns what net/mail parsed for a known zone, never in time.UTC, which marks
// an unknown one (ZoneUnknown): net/mail gives offset zero in time.UTC when time.Local is
// time.UTC, and the names UT and UTC always.
func knownZone(t time.Time, err error) (time.Time, error) {
	if err == nil && t.Location() == time.UTC {
		t = t.In(universalTime)
	}
	return t, err
}

// normalizeCFWS returns an unfolded date-time with every comment (RFC 5322 §3.2.2) and
// run of white space between two tokens written as one space, as net/mail's layouts
// separate tokens, except that there is none before the comma after the day name or
// around a colon between the digits of the time of day, and always one after that comma:
// day = ([FWS] 1*2DIGIT FWS) makes it optional (§3.3). A date-time has no quoted
// strings, so every "(" opens a comment; the rest of the value from one that does not
// close is left as written, for net/mail to reject.
func normalizeCFWS(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	var prev byte   // the last byte written
	sep := false    // white space or a comment since prev
	digits := false // a digit was written: the day-of-week is behind
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' {
			sep = true
			continue
		}
		if c == '(' {
			if n := commentLen(s[i:]); n > 0 {
				i += n - 1
				sep = true
				continue
			}
		}
		dayComma := c == ',' && !digits
		timeColon := c == ':' && isDigit(prev) || prev == ':' && isDigit(c)
		if sep && prev != 0 && !dayComma && !timeColon {
			b.WriteByte(' ')
		}
		if c == '(' {
			b.WriteString(s[i:])
			break
		}
		b.WriteByte(c)
		prev, sep, digits = c, dayComma, digits || isDigit(c)
	}
	return b.String()
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

// commentLen returns the length of the comment s starts with, nested comments and
// quoted-pairs included (RFC 5322 §3.2.2), or 0 if it is malformed or
// does not close. An unquoted NUL is not ctext, including obsolete ctext;
// a quoted NUL remains allowed by obs-qp (§4.1).
func commentLen(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 0:
			return 0
		case '\\':
			i++
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return i + 1
			}
		}
	}
	return 0
}
