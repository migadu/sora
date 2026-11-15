package helpers

import (
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

// alphabeticZone matches a date-time (RFC 5322 §3.3) up to the end of its time-of-day
// (the field's first colon is the one after the hour) and the run of letters that follows
// it after any folding white space: the zone.
var alphabeticZone = regexp.MustCompile(`^[^:]*\d:\d{2}(?::\d{2})?([ \t]*)([A-Za-z]+)`)

// obsYear matches a date-time (RFC 5322 §3.3) up to a year of two or three digits
// (obs-year, §4.3): the digits right before the hour, which the field's first colon
// follows.
var obsYear = regexp.MustCompile(`^[^:]*[ \t](\d{2,3})[ \t]+\d{1,2}:`)

// ParseDateHeader parses the value of a Date: header field (RFC 5322 §3.3), like
// net/mail.ParseDate but reading an alphabetic zone by RFC 5322 §4.3 instead of by the
// host's time zone, a two- or three-digit year by §4.3 too, and comments and white
// space between the tokens.
//
// net/mail.ParseDate gives an alphabetic zone the offset it has in time.Local, and
// offset zero when time.Local does not know it: PDT is 02:23:25 UTC on a server in UTC,
// and EST in July is given in EDT on one in America/New_York. Here the zone is replaced
// by its numeric equivalent before parsing: the ten names of §4.3 by their offsets, and
// the military zones and any other name by "-0000", which §4.3 says they "SHOULD all be
// considered equivalent to" without out-of-band information.
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
func ParseDateHeader(value string) (time.Time, error) {
	// Unfold exactly as net/mail does, without turning an unpaired CR or LF
	// before the zone into valid white space during the replacement below.
	unfolded := strings.ReplaceAll(value, "\r\n", "")
	if strings.ContainsAny(unfolded, "\r\n") {
		return mail.ParseDate(value)
	}
	unfolded = normalizeCFWS(unfolded)
	if m := obsYear.FindStringSubmatchIndex(unfolded); m != nil {
		year, _ := strconv.Atoi(unfolded[m[2]:m[3]])
		if m[3]-m[2] == 2 && year < 50 {
			year += 2000
		} else {
			year += 1900
		}
		unfolded = unfolded[:m[2]] + strconv.Itoa(year) + unfolded[m[3]:]
	}
	if m := alphabeticZone.FindStringSubmatchIndex(unfolded); m != nil {
		end := m[5]
		// Replace a whole zone token only. For example, PDT+0400 is not PDT:
		// net/mail would discard the suffix after a numeric replacement. Keep
		// its existing behavior for extensions it accepts, such as GMT+0000
		// (unfolded is the value net/mail would see, with the separators and
		// the year rewritten).
		if end < len(unfolded) && unfolded[end] != ' ' && unfolded[end] != '\t' && unfolded[end] != '(' {
			return mail.ParseDate(unfolded)
		}
		// Nor are the letters the zone when a numeric offset follows them after
		// white space or a comment, as in "02:23:25 PM -0700": the grammar has one
		// zone after the time of day ("time = time-of-day zone"), and net/mail
		// would discard the offset after the replacement.
		if rest := strings.TrimLeft(unfolded[end:], " \t"); rest != "" && (rest[0] == '+' || rest[0] == '-') {
			return mail.ParseDate(unfolded)
		}
		zone, ok := obsZones[strings.ToUpper(unfolded[m[4]:end])]
		if !ok {
			zone = "-0000"
		}
		// An obs-zone needs no white space before it, a numeric zone does.
		unfolded = unfolded[:m[2]] + " " + zone + unfolded[end:]
	}
	return mail.ParseDate(unfolded)
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
