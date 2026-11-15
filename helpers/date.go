package helpers

import (
	"net/mail"
	"regexp"
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

// ParseDateHeader parses the value of a Date: header field (RFC 5322 §3.3), like
// net/mail.ParseDate but reading an alphabetic zone by RFC 5322 §4.3 instead of by the
// host's time zone.
//
// net/mail.ParseDate gives an alphabetic zone the offset it has in time.Local, and
// offset zero when time.Local does not know it: PDT is 02:23:25 UTC on a server in UTC,
// and EST in July is given in EDT on one in America/New_York. Here the zone is replaced
// by its numeric equivalent before parsing: the ten names of §4.3 by their offsets, and
// the military zones and any other name by "-0000", which §4.3 says they "SHOULD all be
// considered equivalent to" without out-of-band information.
func ParseDateHeader(value string) (time.Time, error) {
	// Unfold exactly as net/mail does, without turning an unpaired CR or LF
	// before the zone into valid white space during the replacement below.
	unfolded := strings.ReplaceAll(value, "\r\n", "")
	if strings.ContainsAny(unfolded, "\r\n") {
		return mail.ParseDate(value)
	}
	if m := alphabeticZone.FindStringSubmatchIndex(unfolded); m != nil {
		end := m[5]
		// Replace a whole zone token only. For example, PDT+0400 is not PDT:
		// net/mail would discard the suffix after a numeric replacement. Keep
		// its existing behavior for extensions it accepts, such as GMT+0000.
		if end < len(unfolded) && unfolded[end] != ' ' && unfolded[end] != '\t' && unfolded[end] != '(' {
			return mail.ParseDate(value)
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
