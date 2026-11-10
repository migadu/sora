package helpers

import (
	"strings"

	"github.com/migadu/go-imap"
)

// FlagColorKeywords are the RFC 9979 §3.1 keywords whose bit pattern gives a
// \Flagged message its color. They mean nothing without \Flagged, which they
// "MUST be ignored" without.
var FlagColorKeywords = []imap.Flag{"$MailFlagBit0", "$MailFlagBit1", "$MailFlagBit2"}

// IsFlagColorKeyword reports whether flag is one of FlagColorKeywords, in any
// case (keywords are case-insensitive).
func IsFlagColorKeyword(flag imap.Flag) bool {
	for _, k := range FlagColorKeywords {
		if strings.EqualFold(string(flag), string(k)) {
			return true
		}
	}
	return false
}

// HasFlag reports whether flags contains want, in any case.
func HasFlag(flags []imap.Flag, want imap.Flag) bool {
	for _, f := range flags {
		if strings.EqualFold(string(f), string(want)) {
			return true
		}
	}
	return false
}
