package helpers

import (
	"strings"
	"unicode/utf8"

	"github.com/emersion/go-imap/v2"
)

func SanitizeUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	buf := make([]rune, 0, len(s))
	for i, r := range s {
		if r == utf8.RuneError {
			_, size := utf8.DecodeRuneInString(s[i:])
			if size == 1 {
				continue // skip invalid byte
			}
		}
		buf = append(buf, r)
	}
	return string(buf)
}

// SanitizeFlags removes invalid flag values that could cause IMAP protocol errors.
// This prevents issues like NIL appearing as a flag, which triggers errors:
// "Keyword used without being in FLAGS: NIL"
//
// Filters out:
// - Flags containing "NIL" (case-insensitive) - e.g., "$NIL", "nil", "NIL"
// - Flags containing "NULL" (case-insensitive) - e.g., "$NULL", "null"
// - Empty string flags
// - Flags with only whitespace
//
// Returns a new slice with only valid flags.
func SanitizeFlags(flags []imap.Flag) []imap.Flag {
	if len(flags) == 0 {
		return flags
	}

	sanitized := make([]imap.Flag, 0, len(flags))
	for _, flag := range flags {
		flagStr := string(flag)
		flagUpper := strings.ToUpper(flagStr)

		// Skip empty or whitespace-only flags
		if strings.TrimSpace(flagStr) == "" {
			continue
		}

		// Skip flags containing NIL (case-insensitive)
		// This catches: NIL, $NIL, nil, $nil, etc.
		if strings.Contains(flagUpper, "NIL") {
			continue
		}

		// Skip flags containing NULL (case-insensitive)
		if strings.Contains(flagUpper, "NULL") {
			continue
		}

		// Flag is valid, keep it
		sanitized = append(sanitized, flag)
	}

	return sanitized
}
