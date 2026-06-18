package helpers

import (
	"strings"
	"unicode/utf8"

	"github.com/emersion/go-imap/v2"
)

// SanitizeUTF8 removes invalid UTF-8 sequences and NULL bytes from a string.
// PostgreSQL's text type does not allow NULL bytes (0x00) even though they are valid UTF-8.
// This function ensures the string is safe to store in any PostgreSQL text column.
func SanitizeUTF8(s string) string {
	// Quick check: if string is valid UTF-8 and has no NULL bytes, return as-is
	if utf8.ValidString(s) && !strings.ContainsRune(s, '\x00') {
		return s
	}

	buf := make([]rune, 0, len(s))
	for i, r := range s {
		// Skip NULL bytes (0x00) - PostgreSQL text columns don't allow them
		if r == '\x00' {
			continue
		}

		// Skip invalid UTF-8 sequences
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

// SanitizeUTF8ForFTS removes invalid UTF-8 sequences, NULL bytes, and backslashes from a string.
// This is specifically for text that will be passed to PostgreSQL's to_tsvector() function,
// where backslash patterns like \uXXXX can cause "unsupported Unicode escape sequence"
// errors (SQLSTATE 22P05). Regular text columns using parameterized queries are safe from
// this issue and should use SanitizeUTF8 instead to preserve backslashes in stored content.
func SanitizeUTF8ForFTS(s string) string {
	// Quick check: if string is valid UTF-8 and has no problematic characters, return as-is
	if utf8.ValidString(s) && !strings.ContainsRune(s, '\x00') && !strings.ContainsRune(s, '\\') {
		return s
	}

	buf := make([]rune, 0, len(s))
	for i, r := range s {
		// Skip NULL bytes (0x00) - PostgreSQL text columns don't allow them
		if r == '\x00' {
			continue
		}

		// Replace backslashes with spaces to prevent PostgreSQL escape sequence errors
		// in to_tsvector() which can interpret \uXXXX as Unicode escapes
		if r == '\\' {
			buf = append(buf, ' ')
			continue
		}

		// Skip invalid UTF-8 sequences
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

// StringsToFlags converts a slice of flag/keyword names (e.g. the flags resolved by
// a Sieve script's imap4flags actions) into IMAP flags. It does not validate or
// deduplicate; pair it with SanitizeFlags to drop invalid values.
func StringsToFlags(names []string) []imap.Flag {
	if len(names) == 0 {
		return nil
	}
	flags := make([]imap.Flag, 0, len(names))
	for _, n := range names {
		flags = append(flags, imap.Flag(n))
	}
	return flags
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

// RemoveLongTokens drops any continuous sequence of non-whitespace characters longer than maxTokenLen.
// This prevents PostgreSQL to_tsvector from taking excessive time on pathological blocks
// (e.g. continuous base64, hex dumps, gpg blocks) while keeping the rest of the text searchable,
// and prevents polluting the FTS index with broken chunks.
func RemoveLongTokens(s string, maxTokenLen int) string {
	if len(s) == 0 {
		return s
	}

	var buf strings.Builder
	buf.Grow(len(s))

	var currentWord []rune
	for _, r := range s {
		// We use standard whitespace as token boundaries.
		// PostgreSQL splits on other punctuation too, but removing long blobs between whitespace
		// is the safest way to target raw payloads without needing a complex lexer.
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '<' || r == '>' {
			if len(currentWord) <= maxTokenLen {
				for _, wr := range currentWord {
					buf.WriteRune(wr)
				}
			}
			currentWord = currentWord[:0]
			buf.WriteRune(r)
		} else {
			currentWord = append(currentWord, r)
		}
	}

	// Handle the final word
	if len(currentWord) <= maxTokenLen {
		for _, wr := range currentWord {
			buf.WriteRune(wr)
		}
	}

	return buf.String()
}

// TruncateUTF8Safe safely truncates a UTF-8 string to a maximum byte length without cutting a multibyte rune in half.
func TruncateUTF8Safe(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}

	// Find the nearest valid rune boundary by scanning backwards
	truncLen := maxBytes
	for truncLen > 0 && !utf8.RuneStart(s[truncLen]) {
		truncLen--
	}
	return s[:truncLen]
}
