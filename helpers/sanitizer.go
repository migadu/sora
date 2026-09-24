package helpers

import (
	"slices"
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

// IsValidFlagName reports whether f is a syntactically valid IMAP flag, i.e.
// matches flag / flag-keyword / flag-extension from RFC 9051 §9 (Formal Syntax):
//
//	flag           = "\\Answered" / ... / flag-keyword / flag-extension
//	flag-extension = "\\" atom
//	flag-keyword   = "$MDNSent" / ... / atom
//	atom           = 1*ATOM-CHAR
//	ATOM-CHAR      = <any CHAR except atom-specials>
//	atom-specials  = "(" / ")" / "{" / SP / CTL / list-wildcards
//	                 / quoted-specials / resp-specials
//
// CHAR is %x01-7F (RFC 5234), so a flag is ASCII by construction: a keyword
// holding non-ASCII bytes cannot be encoded as an atom and therefore cannot be
// put on the wire at all. "\\*" (flag-perm) is accepted because SELECT
// advertises it in PERMANENTFLAGS.
//
// This is the server's half of an invariant the wire encoder enforces on the way
// out: go-imap's Encoder.Flag rejects an invalid flag and, because encoder errors
// are sticky, abandons the response mid-list -- leaving the untagged line
// unterminated and unflushed, so the client waits forever for a tagged reply.
// A single such keyword reaching a mailbox's keyword registry therefore makes
// SELECT/EXAMINE of that mailbox hang for every client, permanently. Rejecting
// the value here, at the point it enters the system, is what keeps that
// unreachable.
func IsValidFlagName(f imap.Flag) bool {
	s := string(f)
	if s == "" {
		return false
	}
	if s == "\\*" {
		return true
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\\' {
			// A backslash is legal only as the flag-extension prefix.
			if i != 0 {
				return false
			}
			continue
		}
		if !isAtomChar(ch) {
			return false
		}
	}
	// A lone "\" is not a flag: flag-extension requires an atom after it.
	return s != "\\"
}

// isAtomChar reports whether ch is an ATOM-CHAR (RFC 9051 §9). Note the
// range is ASCII-only; every byte with the high bit set is rejected, which is
// what keeps non-ASCII keywords out.
func isAtomChar(ch byte) bool {
	if ch < 0x21 || ch > 0x7E { // CTL, SP and anything non-ASCII
		return false
	}
	switch ch {
	case '(', ')', '{', '%', '*', '"', '\\', ']':
		return false
	}
	return true
}

// SanitizeFlags removes flag values that would break the IMAP protocol if they
// were stored or advertised.
//
// Filters out:
//   - The IMAP NIL / NULL atoms (whole-token match), which are parser artifacts
//   - Empty or whitespace-only flags
//   - Anything that is not a syntactically valid flag (IsValidFlagName): most
//     importantly keywords holding non-ASCII characters, which no IMAP response
//     can encode
//
// It sits on both the ingest paths (Sieve imap4flags, IMAP STORE/APPEND) and the
// paths that read keywords back out for a client, so an invalid keyword that
// predates this check is dropped on read as well as refused on write -- a
// mailbox poisoned by an earlier release heals itself the next time it is
// opened, without a data migration.
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

		// Skip the IMAP NIL / NULL atoms (and their "$"-prefixed forms), which
		// arise as parser artifacts (e.g. "Keyword used without being in FLAGS:
		// NIL"). Match the whole token only — legitimate keywords that merely
		// CONTAIN these substrings ("Nile", "nullable", "Manila", "$NOTNIL") are
		// kept.
		switch flagUpper {
		case "NIL", "$NIL", "NULL", "$NULL":
			continue
		}

		// Drop anything that is not encodable as an IMAP flag. Without this a
		// keyword such as a Cyrillic Sieve addflag value reaches the mailbox
		// keyword registry and wedges SELECT for good; see IsValidFlagName.
		if !IsValidFlagName(flag) {
			continue
		}

		// Flag is valid, keep it
		sanitized = append(sanitized, flag)
	}

	return sanitized
}

// DroppedFlags returns the flags in raw that SanitizeFlags(raw) removed, as
// strings, for logging. Sieve imap4flags is the one flag source that never
// passes an IMAP parser, so a dropped keyword there is a user's script line
// that silently did nothing; callers log these so support can point at it.
func DroppedFlags(raw, kept []imap.Flag) []string {
	if len(raw) == len(kept) {
		return nil
	}
	dropped := make([]string, 0, len(raw)-len(kept))
	for _, f := range raw {
		if !slices.Contains(kept, f) {
			dropped = append(dropped, string(f))
		}
	}
	return dropped
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
