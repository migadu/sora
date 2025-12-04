package helpers

import (
	"strings"
	"unicode"
)

// NormalizeSubjectForSort normalizes an email subject for SORT operations per RFC 5256.
// It removes reply/forward prefixes and normalizes whitespace to ensure proper thread grouping.
//
// RFC 5256 Section 2.1 defines the base subject extraction algorithm:
// 1. Remove leading "Re:", "Fwd:", etc. (case-insensitive)
// 2. Remove leading/trailing whitespace
// 3. Repeat until no more prefixes can be removed
//
// This function handles common prefixes:
// - Re, RE, re (Reply)
// - Fw, FW, fw, Fwd, FWD, fwd (Forward)
// And their variations with/without colons and brackets
func NormalizeSubjectForSort(subject string) string {
	if subject == "" {
		return ""
	}

	// Uppercase for case-insensitive comparison
	normalized := strings.ToUpper(subject)

	// Keep removing prefixes until we can't remove any more
	changed := true
	for changed {
		changed = false
		old := normalized

		// Trim leading/trailing whitespace
		normalized = strings.TrimSpace(normalized)

		// Remove leading "Re:" variants
		// Handles: Re:, RE:, re:, Re[2]:, Re(3):, etc.
		normalized = removeReplyPrefix(normalized)

		// Remove leading "Fwd:" variants
		// Handles: Fwd:, FWD:, fwd:, Fw:, FW:, fw:, Forward:, etc.
		normalized = removeForwardPrefix(normalized)

		if old != normalized {
			changed = true
		}
	}

	// Final cleanup: trim any remaining whitespace
	return strings.TrimSpace(normalized)
}

// removeReplyPrefix removes reply prefixes like "Re:", "RE:", "Re[2]:", etc.
func removeReplyPrefix(s string) string {
	s = strings.TrimSpace(s)

	// Check for "Re:" prefix (case already uppercased by caller)
	if strings.HasPrefix(s, "RE:") {
		s = strings.TrimSpace(s[3:])
		return s
	}

	// Check for "Re[N]:" or "Re(N):" style prefixes
	if strings.HasPrefix(s, "RE[") || strings.HasPrefix(s, "RE(") {
		// Find the closing bracket/paren
		closeChar := ']'
		if s[2] == '(' {
			closeChar = ')'
		}

		// Find closing character
		closeIdx := strings.IndexRune(s[3:], closeChar)
		if closeIdx >= 0 {
			// Check if there's a colon after the bracket
			afterBracket := s[3+closeIdx+1:]
			if strings.HasPrefix(afterBracket, ":") {
				return strings.TrimSpace(afterBracket[1:])
			}
		}
	}

	return s
}

// removeForwardPrefix removes forward prefixes like "Fwd:", "FW:", "Forward:", etc.
func removeForwardPrefix(s string) string {
	s = strings.TrimSpace(s)

	// Check for common forward prefixes (case already uppercased by caller)
	prefixes := []string{
		"FWD:", "FW:", "FORWARD:",
	}

	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return strings.TrimSpace(s[len(prefix):])
		}
	}

	return s
}

// SanitizeSubjectForSort combines UTF-8 sanitization with RFC 5256 normalization.
// This is the recommended function to use for SORT operations.
func SanitizeSubjectForSort(subject string) string {
	// First sanitize UTF-8
	sanitized := SanitizeUTF8(subject)

	// Then normalize for sorting per RFC 5256
	return NormalizeSubjectForSort(sanitized)
}

// isWhitespace checks if a rune is whitespace
func isWhitespace(r rune) bool {
	return unicode.IsSpace(r)
}
