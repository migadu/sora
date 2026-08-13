package server

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseLine is a simple, non-spec-compliant parser for line-based protocols.
// It handles space-separated atoms and double-quoted strings.
// If hasTag is true, it expects the line to start with a tag.
func ParseLine(line string, hasTag bool) (tag, command string, args []string, err error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", nil, nil
	}

	rem := line
	if hasTag {
		// 1. Extract Tag
		parts := strings.SplitN(rem, " ", 2)
		tag = parts[0]
		if len(parts) < 2 {
			return tag, "", nil, nil // Tag only
		}
		rem = strings.TrimSpace(parts[1])
	}

	// 2. Extract Command
	if rem == "" {
		// This can happen if hasTag is true and there's only a tag.
		return tag, "", nil, nil
	}
	parts := strings.SplitN(rem, " ", 2)
	command = strings.ToUpper(parts[0])
	if len(parts) < 2 {
		return tag, command, nil, nil // Tag and command, no args
	}
	rem = strings.TrimSpace(parts[1])

	// 3. Parse arguments
	for rem != "" {
		rem = strings.TrimSpace(rem)
		if rem == "" {
			break
		}

		var arg string
		if rem[0] == '"' {
			// Quoted string - find closing quote, respecting escape sequences
			// RFC 3501: quoted-specials = DQUOTE / "\"
			// Characters inside quotes can be escaped with backslash
			i := 1
			escaped := false
			found := false
			for i < len(rem) {
				if escaped {
					// Previous character was backslash, skip this character
					escaped = false
					i++
					continue
				}
				if rem[i] == '\\' {
					escaped = true
					i++
					continue
				}
				if rem[i] == '"' {
					// Found unescaped closing quote
					arg = rem[:i+1]
					rem = rem[i+1:]
					found = true
					break
				}
				i++
			}
			if !found {
				return tag, command, nil, fmt.Errorf("unclosed quote in command arguments")
			}
		} else {
			// Atom
			end := strings.Index(rem, " ")
			if end == -1 {
				arg = rem
				rem = ""
			} else {
				arg = rem[:end]
				rem = rem[end:]
			}
		}
		args = append(args, arg)
	}

	return tag, command, args, nil
}

// UnquoteString removes surrounding double quotes from a string if present
// and processes escape sequences according to RFC 3501.
// RFC 3501: quoted-specials = DQUOTE / "\"
// Inside quoted strings, backslash is used to escape double-quote and backslash itself.
func UnquoteString(str string) string {
	if len(str) < 2 || str[0] != '"' || str[len(str)-1] != '"' {
		return str
	}

	// Remove surrounding quotes
	inner := str[1 : len(str)-1]

	// Process escape sequences
	var result strings.Builder
	result.Grow(len(inner)) // Pre-allocate to avoid reallocations
	escaped := false
	for i := 0; i < len(inner); i++ {
		if escaped {
			// Previous character was backslash, add this character literally
			result.WriteByte(inner[i])
			escaped = false
		} else if inner[i] == '\\' {
			// Start escape sequence
			escaped = true
		} else {
			// Regular character
			result.WriteByte(inner[i])
		}
	}

	return result.String()
}

// ParseLiteral parses an IMAP literal string {size} or {size+} and returns
// the size plus whether the literal is non-synchronizing. Non-synchronizing
// literals ({size+}, RFC 7888 LITERAL+) are base functionality in IMAP4rev2
// (RFC 9051 §4.3): the client sends the literal data immediately without
// waiting for a continuation response, so callers must NOT send one.
// Returns error if the format is invalid or size is negative.
func ParseLiteral(str string) (size int, nonSync bool, err error) {
	if !strings.HasPrefix(str, "{") || !strings.HasSuffix(str, "}") {
		return 0, false, fmt.Errorf("not a literal")
	}

	sizeStr := str[1 : len(str)-1]
	if strings.HasSuffix(sizeStr, "+") {
		nonSync = true
		sizeStr = sizeStr[:len(sizeStr)-1]
	}
	// RFC grammar allows digits only (Atoi would also accept a leading sign)
	if sizeStr == "" {
		return 0, false, fmt.Errorf("empty literal size")
	}
	for _, c := range sizeStr {
		if c < '0' || c > '9' {
			return 0, false, fmt.Errorf("invalid literal size: %q", sizeStr)
		}
	}
	size, err = strconv.Atoi(sizeStr)
	if err != nil {
		return 0, false, fmt.Errorf("invalid literal size: %w", err)
	}

	return size, nonSync, nil
}
