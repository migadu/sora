package server

import (
	"fmt"
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
			// Quoted string
			end := strings.Index(rem[1:], `"`)
			if end == -1 {
				return tag, command, nil, fmt.Errorf("unclosed quote in command arguments")
			}
			arg = rem[:end+2]
			rem = rem[end+2:]
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

// UnquoteString removes surrounding double quotes from a string if present.
func UnquoteString(str string) string {
	if len(str) >= 2 && str[0] == '"' && str[len(str)-1] == '"' {
		return str[1 : len(str)-1]
	}
	return str
}
