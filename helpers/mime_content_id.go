package helpers

import "strings"

// mimeContentID ignores surrounding comments and folding whitespace, which have
// no semantic content in Content-ID or a multipart/related start msg-id (RFC
// 2045 §§1, 7; RFC 2387 §3.4). Keep the identifier's bytes and case, including
// legacy IDs such as <logo>, and retain raw matching for malformed wrappers.
func mimeContentID(raw string) string {
	fallback := strings.TrimSpace(raw)
	s := mimeHeaderScanner{rest: fallback}
	if !s.skipCFWS() || !strings.HasPrefix(s.rest, "<") {
		return fallback
	}
	id := s.rest
	quoted, literal, escaped := false, false, false
	for i := 1; i < len(id); i++ {
		c := id[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && (quoted || literal) {
			escaped = true
			continue
		}
		if quoted {
			if c == '"' {
				quoted = false
			}
			continue
		}
		if literal {
			if c == ']' {
				literal = false
			}
			continue
		}
		switch c {
		case '"':
			quoted = true
		case '[':
			literal = true
		case '>':
			s.rest = id[i+1:]
			if s.skipCFWS() && s.rest == "" {
				return id[:i+1]
			}
			return fallback
		}
	}
	return fallback
}
