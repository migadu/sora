package helpers

import "strings"

// mimeHeaderValue retains independent parameters even when another is bad.
// complete is required for a negative attachment result, but a valid parameter
// may still supply positive evidence. Conflicting duplicate keys stay invalid.
type mimeHeaderValue struct {
	value    string
	params   map[string]string
	invalid  map[string]bool
	complete bool
}

// parseMIMEHeader follows the MIME token/quoted-string grammar, including RFC
// 822 comments between tokens in both type and disposition fields (RFC 2183 §2
// and RFC 2045 verified erratum 2586).
func parseMIMEHeader(raw string, contentType bool) mimeHeaderValue {
	v := mimeHeaderValue{params: make(map[string]string), invalid: make(map[string]bool), complete: true}
	s := mimeHeaderScanner{rest: raw}
	if !s.skipCFWS() {
		v.complete = false
		return v
	}
	first := s.token()
	if first == "" || !s.skipCFWS() {
		v.complete = false
		return v
	}
	if contentType {
		if !s.take('/') || !s.skipCFWS() {
			v.complete = false
			return v
		}
		second := s.token()
		if second == "" {
			v.complete = false
			return v
		}
		v.value = strings.ToLower(first + "/" + second)
	} else {
		v.value = strings.ToLower(first)
	}
	if !s.skipCFWS() || (s.rest != "" && s.rest[0] != ';') {
		v.value, v.complete = "", false
		return v
	}
	for s.skipCFWS() {
		if s.rest == "" {
			return v
		}
		if !s.take(';') || !s.skipCFWS() {
			break
		}
		// Match mime.ParseMediaType's tolerance of a dangling separator.
		// It supplies no parameter and cannot conceal another MIME part.
		if s.rest == "" {
			return v
		}
		key := strings.ToLower(s.token())
		if key == "" || !s.skipCFWS() || !s.take('=') || !s.skipCFWS() {
			v.complete = false
			v.invalidate(key)
			if !s.recoverParameter() {
				return v
			}
			continue
		}
		value, valid, trustworthy := s.parameterValue()
		if !valid {
			v.complete = false
			v.invalidate(key)
		} else if previous, exists := v.params[key]; exists && previous != value {
			v.complete = false
			v.invalidate(key)
		} else if !v.invalid[key] {
			v.params[key] = value
		}
		if !trustworthy {
			return v
		}
	}
	v.complete = false
	return v
}

func (v *mimeHeaderValue) invalidate(key string) {
	if key != "" {
		delete(v.params, key)
		v.invalid[key] = true
	}
}

type mimeHeaderScanner struct {
	rest string
}

func (s *mimeHeaderScanner) take(c byte) bool {
	if s.rest == "" || s.rest[0] != c {
		return false
	}
	s.rest = s.rest[1:]
	return true
}

func mimeTokenByte(c byte) bool {
	return c > 32 && c < 127 && !strings.ContainsRune("()<>@,;:\\\"/[]?=", rune(c))
}

func (s *mimeHeaderScanner) token() string {
	i := 0
	for i < len(s.rest) && mimeTokenByte(s.rest[i]) {
		i++
	}
	token := s.rest[:i]
	s.rest = s.rest[i:]
	return token
}

func (s *mimeHeaderScanner) skipCFWS() bool {
	for len(s.rest) > 0 {
		switch s.rest[0] {
		case ' ', '\t', '\r', '\n':
			s.rest = s.rest[1:]
		case '(':
			depth := 1
			s.rest = s.rest[1:]
			for depth > 0 {
				if s.rest == "" {
					return false
				}
				c := s.rest[0]
				s.rest = s.rest[1:]
				switch c {
				case '\\':
					if s.rest == "" {
						return false
					}
					s.rest = s.rest[1:]
				case '(':
					depth++
				case ')':
					depth--
				}
			}
		default:
			return true
		}
	}
	return true
}

func (s *mimeHeaderScanner) parameterValue() (value string, valid, trustworthy bool) {
	if s.take('"') {
		var decoded strings.Builder
		for len(s.rest) > 0 {
			c := s.rest[0]
			s.rest = s.rest[1:]
			if c == '"' {
				if !s.skipCFWS() || (s.rest != "" && s.rest[0] != ';') {
					// Junk after a closing quote may mean the quote belonged
					// to a later field. Do not reinterpret its semicolons.
					return "", false, false
				}
				return decoded.String(), true, true
			}
			if c == '\\' {
				if s.rest == "" {
					return "", false, false
				}
				c = s.rest[0]
				s.rest = s.rest[1:]
			}
			decoded.WriteByte(c)
		}
		return "", false, false
	}
	value = s.token()
	if value != "" && s.skipCFWS() && (s.rest == "" || s.rest[0] == ';') {
		return value, true, true
	}
	return "", false, s.recoverParameter()
}

// Only recover at a delimiter whose quote/comment scope is known. An unquoted
// slash or space is recoverable; a stray quote makes the remaining text opaque.
func (s *mimeHeaderScanner) recoverParameter() bool {
	for len(s.rest) > 0 {
		switch s.rest[0] {
		case ';':
			return true
		case '"':
			return false
		case '(':
			if !s.skipCFWS() {
				return false
			}
		default:
			s.rest = s.rest[1:]
		}
	}
	return true
}
