package helpers

import (
	stdmime "mime"
	"net/url"
	"strconv"
	"strings"
)

// mimeFilename checks for a nonempty filename without decoding its charset.
// mime.ParseMediaType silently drops RFC 2231 values in charsets other than
// UTF-8/ASCII. Parse each value under a neutral attribute instead, retaining
// encoded bytes and continuations. Their existence, not display text, matters.
func mimeFilename(header, name string) attachmentResult {
	prefix, remaining, hasParams := strings.Cut(header, ";")
	if !hasParams {
		return attachmentNone
	}
	// A quote in an invalid type/disposition must not turn text inside it
	// into an apparent filename parameter.
	if _, _, err := stdmime.ParseMediaType(prefix); err != nil {
		return attachmentUnknown
	}
	params := make(map[string]string)
	for remaining != "" {
		var segment string
		segment, remaining = nextMIMEParameter(remaining)
		key, value, ok := strings.Cut(segment, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || (key != name && !strings.HasPrefix(key, name+"*")) {
			continue
		}
		_, parsed, err := stdmime.ParseMediaType("x; value=" + strings.TrimSpace(value))
		if err != nil {
			return attachmentUnknown
		}
		if previous, exists := params[key]; exists && previous != parsed["value"] {
			return attachmentUnknown
		}
		params[key] = parsed["value"]
	}
	if params[name] != "" {
		return attachmentFound
	}
	delete(params, name)
	if value, exists := params[name+"*"]; exists {
		decoded, ok := mimeParameterBytes(value, true)
		if !ok {
			return attachmentUnknown
		}
		if decoded != "" {
			return attachmentFound
		}
		delete(params, name+"*")
	}
	// RFC 2231 continuations start at zero, have no gaps, and may arrive in
	// any order. Bound the loop by the number of parameters, not an index
	// supplied by the message.
	found, consumed := false, 0
	for i := 0; i < len(params); i++ {
		key := name + "*" + strconv.Itoa(i)
		plain, hasPlain := params[key]
		encoded, hasEncoded := params[key+"*"]
		if hasPlain == hasEncoded {
			return attachmentUnknown
		}
		if hasEncoded {
			var ok bool
			plain, ok = mimeParameterBytes(encoded, i == 0)
			if !ok {
				return attachmentUnknown
			}
		}
		found = found || plain != ""
		consumed++
	}
	if consumed > 0 && found {
		return attachmentFound
	}
	return attachmentNone
}

// nextMIMEParameter only finds an unquoted semicolon. The standard MIME parser
// handles the actual token/quoted-string syntax and escapes of each value.
func nextMIMEParameter(s string) (string, string) {
	quoted := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if quoted {
				i++
			}
		case '"':
			quoted = !quoted
		case ';':
			if !quoted {
				return s[:i], s[i+1:]
			}
		}
	}
	return s, ""
}

func mimeParameterBytes(value string, first bool) (string, bool) {
	if first {
		// charset'language'encoded-value; either prefix may be unspecified.
		_, rest, ok := strings.Cut(value, "'")
		if !ok {
			return "", false
		}
		_, value, ok = strings.Cut(rest, "'")
		if !ok {
			return "", false
		}
	}
	decoded, err := url.PathUnescape(value)
	return decoded, err == nil
}
