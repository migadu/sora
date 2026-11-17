package helpers

import (
	"bytes"
	"strings"

	"github.com/emersion/go-message"
)

// ExtractMessageIDRaw extracts the unfolded RFC 5322 Message-ID field text when
// messages.message_id cannot represent it losslessly for IMAP HEADER Message-ID
// substring searches (#529).
//
// It returns nil when:
//   - no Message-ID header field is present, or
//   - there is a single Message-ID field whose unfolded trimmed value equals
//     "<" + SanitizeUTF8(parsedMessageID) + ">" and contains neither a leading '<'
//     inside parsedMessageID nor a '[' domain-literal bracket.
//
// Otherwise it returns the unfolded trimmed field text (joining multiple
// Message-ID header fields with "\n", since no single unfolded field contains
// a newline).
func ExtractMessageIDRaw(header message.Header, parsedMessageID string) *string {
	fields := header.FieldsByKey("Message-ID")
	var values []string
	for fields.Next() {
		var unfolded string
		if raw, err := fields.Raw(); err == nil {
			if colon := bytes.IndexByte(raw, ':'); colon >= 0 {
				unfolded = unfoldRFC5322FieldBody(raw[colon+1:])
			} else {
				unfolded = unfoldRFC5322FieldBody(raw)
			}
		} else {
			unfolded = strings.Map(func(r rune) rune {
				if r == '\r' || r == '\n' {
					return ' '
				}
				return r
			}, fields.Value())
			unfolded = strings.Trim(unfolded, " \t")
		}
		values = append(values, SanitizeUTF8(unfolded))
	}
	if len(values) == 0 {
		return nil
	}

	saneParsed := SanitizeUTF8(parsedMessageID)
	if len(values) == 1 &&
		saneParsed != "" &&
		!strings.HasPrefix(saneParsed, "<") &&
		!strings.Contains(saneParsed, "[") &&
		values[0] == "<"+saneParsed+">" {
		return nil
	}

	joined := strings.Join(values, "\n")
	return &joined
}

// ExtractRawMessageIDFromBytes extracts unfolded Message-ID field text directly
// from a raw RFC 5322 header block when server.ParseMessage fails on degraded
// IMAP APPEND (where parsedMessageID is always empty and replaced by a synthetic
// "<timestamp@mailbox>" ID). Returns nil when no Message-ID field is present.
func ExtractRawMessageIDFromBytes(raw []byte) *string {
	var values []string
	var current bytes.Buffer
	collecting := false

	flush := func() {
		if !collecting {
			return
		}
		v := SanitizeUTF8(unfoldRFC5322FieldBody(current.Bytes()))
		values = append(values, v)
		current.Reset()
		collecting = false
	}

	rest := raw
	for len(rest) > 0 {
		var line []byte
		if nl := bytes.IndexByte(rest, '\n'); nl >= 0 {
			line = rest[:nl]
			rest = rest[nl+1:]
		} else {
			line = rest
			rest = nil
		}
		trimmedCR := line
		if len(trimmedCR) > 0 && trimmedCR[len(trimmedCR)-1] == '\r' {
			trimmedCR = trimmedCR[:len(trimmedCR)-1]
		}
		if len(trimmedCR) == 0 {
			break
		}
		if trimmedCR[0] == ' ' || trimmedCR[0] == '\t' {
			if collecting {
				current.Write(trimmedCR)
			}
			continue
		}
		flush()
		colon := bytes.IndexByte(trimmedCR, ':')
		if colon <= 0 {
			continue
		}
		name := trimmedCR[:colon]
		for len(name) > 0 && (name[len(name)-1] == ' ' || name[len(name)-1] == '\t') {
			name = name[:len(name)-1]
		}
		if isMessageIDFieldName(name) {
			collecting = true
			current.Write(trimmedCR[colon+1:])
		}
	}
	flush()

	if len(values) == 0 {
		return nil
	}
	joined := strings.Join(values, "\n")
	return &joined
}

// SanitizeMessageIDRaw sanitizes a caller-supplied *string for storage in
// messages.message_id_raw. Retain the complete field body: RFC 5322 limits
// physical line length, not the total length of a folded field. Ingress message
// limits already bound the source bytes.
func SanitizeMessageIDRaw(raw *string) *string {
	if raw == nil {
		return nil
	}
	s := SanitizeUTF8(*raw)
	return &s
}

func isMessageIDFieldName(name []byte) bool {
	const want = "message-id"
	if len(name) != len(want) {
		return false
	}
	for i, c := range name {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != want[i] {
			return false
		}
	}
	return true
}

// unfoldRFC5322FieldBody removes CRLF/LF before WSP (RFC 5322 §2.2.3), strips
// trailing line terminators, replaces any stray bare CR/LF with space so "\n"
// remains an unambiguous separator between multiple Message-ID fields, and trims
// surrounding horizontal whitespace.
func unfoldRFC5322FieldBody(b []byte) string {
	for len(b) > 0 && (b[len(b)-1] == '\r' || b[len(b)-1] == '\n') {
		b = b[:len(b)-1]
	}
	var out strings.Builder
	out.Grow(len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '\r' && i+2 < len(b) && b[i+1] == '\n' && (b[i+2] == ' ' || b[i+2] == '\t') {
			i++ // skip \r\n, next iteration writes the WSP byte
			continue
		}
		if b[i] == '\n' && i+1 < len(b) && (b[i+1] == ' ' || b[i+1] == '\t') {
			continue // skip \n before WSP
		}
		if b[i] == '\r' || b[i] == '\n' {
			out.WriteByte(' ')
			continue
		}
		out.WriteByte(b[i])
	}
	return strings.Trim(out.String(), " \t")
}
