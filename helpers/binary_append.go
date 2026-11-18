package helpers

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/emersion/go-message"
)

// ErrBinaryAppendUnsafe means a binary APPEND cannot be represented as ordinary
// MIME without guessing at its structure or changing its decoded content.
var ErrBinaryAppendUnsafe = errors.New("binary APPEND cannot be safely encoded")

const (
	maxBinaryAppendDepth   = 64
	maxBinaryAppendParts   = 4096
	maxBinaryAppendPatches = 8192
	maxBinaryAppendHeader  = 1 << 20
	maxBinaryAppendHeaders = 4 << 20
)

// NormalizeBinaryAppend converts binary MIME leaves to base64 without decoding
// charsets or rewriting unrelated headers, bodies, or multipart framing. Identity
// encodings containing NUL are converted too. Unsafe or ambiguous input returns
// ErrBinaryAppendUnsafe; the caller can answer NO [UNKNOWN-CTE].
//
// The input is never modified. If it needs no changes, the original slice is
// returned and reserveOutput is not called. Otherwise reserveOutput receives the
// exact output size before its buffer is allocated; its error is returned as-is.
// The caller owns releasing that reservation, including when it retains raw too.
func NormalizeBinaryAppend(raw []byte, reserveOutput func(int64) error) ([]byte, error) {
	p := binaryAppendPlan{raw: raw}
	if err := p.entity(0, len(raw), "text/plain", 0); err != nil {
		return nil, err
	}
	if len(p.patches) == 0 {
		if bytes.IndexByte(raw, 0) >= 0 {
			return nil, binaryAppendUnsafe("unrepresentable NUL outside a MIME leaf")
		}
		return raw, nil
	}
	sort.Slice(p.patches, func(i, j int) bool { return p.patches[i].start < p.patches[j].start })
	size := len(raw)
	last := 0
	for _, patch := range p.patches {
		if patch.start < last {
			return nil, binaryAppendUnsafe("overlapping MIME regions")
		}
		if bytes.IndexByte(raw[last:patch.start], 0) >= 0 {
			return nil, binaryAppendUnsafe("NUL outside a converted MIME body")
		}
		last = patch.end
		delta := patch.size - (patch.end - patch.start)
		if delta > 0 && size > int(^uint(0)>>1)-delta {
			return nil, binaryAppendUnsafe("encoded message is too large")
		}
		size += delta
	}
	if bytes.IndexByte(raw[last:], 0) >= 0 {
		return nil, binaryAppendUnsafe("NUL outside a converted MIME body")
	}
	if reserveOutput != nil {
		if err := reserveOutput(int64(size)); err != nil {
			return nil, err
		}
	}
	out := make([]byte, size)
	pos, source := 0, 0
	for _, patch := range p.patches {
		pos += copy(out[pos:], raw[source:patch.start])
		if patch.base64 {
			pos += writeBinaryAppendBase64(out[pos:pos+patch.size], raw[patch.start:patch.end])
		} else {
			pos += copy(out[pos:], patch.header)
		}
		source = patch.end
	}
	copy(out[pos:], raw[source:])
	return out, nil
}

type binaryAppendPatch struct {
	start, end int
	size       int
	header     string
	base64     bool
}

type binaryAppendPlan struct {
	raw     []byte
	patches []binaryAppendPatch
	parts   int
	headers int
}

type binaryAppendHeader struct {
	body                       int
	separator                  int
	contentType, encoding      string
	encodingStart, encodingEnd int
	hasEncoding                bool
}

func binaryAppendUnsafe(reason string) error {
	return fmt.Errorf("%w: %s", ErrBinaryAppendUnsafe, reason)
}

func (p *binaryAppendPlan) entity(start, end int, defaultType string, depth int) error {
	if depth > maxBinaryAppendDepth {
		return binaryAppendUnsafe("MIME nesting limit exceeded")
	}
	p.parts++
	if p.parts > maxBinaryAppendParts {
		return binaryAppendUnsafe("MIME part limit exceeded")
	}
	h, err := readBinaryAppendHeader(p.raw, start, end)
	if err != nil {
		return err
	}
	p.headers += h.body - start
	if p.headers > maxBinaryAppendHeaders {
		return binaryAppendUnsafe("total MIME header limit exceeded")
	}
	body := p.raw[h.body:end]
	mediaType := defaultType
	var contentType mimeHeaderValue
	var readerBoundary string
	if h.contentType != "" {
		contentType = parseMIMEHeaderStrict(h.contentType, true)
		if !contentType.complete || contentType.value == "" {
			return binaryAppendUnsafe("ambiguous MIME content type")
		}
		mediaType = contentType.value
		// Use the same header-only parameter decoding as FETCH. The strict
		// parser must not select regions under a boundary the stored-message
		// reader interprets differently (encoded words, RFC 2231 charsets).
		var readerHeader message.Header
		readerHeader.Set("Content-Type", h.contentType)
		readerType, params, err := readerHeader.ContentType()
		if err != nil || readerType != mediaType {
			return binaryAppendUnsafe("MIME readers disagree on content type")
		}
		readerBoundary = params["boundary"]
	}
	encoding := transferEncodingMechanism(h.encoding)
	switch encoding {
	case "", "7bit", "8bit", "binary":
	case "base64", "quoted-printable":
		if strings.HasPrefix(mediaType, "multipart/") || mediaType == "message/rfc822" || mediaType == "message/global" {
			return binaryAppendUnsafe("encoded MIME container cannot be normalized")
		}
		if bytes.IndexByte(body, 0) >= 0 {
			return binaryAppendUnsafe("NUL in an encoded MIME body")
		}
		return nil
	default:
		if strings.HasPrefix(mediaType, "multipart/") || mediaType == "message/rfc822" || mediaType == "message/global" {
			return binaryAppendUnsafe("unknown MIME container encoding")
		}
		if bytes.IndexByte(body, 0) >= 0 {
			return binaryAppendUnsafe("unknown transfer encoding contains NUL")
		}
		return nil // A safe opaque encoding does not need conversion.
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary, ok := contentType.boundary()
		if !ok || !validBinaryAppendBoundary(boundary) || boundary != readerBoundary {
			return binaryAppendUnsafe("invalid multipart boundary")
		}
		if encoding == "binary" {
			if err := p.encodingPatch(h, "8bit"); err != nil {
				return err
			}
		}
		childType := "text/plain"
		if mediaType == "multipart/digest" {
			childType = "message/rfc822"
		}
		return p.multipart(h.body, end, boundary, childType, depth)
	}
	if mediaType == "message/rfc822" || mediaType == "message/global" {
		if encoding == "binary" {
			if err := p.encodingPatch(h, "8bit"); err != nil {
				return err
			}
		}
		return p.entity(h.body, end, "text/plain", depth+1)
	}
	if encoding != "binary" && bytes.IndexByte(body, 0) < 0 {
		return nil
	}
	if strings.HasPrefix(mediaType, "message/") {
		return binaryAppendUnsafe("message container cannot be base64 encoded")
	}
	if err := p.encodingPatch(h, "base64"); err != nil {
		return err
	}
	// MIME base64 uses 76-character lines; only separators between lines are
	// added, leaving boundary-owned CRLF outside the transformed body span.
	if len(body) > (int(^uint(0)>>1)-2)/4*3 {
		return binaryAppendUnsafe("encoded body is too large")
	}
	size := base64.StdEncoding.EncodedLen(len(body))
	if size > 0 {
		breaks := (size - 1) / 76
		if size > int(^uint(0)>>1)-2*breaks {
			return binaryAppendUnsafe("encoded body is too large")
		}
		size += 2 * breaks
	}
	return p.patch(binaryAppendPatch{start: h.body, end: end, size: size, base64: true})
}

func (p *binaryAppendPlan) encodingPatch(h binaryAppendHeader, encoding string) error {
	start, end := h.separator, h.separator
	if h.hasEncoding {
		start, end = h.encodingStart, h.encodingEnd
	}
	field := "Content-Transfer-Encoding: " + encoding + "\r\n"
	return p.patch(binaryAppendPatch{start: start, end: end, size: len(field), header: field})
}

func (p *binaryAppendPlan) patch(patch binaryAppendPatch) error {
	if len(p.patches) >= maxBinaryAppendPatches {
		return binaryAppendUnsafe("MIME replacement limit exceeded")
	}
	p.patches = append(p.patches, patch)
	return nil
}

// multipart recognizes complete delimiter lines, retaining their exact bytes and
// the CRLF which introduces them. That CRLF is framing, not child payload.
func (p *binaryAppendPlan) multipart(start, end int, boundary, defaultType string, depth int) error {
	marker := []byte("--" + boundary)
	partStart := -1
	for line := start; line < end; {
		next := bytes.IndexByte(p.raw[line:end], '\n')
		lineEnd := end
		if next >= 0 {
			lineEnd = line + next + 1
		}
		value := p.raw[line:lineEnd]
		if bytes.HasSuffix(value, []byte("\n")) {
			value = value[:len(value)-1]
			if bytes.HasSuffix(value, []byte("\r")) {
				value = value[:len(value)-1]
			}
		}
		if bytes.HasPrefix(value, marker) {
			rest := value[len(marker):]
			closing := bytes.HasPrefix(rest, []byte("--"))
			if closing {
				rest = rest[2:]
			}
			if len(bytes.Trim(rest, " \t")) == 0 {
				if line > start && (line < 2 || p.raw[line-2] != '\r') {
					return binaryAppendUnsafe("multipart delimiter lacks CRLF")
				}
				if lineEnd != end && (lineEnd < 2 || p.raw[lineEnd-2] != '\r') {
					return binaryAppendUnsafe("multipart delimiter lacks CRLF")
				}
				regionEnd := line
				if line > start {
					regionEnd -= 2
				}
				if partStart < 0 {
					if closing || bytes.IndexByte(p.raw[start:regionEnd], 0) >= 0 {
						return binaryAppendUnsafe("invalid multipart preamble")
					}
				} else {
					if regionEnd < partStart {
						return binaryAppendUnsafe("empty multipart entity")
					}
					if err := p.entity(partStart, regionEnd, defaultType, depth+1); err != nil {
						return err
					}
				}
				if closing {
					if bytes.IndexByte(p.raw[lineEnd:end], 0) >= 0 {
						return binaryAppendUnsafe("NUL in multipart epilogue")
					}
					return nil
				}
				if lineEnd == end {
					return binaryAppendUnsafe("truncated multipart delimiter")
				}
				partStart = lineEnd
			}
		}
		line = lineEnd
	}
	return binaryAppendUnsafe("missing closing multipart delimiter")
}

func validBinaryAppendBoundary(boundary string) bool {
	if len(boundary) == 0 || len(boundary) > 70 || boundary[len(boundary)-1] == ' ' {
		return false
	}
	for _, c := range []byte(boundary) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("'()+_,-./:=? ", rune(c)) {
			continue
		}
		return false
	}
	return true
}

// readBinaryAppendHeader records metadata spans without passing the body through
// a MIME/charset decoder or reserializing any unchanged field.
func readBinaryAppendHeader(raw []byte, start, end int) (binaryAppendHeader, error) {
	var h binaryAppendHeader
	fieldStart, valueStart := -1, -1
	var fieldName string
	hasType := false
	finish := func(fieldEnd int) error {
		if fieldStart < 0 {
			return nil
		}
		if fieldName != "content-type" && fieldName != "content-transfer-encoding" {
			return nil
		}
		value := binaryAppendHeaderValue(raw[valueStart:fieldEnd])
		if fieldName == "content-type" {
			if hasType || value == "" {
				return binaryAppendUnsafe("ambiguous Content-Type header")
			}
			h.contentType, hasType = value, true
		} else {
			if h.hasEncoding {
				return binaryAppendUnsafe("duplicate Content-Transfer-Encoding header")
			}
			h.encoding, h.hasEncoding = value, true
			h.encodingStart, h.encodingEnd = fieldStart, fieldEnd
		}
		return nil
	}
	for pos := start; pos < end; {
		lf := bytes.IndexByte(raw[pos:end], '\n')
		if lf < 1 || pos+lf-start+1 > maxBinaryAppendHeader || raw[pos+lf-1] != '\r' {
			return h, binaryAppendUnsafe("invalid or oversized MIME header")
		}
		next := pos + lf + 1
		line := raw[pos : next-2]
		if bytes.IndexByte(line, 0) >= 0 || bytes.IndexByte(line, '\r') >= 0 {
			return h, binaryAppendUnsafe("invalid byte in MIME header")
		}
		if len(line) == 0 {
			if err := finish(pos); err != nil {
				return h, err
			}
			h.separator, h.body = pos, next
			return h, nil
		}
		if line[0] == ' ' || line[0] == '\t' {
			if fieldStart < 0 {
				return h, binaryAppendUnsafe("orphan MIME header continuation")
			}
		} else {
			if err := finish(pos); err != nil {
				return h, err
			}
			colon := bytes.IndexByte(line, ':')
			if colon <= 0 {
				return h, binaryAppendUnsafe("malformed MIME header")
			}
			for _, c := range line[:colon] {
				if c < 33 || c > 126 {
					return h, binaryAppendUnsafe("invalid MIME header name")
				}
			}
			fieldStart, valueStart = pos, pos+colon+1
			fieldName = strings.ToLower(string(line[:colon]))
		}
		pos = next
	}
	return h, binaryAppendUnsafe("missing MIME header terminator")
}

// Match go-message/textproto's field unfolding: trim only ASCII space/tab
// around each line, then join its nonempty lines with a single space. In
// particular, Unicode whitespace must not turn an unknown CTE into "binary",
// and a quoted folded boundary must name the same parts when FETCH reads it.
func binaryAppendHeaderValue(raw []byte) string {
	var value strings.Builder
	value.Grow(len(raw))
	for len(raw) > 0 {
		line := raw
		if lf := bytes.IndexByte(raw, '\n'); lf >= 0 {
			line, raw = raw[:lf], raw[lf+1:]
		} else {
			raw = nil
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		line = bytes.Trim(line, " \t")
		if len(line) == 0 {
			continue
		}
		if value.Len() > 0 {
			value.WriteByte(' ')
		}
		value.Write(line)
	}
	return value.String()
}

func writeBinaryAppendBase64(out, raw []byte) int {
	pos := 0
	for len(raw) > 0 {
		n := min(len(raw), 57) // 57 octets produce a 76-character MIME line.
		encoded := base64.StdEncoding.EncodedLen(n)
		base64.StdEncoding.Encode(out[pos:pos+encoded], raw[:n])
		pos += encoded
		raw = raw[n:]
		if len(raw) > 0 {
			pos += copy(out[pos:], "\r\n")
		}
	}
	return pos
}
