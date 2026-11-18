package helpers

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"strings"

	"github.com/emersion/go-message/textproto"
)

// maxNULPartDepth bounds the entity nesting EncodeNULParts descends into, as
// maxAttachmentMultipartDepth does for attachment classification. Deeper
// entities are kept as they are.
const maxNULPartDepth = 128

// EncodeNULParts re-encodes as base64 every leaf body part that holds a NUL
// octet under an identity Content-Transfer-Encoding (none, 7bit, 8bit or
// binary), and keeps every other byte of the message as it is. It returns data
// and false when no part needed it.
//
// RFC 3501 §4.3 and RFC 9051 §4.3 do not permit "unencoded binary strings" (any
// string with NUL) outside BINARY[], and RFC 3516 §6 has FETCH BODY return the
// content "in the format described by the corresponding FETCH BODYSTRUCTURE
// response", so such a part cannot be stored as it arrived. RFC 3516 §4.4 lets
// the server "modify the CTE of the appended data" as long as the
// transformation does not "result in a loss of data", which base64 does not.
//
// The input is never modified. When nothing needs re-encoding, data itself is
// returned and reserve is not called. Otherwise the exact size of the encoded
// message is computed first, without allocating it, and passed to reserve
// (when not nil) BEFORE the output buffer is allocated; an error from reserve
// is returned as is, with nothing allocated. The caller owns releasing what
// reserve took. data stays referenced by the caller, so for the length of the
// call both buffers exist at once: reserve is told the whole output size, not
// only its growth over data.
func EncodeNULParts(data []byte, reserve func(size int64) error) ([]byte, bool, error) {
	if bytes.IndexByte(data, 0) < 0 {
		return data, false, nil
	}
	count := &nulPartWriter{count: true}
	if !encodeNULEntity(count, data, "text/plain", 0) {
		return data, false, nil
	}
	if reserve != nil {
		if err := reserve(count.n); err != nil {
			return nil, false, err
		}
	}
	out := &nulPartWriter{buf: make([]byte, 0, count.n)}
	encodeNULEntity(out, data, "text/plain", 0)
	return out.buf, true, nil
}

// nulPartWriter receives encodeNULEntity's output. With count set it only adds
// up the size, so EncodeNULParts can have the output reserved before it
// allocates it; the same code produces both, so the size is exact.
type nulPartWriter struct {
	buf   []byte
	n     int64
	count bool
}

func (w *nulPartWriter) Write(p []byte) {
	w.n += int64(len(p))
	if !w.count {
		w.buf = append(w.buf, p...)
	}
}

// encodeNULEntity writes entity to out, with its NUL-bearing leaves re-encoded.
// It reports whether it changed anything.
func encodeNULEntity(out *nulPartWriter, entity []byte, defaultType string, depth int) bool {
	headerEnd, bodyStart, ok := splitEntityHeader(entity)
	if !ok || depth > maxNULPartDepth || bytes.IndexByte(entity[bodyStart:], 0) < 0 {
		out.Write(entity)
		return false
	}
	header, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(entity[:bodyStart])))
	if err != nil {
		out.Write(entity)
		return false
	}
	body := entity[bodyStart:]

	contentType := mimeHeaderValue{value: defaultType, complete: true}
	if header.Has("Content-Type") {
		contentType = parseMIMEHeader(header.Get("Content-Type"), true)
	}
	mechanism := transferEncodingMechanism(header.Get("Content-Transfer-Encoding"))
	identity := mechanism == "" || mechanism == "7bit" || mechanism == "8bit" || mechanism == "binary"

	switch {
	case strings.HasPrefix(contentType.value, "multipart/"):
		boundary, ok := contentType.boundary()
		if !ok {
			break
		}
		childType := "text/plain"
		if contentType.value == "multipart/digest" {
			childType = "message/rfc822"
		}
		out.Write(entity[:bodyStart])
		return encodeNULMultipart(out, body, boundary, childType, depth)
	case contentType.value == "message/rfc822" || contentType.value == "message/global":
		if !identity {
			break
		}
		out.Write(entity[:bodyStart])
		return encodeNULEntity(out, body, "text/plain", depth+1)
	case identity:
		eol := entity[headerEnd:bodyStart]
		writeHeaderWithBase64CTE(out, entity[:headerEnd], eol)
		out.Write(eol)
		writeBase64Lines(out, body, eol)
		return true
	}
	out.Write(entity)
	return false
}

// splitEntityHeader returns where the header ends (the start of the empty
// line) and where the body starts (after it). ok is false without an empty
// line, so for an entity that is all header.
func splitEntityHeader(entity []byte) (headerEnd, bodyStart int, ok bool) {
	for p := 0; p < len(entity); {
		e := lineEnd(entity, p)
		if line := entity[p:e]; string(line) == "\r\n" || string(line) == "\n" {
			return p, e, true
		}
		p = e
	}
	return 0, 0, false
}

// lineEnd returns the index just past the LF ending the line that starts at p,
// or len(b) for a last line without one.
func lineEnd(b []byte, p int) int {
	if i := bytes.IndexByte(b[p:], '\n'); i >= 0 {
		return p + i + 1
	}
	return len(b)
}

// encodeNULMultipart writes a multipart body, re-encoding inside its parts. As
// in RFC 2046 §5.1.1 (and the go-message reader FETCH uses) the line break
// before a delimiter line belongs to the delimiter, not to the part before it.
func encodeNULMultipart(out *nulPartWriter, body []byte, boundary, childType string, depth int) bool {
	dash := []byte("--" + boundary)
	changed, closed := false, false
	copied := 0     // body[:copied] has been written
	partStart := -1 // start of the current part; -1 in the preamble
	for p := 0; p < len(body); {
		e := lineEnd(body, p)
		final, isDelimiter := delimiterLine(body[p:e], dash)
		if !isDelimiter {
			p = e
			continue
		}
		if partStart >= 0 {
			end := p
			if end > partStart && body[end-1] == '\n' {
				end--
				if end > partStart && body[end-1] == '\r' {
					end--
				}
			}
			out.Write(body[copied:partStart])
			if encodeNULEntity(out, body[partStart:end], childType, depth+1) {
				changed = true
			}
			copied = end
		}
		if final {
			closed = true
			break
		}
		partStart = e
		p = e
	}
	if !closed && partStart >= 0 {
		// A last part without a close delimiter runs to the end of the body.
		out.Write(body[copied:partStart])
		if encodeNULEntity(out, body[partStart:], childType, depth+1) {
			changed = true
		}
		copied = len(body)
	}
	out.Write(body[copied:])
	return changed
}

// delimiterLine reports whether line is a boundary delimiter line, and whether
// it is the close delimiter: "--" boundary ["--"], then optional linear white
// space (RFC 2046 §5.1.1 transport padding) and the line break.
func delimiterLine(line, dash []byte) (final, ok bool) {
	if !bytes.HasPrefix(line, dash) {
		return false, false
	}
	rest := line[len(dash):]
	if bytes.HasPrefix(rest, []byte("--")) {
		final, rest = true, rest[2:]
	}
	rest = bytes.TrimLeft(rest, " \t")
	switch string(rest) {
	case "", "\n", "\r\n":
		return final, true
	}
	return false, false
}

// writeHeaderWithBase64CTE writes header (its fields, without the empty line)
// with every Content-Transfer-Encoding field, folded lines included, replaced
// by one "Content-Transfer-Encoding: base64" where the first of them was, or
// after the last field when there was none.
func writeHeaderWithBase64CTE(out *nulPartWriter, header, eol []byte) {
	cte := append([]byte("Content-Transfer-Encoding: base64"), eol...)
	written := false
	inCTE := false
	for p := 0; p < len(header); {
		e := lineEnd(header, p)
		line := header[p:e]
		if line[0] != ' ' && line[0] != '\t' {
			name, _, _ := bytes.Cut(line, []byte(":"))
			inCTE = strings.EqualFold(strings.TrimSpace(string(name)), "Content-Transfer-Encoding")
			if inCTE && !written {
				out.Write(cte)
				written = true
			}
		}
		if !inCTE {
			out.Write(line)
		}
		p = e
	}
	if !written {
		out.Write(cte)
	}
}

// writeBase64Lines writes data base64-encoded in lines of 76 characters, the
// RFC 2045 §6.8 limit, separated by eol. The last line has no line break: the
// one that follows belongs to the next delimiter, if there is one.
func writeBase64Lines(out *nulPartWriter, data, eol []byte) {
	const lineInput = 76 / 4 * 3
	if out.count {
		// Every line but the last encodes lineInput octets (a multiple of 3), so
		// the lines together are as long as data encoded in one piece.
		if len(data) > 0 {
			lines := (len(data) + lineInput - 1) / lineInput
			out.n += int64(base64.StdEncoding.EncodedLen(len(data))) + int64(lines-1)*int64(len(eol))
		}
		return
	}
	for len(data) > 0 {
		n := min(len(data), lineInput)
		before := len(out.buf)
		out.buf = base64.StdEncoding.AppendEncode(out.buf, data[:n])
		out.n += int64(len(out.buf) - before)
		data = data[n:]
		if len(data) > 0 {
			out.Write(eol)
		}
	}
}
