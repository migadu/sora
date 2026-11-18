package adminapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/migadu/sora/server"
)

// deliverRequestError is a request /admin/mail/deliver refuses with 400 and this text.
type deliverRequestError string

func (e deliverRequestError) Error() string { return string(e) }

const (
	// maxDeliverFormParts is how many parts a multipart/form-data delivery may have,
	// the limit http.Request.ParseMultipartForm applies.
	maxDeliverFormParts = 1000
	// maxDeliverFormField is the largest "recipients" or "from" form value: each holds
	// one address (RFC 5321 §4.5.3.1.3 allows a path 256 octets).
	maxDeliverFormField = 1024
)

// deliverMailReader reads the body of a /admin/mail/deliver request, charging the
// server's delivery memory budget (limits.delivery_memory_limit) for every
// message-sized buffer before it is allocated. The standard parsers cannot do that:
// ParseMultipartForm and json.Decoder buffer the body in buffers of their own, and
// encoding/json builds the message string through a second one.
//
// What it charged and still holds is in held; the handler frees it (release) when
// the request ends, on every path.
type deliverMailReader struct {
	budget *server.SessionMemoryTracker
	held   int64
}

// charge charges n bytes about to be allocated.
func (d *deliverMailReader) charge(n int64) error {
	if d.budget == nil {
		return nil
	}
	if err := d.budget.Allocate(n); err != nil {
		return fmt.Errorf("%w: %v", server.ErrMemoryBudgetExhausted, err)
	}
	d.held += n
	return nil
}

// free gives back n bytes charged for a buffer that is no longer referenced.
func (d *deliverMailReader) free(n int64) {
	if d.budget != nil && n > 0 {
		d.budget.Free(n)
		d.held -= n
	}
}

// release gives back everything still held.
func (d *deliverMailReader) release() { d.free(d.held) }

// readAll reads src into a buffer charged before it grows (server.ReadAllCharged).
// It returns what the buffer is charged, for a caller that drops it early.
func (d *deliverMailReader) readAll(src io.Reader) ([]byte, int64, error) {
	data, charged, err := server.ReadAllCharged(src, d.budget)
	d.held += charged
	return data, charged, err
}

// multipart reads a multipart/form-data request from the stream, part by part:
//
//   - "message", as a form value or as a file upload, is read straight into its own
//     charged buffer. A form value wins over a file and the first of each counts,
//     wherever they are in the body, as with http.Request.ParseMultipartForm; a
//     message that loses is not read, or is dropped and its charge freed.
//   - "recipients" (each value one recipient) and "from" (the first value) are form
//     values of at most maxDeliverFormField bytes.
//   - Every other part is skipped without being read into memory.
//
// A body that cannot be parsed, is cut short, is over the size limit or has more
// than maxDeliverFormParts parts is a deliverRequestError.
func (d *deliverMailReader) multipart(r *http.Request) (DeliverMailRequest, []byte, error) {
	const malformed = deliverRequestError("Failed to parse multipart form")
	var req DeliverMailRequest
	mr, err := r.MultipartReader()
	if err != nil {
		return req, nil, malformed
	}

	var value, file []byte
	var haveValue, haveFile, haveFrom bool
	var fileCharged int64
	var field [maxDeliverFormField + 1]byte
	for parts := 0; ; parts++ {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil || parts >= maxDeliverFormParts {
			return req, nil, malformed
		}
		name, isFile := part.FormName(), part.FileName() != ""

		switch {
		case name == "message" && !isFile && !haveValue:
			if value, _, err = d.readAll(part); err != nil {
				return req, nil, multipartReadError(err, malformed)
			}
			haveValue = true
			// The form value wins: a file read before it is not the message.
			file = nil
			d.free(fileCharged)
			fileCharged = 0

		case name == "message" && isFile && !haveFile && !haveValue:
			if file, fileCharged, err = d.readAll(part); err != nil {
				return req, nil, multipartReadError(err, malformed)
			}
			haveFile = true

		case (name == "recipients" || name == "from") && !isFile:
			// Read into a fixed buffer; the string is charged before it is made.
			n := 0
			for n < len(field) {
				m, err := part.Read(field[n:])
				n += m
				if err == io.EOF {
					break
				}
				if err != nil {
					return req, nil, malformed
				}
			}
			if n > maxDeliverFormField {
				return req, nil, deliverRequestError(fmt.Sprintf("Form field %q is longer than %d bytes", name, maxDeliverFormField))
			}
			if name == "from" && haveFrom {
				continue
			}
			if err := d.charge(int64(n)); err != nil {
				return req, nil, err
			}
			if name == "from" {
				req.From, haveFrom = string(field[:n]), true
			} else {
				req.Recipients = append(req.Recipients, string(field[:n]))
			}
		}
		// NextPart discards whatever of this part was not read.
	}
	if haveValue {
		return req, value, nil
	}
	return req, file, nil
}

// multipartReadError is the error for a message part that could not be read: the
// budget's refusal as it is, anything else (a truncated upload must not be delivered
// as if it were the message) as the malformed-request error.
func multipartReadError(err error, malformed deliverRequestError) error {
	if errors.Is(err, server.ErrMemoryBudgetExhausted) {
		return err
	}
	return malformed
}

// json reads a JSON request. The body is read into a charged buffer and decoded in
// place; the "message" string is decoded straight into the bytes delivered, charged
// before they are allocated (jsonMessage). Everything else is decoded by
// encoding/json as before: the other fields, unknown fields (ignored), and, like
// json.Decoder.Decode, only the first JSON value of the body. The body's buffer is
// freed once decoded.
func (d *deliverMailReader) json(body io.Reader) (DeliverMailRequest, []byte, error) {
	const invalid = deliverRequestError("Invalid JSON")
	data, charged, err := d.readAll(body)
	if errors.Is(err, server.ErrMemoryBudgetExhausted) {
		return DeliverMailRequest{}, nil, err
	}
	if err != nil {
		return DeliverMailRequest{}, nil, invalid
	}

	var decoded struct {
		DeliverMailRequest
		// Shadows DeliverMailRequest.Message, which stays empty.
		Message jsonMessage `json:"message"`
	}
	decoded.Message.reader = d
	if err := json.Unmarshal(firstJSONValue(data), &decoded); err != nil {
		if errors.Is(err, server.ErrMemoryBudgetExhausted) {
			return DeliverMailRequest{}, nil, err
		}
		return DeliverMailRequest{}, nil, invalid
	}
	// Nothing decoded refers to the body: strings are copies, and so is the message.
	d.free(charged)
	return decoded.DeliverMailRequest, decoded.Message.data, nil
}

// firstJSONValue returns the part of data that json.Decoder.Decode would decode into
// a struct and succeed: a first top-level object up to its closing brace, or a
// top-level null, whatever follows it (Decode stops at the end of the first value;
// json.Unmarshal refuses anything after it). For any other input it returns data,
// which json.Unmarshal then refuses, as Decode does.
func firstJSONValue(data []byte) []byte {
	i := 0
	for i < len(data) && isJSONSpace(data[i]) {
		i++
	}
	if i == len(data) {
		return data
	}
	if data[i] != '{' {
		if end := i + len("null"); end <= len(data) && string(data[i:end]) == "null" {
			return data[:end]
		}
		return data
	}
	depth, inString := 0, false
	for ; i < len(data); i++ {
		switch c := data[i]; {
		case inString && c == '\\':
			i++ // the escaped character, a quote included
		case c == '"':
			inString = !inString
		case inString:
		case c == '{':
			depth++
		case c == '}':
			if depth--; depth == 0 {
				return data[:i+1]
			}
		}
	}
	return data
}

func isJSONSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// jsonMessage is the "message" string of a JSON delivery request, decoded into one
// []byte of exactly its size, charged to reader before it is allocated.
// encoding/json would unquote the string into a buffer of its own, copy that into a
// string, and delivery would copy the string into a []byte: three message-sized
// allocations where one will do.
//
// It decodes exactly as encoding/json decodes a JSON string into a Go string
// (TestJSONMessageMatchesEncodingJSON, FuzzJSONMessage): the same escapes, a \u
// escape of an unpaired surrogate as U+FFFD, and each byte of invalid UTF-8 as
// U+FFFD. Like a string field, null leaves it as it is, another JSON type is an
// error, and when the key repeats the last value counts.
type jsonMessage struct {
	data    []byte
	charged int64
	reader  *deliverMailReader
}

var errJSONMessageNotString = errors.New("message must be a JSON string")

// UnmarshalJSON decodes raw, one complete JSON value whose syntax encoding/json has
// checked.
func (m *jsonMessage) UnmarshalJSON(raw []byte) error {
	if string(raw) == "null" {
		return nil
	}
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return errJSONMessageNotString
	}
	s := raw[1 : len(raw)-1]
	// A first pass sizes the decoded message, so it is charged in full, and exactly,
	// before it is allocated. A message decoded for an earlier "message" key stays
	// charged until this one has replaced it.
	size, ok := unquoteJSONString(nil, s)
	if !ok {
		return errJSONMessageNotString
	}
	if m.reader != nil {
		if err := m.reader.charge(int64(size)); err != nil {
			return err
		}
	}
	out := make([]byte, size)
	unquoteJSONString(out, s)
	if m.reader != nil {
		m.reader.free(m.charged)
	}
	m.data, m.charged = out, int64(size)
	return nil
}

// unquoteJSONString decodes s, the inside of a JSON string, as encoding/json's
// unquote does, and returns the decoded length. With a nil dst it only measures;
// otherwise it writes into dst, which must have that length. ok is false for an
// escape JSON does not have, which checked input never holds.
func unquoteJSONString(dst, s []byte) (n int, ok bool) {
	put := func(b byte) {
		if dst != nil {
			dst[n] = b
		}
		n++
	}
	putRune := func(r rune) {
		if dst != nil {
			utf8.EncodeRune(dst[n:], r)
		}
		n += utf8.RuneLen(r)
	}
	for i := 0; i < len(s); {
		// Most of a message is plain ASCII: copy each run of it in one piece.
		j := i
		for j < len(s) && s[j] != '\\' && s[j] < utf8.RuneSelf {
			j++
		}
		if j > i {
			if dst != nil {
				copy(dst[n:], s[i:j])
			}
			n += j - i
			i = j
			continue
		}
		c := s[i]
		switch {
		case c == '\\':
			if i+1 >= len(s) {
				return n, false
			}
			switch s[i+1] {
			case '"', '\\', '/', '\'':
				put(s[i+1])
			case 'b':
				put('\b')
			case 'f':
				put('\f')
			case 'n':
				put('\n')
			case 'r':
				put('\r')
			case 't':
				put('\t')
			case 'u':
				r := jsonHex4(s[i:])
				if r < 0 {
					return n, false
				}
				i += 6
				if utf16.IsSurrogate(r) {
					if dec := utf16.DecodeRune(r, jsonHex4(s[i:])); dec != unicode.ReplacementChar {
						// A valid pair; consume the second escape too.
						i += 6
						putRune(dec)
						continue
					}
					// An unpaired surrogate: U+FFFD, and what follows is decoded by itself.
					r = unicode.ReplacementChar
				}
				putRune(r)
				continue
			default:
				return n, false
			}
			i += 2
		default:
			// Invalid UTF-8 is one byte decoded as U+FFFD, as in encoding/json.
			r, size := utf8.DecodeRune(s[i:])
			putRune(r)
			i += size
		}
	}
	return n, true
}

// jsonHex4 is the code unit of the \uXXXX escape s starts with, or -1 if it does not
// start with one.
func jsonHex4(s []byte) rune {
	if len(s) < 6 || s[0] != '\\' || s[1] != 'u' {
		return -1
	}
	var r rune
	for _, c := range s[2:6] {
		switch {
		case '0' <= c && c <= '9':
			c -= '0'
		case 'a' <= c && c <= 'f':
			c = c - 'a' + 10
		case 'A' <= c && c <= 'F':
			c = c - 'A' + 10
		default:
			return -1
		}
		r = r*16 + rune(c)
	}
	return r
}
