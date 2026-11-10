package delivery

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"mime"
	"strings"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/textproto"
)

// writeVacationMIME preserves the supplied entity's encoded body and Content-*
// headers. Transport headers always come from the generated reply, so :mime
// cannot replace From, To, Subject, Message-ID or auto-response protections.
func writeVacationMIME(w io.Writer, header message.Header, reason string) error {
	mimeHeader, body, err := readVacationMIMEHeader(strings.NewReader(reason))
	if err != nil {
		return fmt.Errorf("invalid vacation MIME header: %w", err)
	}
	// Validate the encoded source, not go-message's lenient decoders: those
	// repair malformed received mail, but we must not generate invalid MIME.
	if err := validateVacationMIME(message.Header{Header: mimeHeader}, body, "text/plain", 0); err != nil {
		return fmt.Errorf("invalid vacation MIME entity: %w", err)
	}
	// Re-read after validation to preserve the original encoded body verbatim.
	_, reader, err := readVacationMIMEHeader(strings.NewReader(reason))
	if err != nil {
		return err
	}
	fields := mimeHeader.Fields()
	for fields.Next() {
		name, value := fields.Key(), fields.Value()
		if !strings.HasPrefix(strings.ToLower(name), "content-") {
			continue
		}
		header.Add(name, value)
	}
	header.Set("MIME-Version", "1.0")
	if err := textproto.WriteHeader(w, header.Header); err != nil {
		return err
	}
	_, err = io.Copy(w, reader)
	return err
}

// Keep the same 1 MiB header bound as message.Read, including embedded messages.
func readVacationMIMEHeader(r io.Reader) (textproto.Header, io.Reader, error) {
	const limit = 1 << 20
	limited := &io.LimitedReader{R: r, N: limit + 1}
	reader := bufio.NewReader(limited)
	header, err := textproto.ReadHeader(reader)
	if limit+1-limited.N-int64(reader.Buffered()) > limit {
		return header, nil, textproto.ErrHeaderTooBig
	}
	limited.N = math.MaxInt64
	return header, reader, err
}

func validateVacationMIME(header message.Header, body io.Reader, defaultType string, depth int) error {
	if depth > 64 {
		return fmt.Errorf("vacation MIME nesting deeper than 64 levels")
	}
	for _, name := range []string{"Content-Type", "Content-Transfer-Encoding", "MIME-Version"} {
		if len(header.Values(name)) > 1 {
			return fmt.Errorf("duplicate %s", name)
		}
	}
	// Child headers are copied verbatim as part of the encoded multipart body.
	// RFC 2046 §5.1.1 requires ASCII even for headers of 8bit/binary body parts.
	fields := header.Fields()
	for fields.Next() {
		for _, b := range []byte(fields.Value()) {
			if (b < 0x20 && b != '\t') || b >= 0x7f {
				return fmt.Errorf("invalid byte in vacation MIME header %s", fields.Key())
			}
		}
	}
	encoding, err := vacationMIMETokens(header.Get("Content-Transfer-Encoding"))
	if err != nil {
		return err
	}
	encoding = strings.ToLower(encoding)
	switch encoding {
	case "", "7bit", "8bit", "binary", "quoted-printable", "base64":
	default:
		return fmt.Errorf("unsupported transfer encoding %q", encoding)
	}
	contentType := header.Get("Content-Type")
	if !header.Has("Content-Type") {
		contentType = defaultType
	}
	contentType, err = vacationMIMETokens(contentType)
	if err != nil {
		return err
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return err
	}
	// RFC 2046 §§5.2.2–5.2.3 allow only 7bit for partial and external-body
	// containers, regardless of whether a more permissive transport is available.
	if (mediaType == "message/partial" || mediaType == "message/external-body") && encoding != "" && encoding != "7bit" {
		return fmt.Errorf("invalid %s transfer encoding %q", mediaType, encoding)
	}
	// Identity encodings constrain the complete source body, including nested
	// MIME headers, child bodies and multipart preambles/epilogues (§§2.7–2.8).
	if encoding == "" || encoding == "7bit" || encoding == "8bit" {
		body = newVacationMIMELineReader(body, 998, encoding != "8bit")
	}
	if mediaType == "message/rfc822" {
		// RFC 2046 §5.2.1: message/rfc822 containers cannot use an encoding
		// other than 7bit, 8bit or binary. Validate their embedded MIME too.
		if encoding == "quoted-printable" || encoding == "base64" {
			return fmt.Errorf("invalid message/rfc822 transfer encoding %q", encoding)
		}
		embedded, embeddedBody, err := readVacationMIMEHeader(body)
		if err != nil {
			return err
		}
		if !embedded.Has("From") && !embedded.Has("Subject") && !embedded.Has("Date") {
			return fmt.Errorf("message/rfc822 has no From, Subject or Date header")
		}
		return validateVacationMIME(message.Header{Header: embedded}, embeddedBody, "text/plain", depth+1)
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		if !validVacationMIMEBoundary(params["boundary"]) {
			return fmt.Errorf("invalid multipart boundary")
		}
		// RFC 2045 §6.4 forbids encoded multipart containers.
		if encoding == "quoted-printable" || encoding == "base64" {
			return fmt.Errorf("invalid multipart transfer encoding %q", encoding)
		}
		reader := textproto.NewMultipartReader(body, params["boundary"])
		childDefault := "text/plain"
		if mediaType == "multipart/digest" {
			childDefault = "message/rfc822" // RFC 2046 §5.1.5
		}
		count := 0
		for {
			child, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if err := validateVacationMIME(message.Header{Header: child.Header}, child, childDefault, depth+1); err != nil {
				return err
			}
			count++
		}
		if count == 0 {
			return fmt.Errorf("multipart entity has no body parts")
		}
		// NextPart stops at the final boundary. Drain the remaining source so
		// its identity transfer encoding also constrains the epilogue.
		_, err = io.Copy(io.Discard, body)
		return err
	}
	// Charsets do not affect transfer-encoding validity and need no conversion.
	if encoding == "quoted-printable" {
		return validateVacationQuotedPrintable(body)
	}
	if encoding == "base64" {
		// Decoder tolerance for line endings must not permit us to generate
		// bare CR/LF or lines longer than RFC 2045 §6.8's 76 characters.
		body = base64.NewDecoder(base64.StdEncoding, newVacationMIMELineReader(body, 76, true))
	}
	_, err = io.Copy(io.Discard, body)
	return err
}

// RFC 2046 §5.1.1: 1–70 bchars, with no space at the end.
func validVacationMIMEBoundary(boundary string) bool {
	if len(boundary) == 0 || len(boundary) > 70 || boundary[len(boundary)-1] == ' ' {
		return false
	}
	for _, b := range []byte(boundary) {
		if b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || strings.ContainsRune("'()+_,-./:=? ", rune(b)) {
			continue
		}
		return false
	}
	return true
}

// Validate one bounded wire line before exposing any of its original bytes.
// Unlike Scanner, this retains line endings exactly and never buffers a body.
type vacationMIMELineReader struct {
	reader   *bufio.Reader
	maxLine  int
	sevenBit bool
	pending  []byte
	err      error
}

func newVacationMIMELineReader(body io.Reader, maxLine int, sevenBit bool) *vacationMIMELineReader {
	return &vacationMIMELineReader{reader: bufio.NewReaderSize(body, maxLine+3), maxLine: maxLine, sevenBit: sevenBit}
}

func (r *vacationMIMELineReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		line, err := r.reader.ReadSlice('\n')
		if err != nil && err != io.EOF {
			return 0, err
		}
		content := line
		if len(content) > 0 && content[len(content)-1] == '\n' {
			if len(content) < 2 || content[len(content)-2] != '\r' {
				return 0, fmt.Errorf("bare LF in MIME transfer encoding")
			}
			content = content[:len(content)-2]
		}
		if len(content) > r.maxLine {
			return 0, fmt.Errorf("MIME transfer line exceeds %d characters", r.maxLine)
		}
		for _, b := range content {
			if b == 0 || b == '\r' || b == '\n' || r.sevenBit && b >= 128 {
				return 0, fmt.Errorf("invalid byte in MIME transfer encoding")
			}
		}
		r.pending, r.err = line, err
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	if len(r.pending) == 0 {
		return n, r.err
	}
	return n, nil
}

// RFC 2045 §6.7 permits only upper-case hex escapes, soft line breaks,
// printable ASCII and non-trailing space/tab, with at most 76 bytes per line.
func validateVacationQuotedPrintable(body io.Reader) error {
	reader := bufio.NewReader(body)
	for {
		line, err := reader.ReadSlice('\n')
		if err != nil && err != io.EOF {
			return err
		}
		terminated := len(line) >= 2 && line[len(line)-2] == '\r' && line[len(line)-1] == '\n'
		if terminated {
			line = line[:len(line)-2]
		}
		if len(line) > 76 {
			return fmt.Errorf("quoted-printable line exceeds 76 characters")
		}
		for i := 0; i < len(line); i++ {
			b := line[i]
			if b == '=' {
				if i == len(line)-1 && terminated {
					break // Soft line break.
				}
				if i+2 >= len(line) || !isVacationHex(line[i+1]) || !isVacationHex(line[i+2]) {
					return fmt.Errorf("invalid quoted-printable escape")
				}
				i += 2
			} else if b == ' ' || b == '\t' {
				if i == len(line)-1 {
					return fmt.Errorf("trailing quoted-printable whitespace")
				}
			} else if b < 33 || b > 126 {
				return fmt.Errorf("invalid quoted-printable byte")
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}

func isVacationHex(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'F'
}

// RFC 2045 §2 permits RFC 822 comments between MIME header tokens. Remove
// comments and folding whitespace for parsing, retaining quoted strings and
// separation between adjacent tokens. The original headers are still emitted.
func vacationMIMETokens(value string) (string, error) {
	var out strings.Builder
	word := false
	for i := 0; i < len(value); {
		switch value[i] {
		case ' ', '\t':
			i++
		case '(':
			depth := 1
			i++
			for i < len(value) && depth > 0 {
				switch value[i] {
				case '\\':
					i++ // A quoted-pair cannot open or close a comment.
				case '(':
					depth++
				case ')':
					depth--
				}
				i++
			}
			if depth != 0 {
				return "", fmt.Errorf("unterminated MIME header comment")
			}
		case '/', ';', '=':
			out.WriteByte(value[i])
			i++
			word = false
		default:
			start := i
			if value[i] == '"' {
				i++
				closed := false
				for i < len(value) {
					b := value[i]
					i++
					if b == '\\' && i < len(value) {
						i++
					} else if b == '"' {
						closed = true
						break
					}
				}
				if !closed {
					return "", fmt.Errorf("unterminated MIME header quoted string")
				}
			} else {
				for i < len(value) && !strings.ContainsRune(" \t(/;=\"", rune(value[i])) {
					i++
				}
			}
			if word {
				out.WriteByte(' ')
			}
			out.WriteString(value[start:i])
			word = true
		}
	}
	return out.String(), nil
}
