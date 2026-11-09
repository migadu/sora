package delivery

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/textproto"
)

// writeVacationMIME preserves the supplied entity's encoded body and Content-*
// headers. Transport headers always come from the generated reply, so :mime
// cannot replace From, To, Subject, Message-ID or auto-response protections.
func writeVacationMIME(w io.Writer, header message.Header, reason string) error {
	entity, err := message.Read(strings.NewReader(reason))
	if err != nil && !message.IsUnknownCharset(err) {
		return fmt.Errorf("invalid vacation MIME entity: %w", err)
	}
	// Validate decoded content before consuming the suppression window or handing
	// the reply to the relay. The original encoded octets are copied below: MIME
	// charsets, transfer encodings and multipart boundaries need no conversion.
	if err := validateVacationMIME(entity, 0); err != nil {
		return fmt.Errorf("invalid vacation MIME entity: %w", err)
	}

	reader := bufio.NewReader(strings.NewReader(reason))
	mimeHeader, err := textproto.ReadHeader(reader)
	if err != nil {
		return fmt.Errorf("invalid vacation MIME header: %w", err)
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

func validateVacationMIME(part *message.Entity, depth int) error {
	if depth > 64 {
		return fmt.Errorf("vacation MIME nesting deeper than 64 levels")
	}
	for _, name := range []string{"Content-Type", "Content-Transfer-Encoding", "MIME-Version"} {
		if len(part.Header.Values(name)) > 1 {
			return fmt.Errorf("duplicate %s", name)
		}
	}
	// Child headers are copied verbatim as part of the encoded multipart body.
	// RFC 2046 §5.1.1 requires ASCII even for headers of 8bit/binary body parts.
	fields := part.Header.Fields()
	for fields.Next() {
		for _, b := range []byte(fields.Value()) {
			if (b < 0x20 && b != '\t') || b >= 0x7f {
				return fmt.Errorf("invalid byte in vacation MIME header %s", fields.Key())
			}
		}
	}
	// An unknown charset can hide go-message's unknown-encoding error, so
	// validate the transfer encoding independently before accepting that error.
	encoding := strings.ToLower(part.Header.Get("Content-Transfer-Encoding"))
	switch encoding {
	case "", "7bit", "8bit", "binary", "quoted-printable", "base64":
	default:
		return fmt.Errorf("unsupported transfer encoding %q", encoding)
	}
	mediaType, params, err := part.Header.ContentType()
	if err != nil {
		return err
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		if params["boundary"] == "" {
			return fmt.Errorf("multipart entity has no boundary")
		}
		// RFC 2045 §6.4 forbids encoded multipart containers.
		if encoding == "quoted-printable" || encoding == "base64" {
			return fmt.Errorf("invalid multipart transfer encoding %q", encoding)
		}
		reader := part.MultipartReader()
		count := 0
		for {
			child, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil && !message.IsUnknownCharset(err) {
				return err
			}
			if err := validateVacationMIME(child, depth+1); err != nil {
				return err
			}
			count++
		}
		if count == 0 {
			return fmt.Errorf("multipart entity has no body parts")
		}
		return nil
	}
	// Even when the charset is unknown, Body still contains the transfer
	// decoder; consume it to catch malformed base64 or quoted-printable.
	_, err = io.Copy(io.Discard, part.Body)
	return err
}
