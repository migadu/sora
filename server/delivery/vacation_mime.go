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
	err = entity.Walk(func(path []int, part *message.Entity, parseErr error) error {
		if len(path) > 64 {
			return fmt.Errorf("vacation MIME nesting deeper than 64 levels")
		}
		if parseErr != nil && !message.IsUnknownCharset(parseErr) {
			return parseErr
		}
		for _, name := range []string{"Content-Type", "Content-Transfer-Encoding", "MIME-Version"} {
			if len(part.Header.Values(name)) > 1 {
				return fmt.Errorf("duplicate %s", name)
			}
		}
		mediaType, params, err := part.Header.ContentType()
		if err != nil {
			return err
		}
		if strings.HasPrefix(mediaType, "multipart/") {
			if params["boundary"] == "" {
				return fmt.Errorf("multipart entity has no boundary")
			}
			return nil
		}
		_, err = io.Copy(io.Discard, part.Body)
		return err
	})
	if err != nil {
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
		// Copied values go on the wire as-is: only printable ASCII and HT, so a
		// control byte or 8-bit octet cannot ride along in a header the reply sends.
		for _, b := range []byte(value) {
			if (b < 0x20 && b != '\t') || b >= 0x7f {
				return fmt.Errorf("invalid byte in vacation MIME header %s", name)
			}
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
