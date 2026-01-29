package helpers

import (
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/k3a/html2text"
	"lukechampine.com/blake3"
)

func ExtractPlaintextBody(msg *message.Entity) (*string, error) {
	if msg == nil {
		return nil, fmt.Errorf("nil message entity")
	}

	mr := mail.NewReader(msg)
	defer mr.Close()

	var plaintextBody, htmlBody *string
	for plaintextBody == nil {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to get next mail part: %v", err)
		}

		header, ok := part.Header.(*mail.InlineHeader)
		if !ok {
			continue
		}

		mediaType, _, err := header.ContentType()
		if err != nil {
			return nil, fmt.Errorf("failed to get mail part Content-Type: %v", err)
		} else if mediaType != "text/plain" && mediaType != "text/html" {
			continue
		}

		b, err := io.ReadAll(part.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read inline part: %v", err)
		}
		s := string(b)

		switch mediaType {
		case "text/plain":
			plaintextBody = &s
		case "text/html":
			if htmlBody == nil {
				htmlBody = &s
			}
		}
	}

	// If we don't have a plaintext body but we have an HTML body, convert it to plaintext
	if plaintextBody == nil && htmlBody != nil {
		plaintext := html2text.HTML2Text(*htmlBody)
		plaintextBody = &plaintext
	}

	return plaintextBody, nil
}

// decodeToBinary decodes the MIME-encoded content (e.g., Base64, Quoted-Printable) into raw binary.
func DecodeToBinary(part *message.Entity) (io.Reader, error) {
	// Get the Content-Transfer-Encoding from the headers
	encodingType := strings.ToLower(part.Header.Get("Content-Transfer-Encoding"))

	// Based on the encoding type, decode the content
	switch encodingType {
	case "base64":
		// Decode base64 content
		return base64.NewDecoder(base64.StdEncoding, part.Body), nil
	case "quoted-printable":
		// Decode quoted-printable content
		return quotedprintable.NewReader(part.Body), nil
	case "7bit", "8bit", "binary":
		// For these encodings, no decoding is necessary; return the body directly
		return part.Body, nil
	default:
		// Unknown encoding
		return nil, fmt.Errorf("unsupported encoding: %s", encodingType)
	}
}

func HashContent(content []byte) string {
	hash := blake3.Sum256(content)
	return fmt.Sprintf("%x", hash)
}

// ValidateBodyStructure checks if a body structure is valid and returns an error for malformed structures.
// This prevents panics in the IMAP server when serving FETCH BODYSTRUCTURE responses.
func ValidateBodyStructure(bs *imap.BodyStructure) error {
	if bs == nil {
		return nil // nil is handled elsewhere
	}

	switch v := (*bs).(type) {
	case *imap.BodyStructureMultiPart:
		if len(v.Children) == 0 {
			return fmt.Errorf("invalid multipart body structure: no children (subtype=%s)", v.Subtype)
		}
		// Recursively validate children
		for i, child := range v.Children {
			if err := ValidateBodyStructure(&child); err != nil {
				return fmt.Errorf("invalid child %d: %w", i, err)
			}
		}
	case *imap.BodyStructureSinglePart:
		// Check if it contains an embedded message/rfc822
		if v.MessageRFC822 != nil && v.MessageRFC822.BodyStructure != nil {
			childBS := v.MessageRFC822.BodyStructure
			if err := ValidateBodyStructure(&childBS); err != nil {
				return fmt.Errorf("invalid embedded message body structure: %w", err)
			}
		}
	}

	return nil
}
