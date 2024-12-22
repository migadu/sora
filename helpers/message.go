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
			if plaintextBody == nil {
				plaintextBody = &s
			}
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

// Helper function to extract content disposition
func extractDisposition(msg *message.Entity) *imap.BodyStructureDisposition {
	disposition, params, _ := msg.Header.ContentDisposition()
	if disposition != "" {
		return &imap.BodyStructureDisposition{
			Value:  disposition,
			Params: params,
		}
	}
	return nil
}

// // Helper function to parse the media type into its type and subtype components
// func parseMediaType(mediaType string) (string, string) {
// 	parts := strings.SplitN(mediaType, "/", 2)
// 	if len(parts) != 2 {
// 		return mediaType, "" // Return as-is if there's no subtype
// 	}
// 	return parts[0], parts[1]
// }

// func calculateNumLines(r io.Reader) int64 {
// 	var numLines int64
// 	scanner := bufio.NewScanner(r)
// 	for scanner.Scan() {
// 		numLines++
// 	}
// 	return numLines
// }

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
