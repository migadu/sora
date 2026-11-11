package helpers

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/quotedprintable"
	"regexp"
	"strings"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/k3a/html2text"
	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"lukechampine.com/blake3"
)

// stripBase64DataURIs removes base64-encoded data URIs from HTML to prevent huge plaintext conversions.
// Common in newsletters with embedded images: <img src="data:image/png;base64,iVBORw0KG...">
// Matches base64 strings >= 50 characters (roughly 37+ bytes of data)
var dataURIRegex = regexp.MustCompile(`data:[^;]+;base64,[A-Za-z0-9+/=]{50,}`)

func stripBase64DataURIs(html string) string {
	// Replace long base64 data URIs with a placeholder
	return dataURIRegex.ReplaceAllString(html, "[embedded-image]")
}

func ExtractPlaintextBody(msg *message.Entity) (*string, error) {
	if msg == nil {
		return nil, fmt.Errorf("nil message entity")
	}

	mr := mail.NewReader(msg)
	defer mr.Close()

	var plaintextBody, htmlBody *string
	var skippedParts []string // Track reasons for skipped parts (for debugging)

	for plaintextBody == nil {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			// Once NextPart() fails, the multipart reader cannot yield more parts.
			// Malformed MIME parts (e.g., "Content-Transfer-Encoding: 7bit <center>")
			// cause encoding errors here. Rather than failing the entire extraction,
			// we keep whatever plaintext/HTML we collected from earlier parts.
			// This is acceptable because plaintext extraction is best-effort for FTS.
			skippedParts = append(skippedParts, fmt.Sprintf("NextPart error: %v", err))
			break
		}

		header, ok := part.Header.(*mail.InlineHeader)
		if !ok {
			continue
		}

		mediaType, _, err := header.ContentType()
		if err != nil {
			// Malformed Content-Type header (e.g., invalid media parameters).
			// Skip this part and continue - plaintext extraction is best-effort for FTS.
			skippedParts = append(skippedParts, fmt.Sprintf("invalid Content-Type: %v", err))
			continue
		} else if mediaType != "text/plain" && mediaType != "text/html" {
			continue
		}

		b, err := io.ReadAll(part.Body)
		if err != nil {
			// Malformed MIME part body (e.g., unexpected EOF, truncated data).
			// Skip this part and continue - plaintext extraction is best-effort for FTS.
			skippedParts = append(skippedParts, fmt.Sprintf("read %s part: %v", mediaType, err))
			continue
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
		// Strip base64-encoded data URIs before conversion to avoid massive plaintext
		cleanedHTML := stripBase64DataURIs(*htmlBody)

		// Also truncate extremely large HTML before conversion (>1MB) to prevent resource exhaustion
		const maxHTMLForConversion = 1024 * 1024 // 1 MB
		if len(cleanedHTML) > maxHTMLForConversion {
			cleanedHTML = cleanedHTML[:maxHTMLForConversion]
		}

		plaintext := html2text.HTML2Text(cleanedHTML)
		plaintextBody = &plaintext
	}

	// If we skipped any parts due to errors, return an error with context.
	// The caller can still use the extracted text (partial success) while logging the issues.
	if len(skippedParts) > 0 {
		return plaintextBody, fmt.Errorf("extracted text with %d skipped part(s): %s",
			len(skippedParts), strings.Join(skippedParts, "; "))
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
		// go-imap's writeBodyTypeMpart panics if there are no children.
		// While RFC 2046 technically allows empty multipart (though unusual),
		// we must reject it here because the IMAP server cannot serialize it.
		if len(v.Children) == 0 {
			return fmt.Errorf("multipart structure has no children (go-imap cannot serialize this)")
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

// ExtractBodyStructure is imapserver.ExtractBodyStructure, indirected so tests
// can exercise SafeBodyStructure's recovery path.
var ExtractBodyStructure = imapserver.ExtractBodyStructure

// SafeBodyStructure returns the BODYSTRUCTURE to store for a raw message. Every
// ingestion path (LMTP, APPEND, Admin API delivery) stores one and FETCH later
// serializes it, and a nil or malformed structure panics the FETCH write path,
// so the result is never nil: a panic in the extractor, a nil result or a
// structure that fails ValidateBodyStructure (such as a multipart with no
// children) is replaced by a text/plain fallback. The error says why the
// fallback was used, for the caller to log with its own logger.
func SafeBodyStructure(data []byte) (result imap.BodyStructure, err error) {
	// Named results: a bare recover() leaves an unnamed result at its zero
	// value, the nil this function exists to avoid.
	defer func() {
		if r := recover(); r != nil {
			result, err = fallbackBodyStructure(len(data)), fmt.Errorf("body structure extraction panicked: %v", r)
		}
	}()
	bs := ExtractBodyStructure(bytes.NewReader(data))
	if bs == nil {
		return fallbackBodyStructure(len(data)), errors.New("body structure extraction returned no structure")
	}
	if err := ValidateBodyStructure(&bs); err != nil {
		return fallbackBodyStructure(len(data)), err
	}
	return bs, nil
}

// fallbackBodyStructure stands in for a message whose real structure could not
// be produced. Extended is always populated to match imapserver.ExtractBodyStructure,
// and Text because body-fld-lines is mandatory for a text part (RFC 9051
// body-type-text): without it FETCH emits a structure clients reject outright,
// failing the whole response.
func fallbackBodyStructure(size int) imap.BodyStructure {
	return &imap.BodyStructureSinglePart{
		Type:     "text",
		Subtype:  "plain",
		Params:   map[string]string{"charset": "utf-8"},
		Size:     uint32(size),
		Extended: &imap.BodyStructureSinglePartExt{},
		Text:     &imap.BodyStructureText{},
	}
}
