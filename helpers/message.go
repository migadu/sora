package helpers

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime/quotedprintable"
	"regexp"
	"strings"

	"github.com/emersion/go-message"
	"github.com/k3a/html2text"
	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"golang.org/x/net/html"
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

const maxFTSMIMEDepth = 32

func ExtractPlaintextBody(msg *message.Entity) (*string, error) {
	if msg == nil {
		return nil, fmt.Errorf("nil message entity")
	}

	type multipartFrame struct {
		reader          message.MultipartReader
		mediaType       string
		relatedStart    string
		hasRelatedStart bool
		relatedRootSeen bool
	}
	var readers []multipartFrame
	defer func() {
		for i := len(readers) - 1; i >= 0; i-- {
			readers[i].reader.Close()
		}
	}()

	var plaintextBody, htmlBody *string
	// Text parts whose Content-Type parameters do not parse, read without
	// their charset: the text of last resort, used only without any
	// well-formed text part.
	var lenientPlain, lenientHTML *string
	var skippedParts []string // Track reasons for skipped parts (for debugging)

	next := msg
	for plaintextBody == nil {
		var part *message.Entity
		var parent *multipartFrame
		var err error
		if next != nil {
			part = next
			next = nil
		} else {
			if len(readers) == 0 {
				break
			}
			parent = &readers[len(readers)-1]
			part, err = parent.reader.NextPart()
			if err == io.EOF {
				parent.reader.Close()
				readers = readers[:len(readers)-1]
				continue
			} else if part != nil && (message.IsUnknownCharset(err) || message.IsUnknownEncoding(err)) {
				// The part still comes with its header (and, for an unknown
				// charset, its transfer-decoded body). Container/disposition
				// rules and the leaf Content-Transfer-Encoding check below
				// handle it uniformly with single-part messages and PREVIEW.
			} else if err != nil {
				// A broken multipart (malformed part header, missing boundary or
				// missing close delimiter) cannot yield more parts of its own, but
				// popping it lets its parent advance to later sibling parts, matching
				// MessagePreview.
				skippedParts = append(skippedParts, fmt.Sprintf("NextPart error: %v", err))
				parent.reader.Close()
				readers = readers[:len(readers)-1]
				continue
			}
		}

		header := part.Header
		relatedRoot := parent != nil && parent.mediaType == "multipart/related"
		if relatedRoot {
			// RFC 2387 §3.2 selects the root by Content-ID when start is
			// present, otherwise by the first child. Other children are
			// resources, not alternative message bodies, even if textual.
			if parent.relatedRootSeen || (parent.hasRelatedStart &&
				(parent.relatedStart == "" || mimeContentID(header.Get("Content-ID")) != parent.relatedStart)) {
				continue
			}
			parent.relatedRootSeen = true
		}

		disp, _, _ := header.ContentDisposition()
		// RFC 2183 §2.8 assigns attachment semantics to unknown dispositions.
		// Fail closed on malformed values too, while retaining a usable inline
		// type when only its parameters were malformed.
		// Related processing takes precedence over its direct children's
		// disposition (RFC 2387 §4). Attachment ancestors remain excluded.
		if !relatedRoot && header.Get("Content-Disposition") != "" && !strings.EqualFold(disp, "inline") {
			continue
		}

		// go-message keeps the media type when only the parameters are
		// malformed. Such a text part is still text (RFC 2045 §5.2 even
		// recommends assuming text/plain for an invalid field), so it is
		// not dropped, but it is read without its charset: a well-formed
		// alternative, if there is one, is the better text.
		mediaType, params, typeErr := header.ContentType()
		if parent != nil && parent.mediaType == "multipart/digest" && header.Get("Content-Type") == "" {
			// RFC 2046 §5.1.5 changes the default for direct digest children.
			mediaType = "message/rfc822"
		}
		if mediaType == "multipart/encrypted" {
			continue
		}
		if strings.HasPrefix(mediaType, "multipart/") {
			if len(readers) < maxFTSMIMEDepth {
				if mr := part.MultipartReader(); mr != nil {
					start, hasStart := params["start"]
					readers = append(readers, multipartFrame{
						reader:          mr,
						mediaType:       mediaType,
						relatedStart:    mimeContentID(start),
						hasRelatedStart: hasStart,
					})
				}
			}
			continue
		}

		// A single-part entity arrives without a NextPart error, and go-message
		// reports only the charset error when both charset and encoding are
		// unknown. Check every leaf so undecoded bytes are never indexed.
		switch transferEncodingMechanism(header.Get("Content-Transfer-Encoding")) {
		case "", "7bit", "8bit", "binary", "quoted-printable", "base64":
		default:
			skippedParts = append(skippedParts, fmt.Sprintf("unsupported Content-Transfer-Encoding: %q", header.Get("Content-Transfer-Encoding")))
			continue
		}

		if mediaType != "text/plain" && mediaType != "text/html" {
			if typeErr != nil {
				skippedParts = append(skippedParts, fmt.Sprintf("invalid Content-Type: %v", typeErr))
			}
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

		switch {
		case typeErr != nil && mediaType == "text/plain":
			if lenientPlain == nil {
				lenientPlain = &s
			}
		case typeErr != nil:
			if lenientHTML == nil {
				lenientHTML = &s
			}
		case mediaType == "text/plain":
			plaintextBody = &s
		case htmlBody == nil:
			htmlBody = &s
		}
	}
	if plaintextBody == nil && htmlBody == nil {
		plaintextBody, htmlBody = lenientPlain, lenientHTML
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

		// html2text mistakes a raw '<' in text for a tag and an apostrophe
		// in an unquoted attribute for the start of a quoted value. Let the
		// HTML5 tokenizer escape text and quote attributes before conversion,
		// preserving the rest of a malformed HTML-only message for FTS.
		z := html.NewTokenizer(strings.NewReader(cleanedHTML))
		var normalized strings.Builder
		for token := z.Next(); token != html.ErrorToken; token = z.Next() {
			normalized.WriteString(z.Token().String())
		}
		plaintext := html2text.HTML2Text(normalized.String())
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
	encodingType := transferEncodingMechanism(part.Header.Get("Content-Transfer-Encoding"))

	// Based on the encoding type, decode the content
	switch encodingType {
	case "base64":
		// Decode base64 content
		return base64.NewDecoder(base64.StdEncoding, part.Body), nil
	case "quoted-printable":
		// Decode quoted-printable content
		return quotedprintable.NewReader(part.Body), nil
	case "", "7bit", "8bit", "binary":
		// For these encodings, no decoding is necessary; return the body directly
		return part.Body, nil
	default:
		// Unknown encoding
		return nil, fmt.Errorf("unsupported encoding: %s", encodingType)
	}
}

// HashContent returns the content hash of a message: the hex BLAKE3-256 digest that names
// its S3 object and is stored as messages.content_hash.
func HashContent(content []byte) string {
	sum := blake3.Sum256(content)
	return fmt.Sprintf("%x", sum)
}

// NewContentHasher returns a streaming HashContent: the hex encoding of its Sum is
// HashContent of the bytes written to it.
func NewContentHasher() hash.Hash {
	return blake3.New(32, nil)
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

// extractOptions reads the Date: of an attached message/rfc822 or message/global part,
// whose envelope the body structure stores, with ParseDateHeaderWithZone like the message's own.
// go-imap's default is net/mail, which reads an obsolete zone such as PDT in time.Local.
var extractOptions = &imapserver.ExtractOptions{ParseDateWithZone: ParseDateHeaderWithZone}

// ExtractBodyStructure is imapserver.ExtractBodyStructure with the envelope dates of
// attached messages read by ParseDateHeader, indirected so tests can exercise
// SafeBodyStructure's recovery path.
var ExtractBodyStructure = func(r io.Reader) imap.BodyStructure {
	return imapserver.ExtractBodyStructureWithOptions(r, extractOptions)
}

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
