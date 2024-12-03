package helpers

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-message"
	"github.com/k3a/html2text"
)

// extractPart traverses the MIME structure of the message and extracts the requested part.
func ExtractPart(msg *message.Entity, partNum int) (*message.Entity, error) {
	// If partNum is 0 or 1 for a non-multipart message, return the whole message
	if partNum <= 1 {
		mediaType, _, _ := msg.Header.ContentType()
		if !strings.HasPrefix(mediaType, "multipart/") {
			return msg, nil
		}
	}

	mr := msg.MultipartReader()
	if mr == nil {
		return nil, fmt.Errorf("message is not multipart")
	}

	for i := 1; ; i++ {
		p, err := mr.NextPart()
		if err == io.EOF {
			return nil, fmt.Errorf("part %d not found", partNum)
		}
		if err != nil {
			return nil, err
		}

		if i == partNum {
			return p, nil
		}

		// If this part is also multipart, recurse into it
		if mediaType, _, _ := p.Header.ContentType(); strings.HasPrefix(mediaType, "multipart/") {
			nestedPart, err := ExtractPart(p, 1)
			if err == nil {
				return nestedPart, nil
			}
			// If we couldn't extract a nested part, continue to the next part
		}
	}
}

func ExtractBodyStructure(msg *message.Entity, buf *bytes.Buffer, extended bool) (imap.BodyStructure, *string, error) {
	if msg == nil {
		return nil, nil, fmt.Errorf("nil message entity")
	}
	if buf == nil {
		return nil, nil, fmt.Errorf("nil buffer")
	}
	var plaintextBody *string
	var htmlBody *string
	var bodyStructure imap.BodyStructure

	var extractContent func(*message.Entity) ([]imap.BodyStructure, error)
	extractContent = func(entity *message.Entity) ([]imap.BodyStructure, error) {
		mediaType, params, err := entity.Header.ContentType()
		if err != nil {
			return nil, fmt.Errorf("error getting content type: %v", err)
		}

		if strings.HasPrefix(mediaType, "multipart/") {
			mr := entity.MultipartReader()
			if mr == nil {
				return nil, fmt.Errorf("nil multipart reader for multipart content type")
			}

			var children []imap.BodyStructure
			for {
				part, err := mr.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					return nil, fmt.Errorf("error reading multipart: %v", err)
				}
				childStructures, err := extractContent(part)
				if err != nil {
					return nil, err
				}
				children = append(children, childStructures...)
			}
			return children, nil
		} else {
			content, err := io.ReadAll(entity.Body)
			if err != nil {
				return nil, fmt.Errorf("error reading entity body: %v", err)
			}

			switch mediaType {
			case "text/plain":
				if plaintextBody == nil {
					s := string(content)
					plaintextBody = &s
				}
			case "text/html":
				if htmlBody == nil {
					s := string(content)
					htmlBody = &s
				}
			}

			singlePart := &imap.BodyStructureSinglePart{
				Type:     strings.Split(mediaType, "/")[0],
				Subtype:  strings.Split(mediaType, "/")[1],
				Params:   params,
				Size:     uint32(len(content)),
				Encoding: entity.Header.Get("Content-Transfer-Encoding"),
			}
			if extended {
				singlePart.Extended = &imap.BodyStructureSinglePartExt{
					Disposition: extractDisposition(entity),
					Language:    strings.Split(entity.Header.Get("Content-Language"), ","),
					Location:    entity.Header.Get("Content-Location"),
				}
			}
			return []imap.BodyStructure{singlePart}, nil
		}
	}

	children, err := extractContent(msg)
	if err != nil {
		return nil, nil, err
	}

	// Construct the body structure
	mediaType, params, _ := msg.Header.ContentType()
	if strings.HasPrefix(mediaType, "multipart/") {
		multipart := &imap.BodyStructureMultiPart{
			Subtype:  strings.TrimPrefix(mediaType, "multipart/"),
			Children: children,
		}
		if extended {
			multipart.Extended = &imap.BodyStructureMultiPartExt{
				Params:      params,
				Disposition: extractDisposition(msg),
				Language:    strings.Split(msg.Header.Get("Content-Language"), ","),
				Location:    msg.Header.Get("Content-Location"),
			}
		}
		bodyStructure = multipart
	} else {
		// If it's not multipart, we should have exactly one child
		if len(children) == 1 {
			bodyStructure = children[0]
		} else {
			return nil, nil, fmt.Errorf("expected 1 child for non-multipart message, got %d", len(children))
		}
	}

	// If we don't have a plaintext body but we have an HTML body, convert it to plaintext
	if plaintextBody == nil && htmlBody != nil {
		plaintext := html2text.HTML2Text(*htmlBody)
		plaintextBody = &plaintext
	}

	return bodyStructure, plaintextBody, nil
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
