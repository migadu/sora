package helpers

import (
	"bufio"
	"bytes"
	"io"
	"strings"

	"github.com/emersion/go-message/textproto"
)

// attachmentInMessage uses raw part readers: classification needs no body
// decoding. An explicit stack avoids recursion for deeply nested multiparts.
func attachmentInMessage(data []byte) attachmentResult {
	if len(data) == 0 {
		return attachmentUnknown
	}
	reader := bufio.NewReader(bytes.NewReader(data))
	header, err := textproto.ReadHeader(reader)
	if err != nil {
		return attachmentUnknown
	}
	var body io.Reader = reader
	type parent struct {
		reader      *textproto.MultipartReader
		inRelated   bool
		defaultType string
	}
	var parents []parent
	inRelated, unknown := false, false
	defaultType := "text/plain"
	for {
		ambiguousType := len(header.Values("Content-Type")) > 1
		ambiguousDisposition := len(header.Values("Content-Disposition")) > 1
		if ambiguousType || ambiguousDisposition {
			unknown = true
		}
		contentType := mimeHeaderValue{value: defaultType, complete: true}
		if header.Has("Content-Type") {
			contentType = parseMIMEHeader(header.Get("Content-Type"), true)
		}
		mediaType := contentType.value
		opaque := ambiguousType
		switch mediaType {
		case "application/pkcs7-signature", "application/x-pkcs7-signature", "application/pgp-signature":
			// Signature filenames never make the signature an attachment.
			opaque = true
		case "multipart/encrypted", "application/pkcs7-mime", "application/x-pkcs7-mime":
			unknown, opaque = true, true
		case "message/rfc822", "message/global":
			if !ambiguousType {
				return attachmentFound
			}
		}
		if !opaque {
			if !contentType.complete {
				unknown = true
			}
			if primary, subtype, ok := strings.Cut(mediaType, "/"); !ok || primary == "" || subtype == "" {
				unknown = true
			}
			disposition := mimeHeaderValue{complete: true}
			if header.Has("Content-Disposition") && !ambiguousDisposition {
				disposition = parseMIMEHeader(header.Get("Content-Disposition"), false)
				// RFC 2183 §2.8 gives unknown disposition types attachment
				// semantics. Only inline suppresses that positive evidence.
				if disposition.value != "" && disposition.value != "inline" {
					return attachmentFound
				}
				if !disposition.complete {
					unknown = true
				}
			}
			if !inRelated {
				for _, field := range []struct {
					header mimeHeaderValue
					param  string
				}{
					{disposition, "filename"}, {contentType, "name"},
				} {
					switch mimeFilename(field.header, field.param) {
					case attachmentFound:
						return attachmentFound
					case attachmentUnknown:
						unknown = true
					}
				}
			}
			if strings.HasPrefix(mediaType, "multipart/") {
				if boundary, ok := contentType.boundary(); ok {
					mr := textproto.NewMultipartReader(body, boundary)
					part, err := mr.NextPart()
					if err == nil {
						inRelated = inRelated || mediaType == "multipart/related"
						// RFC 2046 §5.1.5 changes only direct digest children's
						// default; an explicitly typed nested multipart resets it.
						defaultType = "text/plain"
						if mediaType == "multipart/digest" {
							defaultType = "message/rfc822"
						}
						parents = append(parents, parent{mr, inRelated, defaultType})
						header, body = part.Header, part
						continue
					}
				}
				// Even a clean EOF before the first child is undecidable.
				unknown = true
			}
		}
		if _, err := io.Copy(io.Discard, body); err != nil {
			unknown = true
		}
		for {
			if len(parents) == 0 {
				if unknown {
					return attachmentUnknown
				}
				return attachmentNone
			}
			p := parents[len(parents)-1]
			part, err := p.reader.NextPart()
			if err != nil {
				if err != io.EOF {
					unknown = true
				}
				// A broken nested multipart cannot hide a known attachment
				// in one of its outer siblings. Resume at the parent.
				parents = parents[:len(parents)-1]
				continue
			}
			inRelated = p.inRelated
			defaultType = p.defaultType
			header, body = part.Header, part
			break
		}
	}
}
