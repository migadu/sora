package helpers

import (
	"bufio"
	"bytes"
	"io"
	"strings"

	"github.com/emersion/go-message/textproto"
)

// Each multipart reader wraps its parent, so an unbounded reader chain makes
// even an iterative traversal quadratic. Bound the chain independently of the
// message size; classification is optional metadata and can remain unknown.
const maxAttachmentMultipartDepth = 128

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
			primary, subtype, validType := strings.Cut(mediaType, "/")
			validType = validType && primary != "" && subtype != ""
			if !validType {
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
				// RFC 8621 §4.1.4 counts every leaf that is not text/plain,
				// text/html, image, audio or video as an attachment, and RFC
				// 9979 §4.1 ties this keyword to JMAP's hasAttachment. With no
				// Content-Disposition at all the type alone decides, so a bare
				// application/pdf is an attachment. A disposition was judged
				// above: attachment returned, inline is exempt (RFC 8621's
				// hasAttachment), and an unparsable one stays undecided.
				if validType && !header.Has("Content-Disposition") &&
					!strings.HasPrefix(mediaType, "multipart/") && !inlineMediaType(mediaType) {
					return attachmentFound
				}
			}
			if strings.HasPrefix(mediaType, "multipart/") {
				if len(parents) >= maxAttachmentMultipartDepth {
					// Do not drain this subtree to find outer siblings: doing
					// so would still incur the nested-reader amplification.
					return attachmentUnknown
				}
				if boundary, ok := contentType.boundary(); ok {
					mr := textproto.NewMultipartReader(body, boundary)
					part, err := mr.NextPart()
					if err == nil {
						// RFC 2387 relates the direct children only, and RFC
						// 8621 §4.1.4 scopes its related rule the same way.
						inRelated = mediaType == "multipart/related"
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

// inlineMediaType reports the body types RFC 8621 §4.1.4 renders inline. Any
// other leaf type is an attachment unless its disposition says otherwise.
func inlineMediaType(mediaType string) bool {
	return mediaType == "text/plain" || mediaType == "text/html" ||
		strings.HasPrefix(mediaType, "image/") ||
		strings.HasPrefix(mediaType, "audio/") ||
		strings.HasPrefix(mediaType, "video/")
}
