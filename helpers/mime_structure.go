package helpers

import (
	"bufio"
	"bytes"
	"io"
	"strings"

	"github.com/emersion/go-message"
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
		reader    *textproto.MultipartReader
		inRelated bool
	}
	var parents []parent
	inRelated, unknown := false, false
	for {
		mimeHeader := message.Header{Header: header}
		mediaType, params, err := mimeHeader.ContentType()
		opaque := false
		switch mediaType {
		case "application/pkcs7-signature", "application/x-pkcs7-signature", "application/pgp-signature":
			// Signature filenames never make the signature an attachment.
			opaque = true
		case "multipart/encrypted", "application/pkcs7-mime", "application/x-pkcs7-mime":
			unknown, opaque = true, true
		case "message/rfc822", "message/global":
			return attachmentFound
		}
		if !opaque {
			if err != nil {
				unknown = true
			}
			if primary, subtype, ok := strings.Cut(mediaType, "/"); !ok || primary == "" || subtype == "" {
				unknown = true
			}
			if mimeHeader.Get("Content-Disposition") != "" {
				disposition, _, err := mimeHeader.ContentDisposition()
				// go-message preserves the disposition type when only its
				// parameters are malformed (e.g. an unquoted filename).
				if strings.EqualFold(disposition, "attachment") {
					return attachmentFound
				}
				if err != nil {
					unknown = true
				}
			}
			if !inRelated {
				for _, field := range []struct{ header, param string }{
					{"Content-Disposition", "filename"}, {"Content-Type", "name"},
				} {
					switch mimeFilename(mimeHeader.Get(field.header), field.param) {
					case attachmentFound:
						return attachmentFound
					case attachmentUnknown:
						unknown = true
					}
				}
			}
			if strings.HasPrefix(mediaType, "multipart/") {
				if params["boundary"] != "" {
					mr := textproto.NewMultipartReader(body, params["boundary"])
					part, err := mr.NextPart()
					if err == nil {
						inRelated = inRelated || mediaType == "multipart/related"
						parents = append(parents, parent{mr, inRelated})
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
			header, body = part.Header, part
			break
		}
	}
}
