package helpers

import (
	"strings"

	"github.com/emersion/go-imap/v2"
)

// The RFC 9979 §4 attachment keywords. They are mutually exclusive, and the
// server sets one during delivery; $hasnoattachment records that the message
// was checked and has none, so a message with neither was never checked.
const (
	KeywordHasAttachment   imap.Flag = "$hasattachment"
	KeywordHasNoAttachment imap.Flag = "$hasnoattachment"
)

// AttachmentKeyword returns the RFC 9979 §4 keyword for a message with body
// structure bs, or false when the structure cannot tell: it is missing or
// malformed, or the content is encrypted (multipart/encrypted, S/MIME
// application/pkcs7-mime), so the server never sees the parts inside.
//
// A part is an attachment when it is a leaf part that:
//   - has Content-Disposition: attachment, or
//   - has a filename (Content-Disposition filename, else Content-Type name),
//     outside multipart/related. That counts Apple Mail's inline-disposition
//     attachments and older mailers' name-only ones, but not the images an HTML
//     body embeds by Content-ID, or
//   - is a message/rfc822 or message/global part (a forwarded message).
//
// Signature parts (S/MIME and OpenPGP) are never attachments, though mailers
// often give them a disposition and a filename such as smime.p7s.
func AttachmentKeyword(bs imap.BodyStructure) (imap.Flag, bool) {
	if bs == nil || ValidateBodyStructure(&bs) != nil {
		return "", false
	}
	switch hasAttachment(bs, false) {
	case attachmentFound:
		return KeywordHasAttachment, true
	case attachmentNone:
		return KeywordHasNoAttachment, true
	default:
		return "", false
	}
}

type attachmentResult int

const (
	attachmentNone attachmentResult = iota
	attachmentUnknown
	attachmentFound
)

func hasAttachment(bs imap.BodyStructure, inRelated bool) attachmentResult {
	switch part := bs.(type) {
	case *imap.BodyStructureMultiPart:
		subtype := strings.ToLower(part.Subtype)
		if subtype == "encrypted" {
			return attachmentUnknown
		}
		inRelated = inRelated || subtype == "related"
		result := attachmentNone
		for _, child := range part.Children {
			switch hasAttachment(child, inRelated) {
			case attachmentFound:
				// A found attachment settles it, even next to an unreadable part.
				return attachmentFound
			case attachmentUnknown:
				result = attachmentUnknown
			}
		}
		return result
	case *imap.BodyStructureSinglePart:
		switch part.MediaType() {
		case "application/pkcs7-signature", "application/x-pkcs7-signature", "application/pgp-signature":
			return attachmentNone
		case "application/pkcs7-mime", "application/x-pkcs7-mime":
			return attachmentUnknown
		case "message/rfc822", "message/global":
			return attachmentFound
		}
		if d := part.Disposition(); d != nil && strings.EqualFold(d.Value, "attachment") {
			return attachmentFound
		}
		if !inRelated && part.Filename() != "" {
			return attachmentFound
		}
		return attachmentNone
	default:
		return attachmentUnknown
	}
}
