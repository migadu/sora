package helpers

import "github.com/emersion/go-imap/v2"

// The RFC 9979 §4 attachment keywords. They are mutually exclusive, and the
// server sets one during delivery; $hasnoattachment records that the message
// was checked and has none. Neither keyword means the status is unknown.
const (
	KeywordHasAttachment   imap.Flag = "$hasattachment"
	KeywordHasNoAttachment imap.Flag = "$hasnoattachment"
)

// AttachmentKeyword returns the RFC 9979 §4 keyword for the raw message, or
// false when its attachment status is unknown. A found attachment settles the
// answer even next to an unreadable part; absence requires a complete MIME walk.
// Raw headers retain the RFC 2231 charset and continuation information needed
// to interpret filenames, and synthetic BODYSTRUCTURE children cannot establish
// attachment absence.
//
// A part is an attachment when it:
//   - has Content-Disposition: attachment or an unrecognized disposition type
//     (RFC 2183 §2.8), or
//   - has a filename (Content-Disposition filename, else Content-Type name),
//     outside multipart/related. That counts Apple Mail's inline-disposition
//     attachments and older mailers' name-only ones, but not the images an HTML
//     body embeds by Content-ID, or
//   - is a message/rfc822 or message/global part (a forwarded message).
//
// Signature parts (S/MIME and OpenPGP) are never attachments, though mailers
// often give them a disposition and a filename such as smime.p7s.
func AttachmentKeyword(data []byte) (imap.Flag, bool) {
	switch attachmentInMessage(data) {
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
