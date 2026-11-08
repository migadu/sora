package db

import (
	"slices"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/helpers"
)

// WithAttachmentKeyword returns the flags to store for the raw message data,
// with the RFC 9979 §4 attachment keyword set by the server
// (see helpers.AttachmentKeyword).
//
// On delivery (override), a known server result replaces any attachment keyword
// a Sieve script set: RFC 9979 §4 has the server set it "during message
// delivery". On APPEND (!override) the client's own keyword is kept, and the
// server only fills in one when the client set neither, or both, which §4
// forbids. A message never keeps both.
//
// The keyword is only added while the message has room under
// MaxCustomKeywordsPerMessage, so it never pushes out a keyword the client or
// script set, and never turns an APPEND into a [LIMIT] refusal.
func WithAttachmentKeyword(flags []imap.Flag, data []byte, override bool) []imap.Flag {
	has := slices.ContainsFunc(flags, isHasAttachmentKeyword)
	hasNo := slices.ContainsFunc(flags, isHasNoAttachmentKeyword)
	keyword, known := helpers.AttachmentKeyword(data)

	if known && (override || has == hasNo) {
		flags = slices.DeleteFunc(slices.Clone(flags), isAttachmentKeyword)
		if DistinctKeywordCount(flags) < MaxCustomKeywordsPerMessage {
			flags = append(flags, keyword)
		}
		return flags
	}
	if has && hasNo {
		return slices.DeleteFunc(slices.Clone(flags), isAttachmentKeyword)
	}
	return flags
}

// hasAttachmentsFromKeywords is DBMessage.HasAttachments for a message with
// keywords kw. A message carrying both keywords, which RFC 9979 §4 forbids
// but a client may still have set, is reported as unknown.
func hasAttachmentsFromKeywords(kw []string) *bool {
	flags := helpers.StringsToFlags(kw)
	has := slices.ContainsFunc(flags, isHasAttachmentKeyword)
	hasNo := slices.ContainsFunc(flags, isHasNoAttachmentKeyword)
	if has == hasNo {
		return nil
	}
	return &has
}

func isHasAttachmentKeyword(f imap.Flag) bool {
	return strings.EqualFold(string(f), string(helpers.KeywordHasAttachment))
}

func isHasNoAttachmentKeyword(f imap.Flag) bool {
	return strings.EqualFold(string(f), string(helpers.KeywordHasNoAttachment))
}

func isAttachmentKeyword(f imap.Flag) bool {
	return isHasAttachmentKeyword(f) || isHasNoAttachmentKeyword(f)
}
