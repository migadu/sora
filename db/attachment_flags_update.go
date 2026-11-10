package db

import (
	"slices"
	"strings"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/helpers"
)

// NormalizeAttachmentKeywordUpdate applies RFC 9979's mutually exclusive
// attachment keywords to the proposed result of a flag update. A requested
// single keyword replaces its opposite; requesting both clears both, as for
// ingestion with an undecidable structure. The input slices are not mutated.
// STORE uses this before its keyword-cap check; DB writers enforce the same
// removals atomically when merging into the current message state.
func NormalizeAttachmentKeywordUpdate(resulting, requested []imap.Flag) []imap.Flag {
	remove := attachmentKeywordRemovals(requested)
	if len(remove) == 0 {
		return resulting
	}
	return slices.DeleteFunc(slices.Clone(resulting), func(flag imap.Flag) bool {
		return slices.Contains(remove, strings.ToLower(string(flag)))
	})
}

func attachmentKeywordRemovals(requested []imap.Flag) []string {
	has := slices.ContainsFunc(requested, isHasAttachmentKeyword)
	hasNo := slices.ContainsFunc(requested, isHasNoAttachmentKeyword)
	remove := make([]string, 0, 2)
	if has {
		remove = append(remove, string(helpers.KeywordHasNoAttachment))
	}
	if hasNo {
		remove = append(remove, string(helpers.KeywordHasAttachment))
	}
	return remove
}
