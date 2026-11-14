package helpers

import "strings"

// MaxReferencesBytes bounds messages."references". The column is in no index, so the
// bound only keeps a pathological header from bloating the row; at 60-70 bytes per ID it
// holds about 30 of them.
const MaxReferencesBytes = 2000

// TrimReferences joins the message IDs of a References field with single spaces, the
// form messages."references" stores, in at most maxBytes bytes.
//
// A References field grows by one ID per reply, the parent's last (RFC 5322 §3.6.4), and
// RFC 5256 §2.2 links a message to its last reference, so when the list does not fit,
// whole IDs are dropped from the middle: the first ID (the thread's root) and as many of
// the last ones as fit are kept, which is how RFC 5537 §3.4.4 trims References. Should
// the first and the parent not fit together, the parent is kept. No ID is ever cut: a
// partial one would match no message and link the message to a dummy.
func TrimReferences(ids []string, maxBytes int) string {
	kept := make([]string, 0, len(ids))
	size := -1 // the joined length: every ID plus a space between each two
	for _, id := range ids {
		if id = SanitizeUTF8(id); id != "" {
			kept = append(kept, id)
			size += len(id) + 1
		}
	}
	if size <= maxBytes {
		return strings.Join(kept, " ")
	}

	// tail returns where the longest run of IDs at the end of kept that joins to at
	// most limit bytes starts.
	tail := func(limit int) int {
		i, n := len(kept), -1
		for i > 0 && n+1+len(kept[i-1]) <= limit {
			i--
			n += 1 + len(kept[i])
		}
		return i
	}
	// With the first ID's bytes set aside, the run cannot reach back to it: the whole
	// list is over the bound.
	if i := tail(maxBytes - len(kept[0]) - 1); i < len(kept) {
		return kept[0] + " " + strings.Join(kept[i:], " ")
	}
	return strings.Join(kept[tail(maxBytes):], " ")
}
