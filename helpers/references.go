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
// THREAD=REFERENCES links a message to its last reference (RFC 5256 §3, BASE.6.4.THREAD,
// step 1(B)), so when the list does not fit, whole IDs are dropped from the middle: the
// first ID (the thread's root) and as many of the last ones as fit are kept. This uses
// the middle-removal approach of the Netnews rule in RFC 5537 §3.4.4; the database bound
// can prevent retaining all three IDs that rule requires (the first and last two).
// Should the first and the parent not fit together, the parent is kept. No ID is ever
// cut: a partial one would match no message and link the message to a dummy. Only the
// derived database value is bounded; the message's original header is unchanged.
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

// SplitMessageIDs splits a stored message_id, in_reply_to or "references" value into
// its ids. The columns join ids with single ASCII spaces, and that space is the only
// separator: go-message keeps the quoting an obsolete local part needs (RFC 5322
// §3.6.4 obs-id-left), so a quoted string opening an id may hold spaces
// (`"foo bar"@example.com`), and an id may hold '<', '>' or '"' in a domain literal
// and any non-ASCII rune, NBSP included, outside quotes. A quote that never closes is
// an ordinary character. db.msgIDListExpr is the same rule in SQL; keep the two in
// step.
func SplitMessageIDs(s string) []string {
	ids := []string{}
	for i := 0; i < len(s); {
		if s[i] == ' ' {
			i++
			continue
		}
		start := i
		if s[i] == '"' {
			if end := quotedStringEnd(s, i); end > 0 {
				i = end
			}
		}
		for i < len(s) && s[i] != ' ' {
			i++
		}
		ids = append(ids, s[start:i])
	}
	return ids
}

// quotedStringEnd returns the index just past the quoted string opening at s[i], or 0
// when the quote never closes. A backslash quotes the next byte (RFC 5322 §3.2.1).
func quotedStringEnd(s string, i int) int {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
	return 0
}
