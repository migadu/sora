package helpers

import "github.com/emersion/go-message"

// HeaderPresenceBit identifies the fixed set of searchable fields recorded by
// migration70. A nil mask is unknown (legacy/old writer), not an absent header.
// Extending this set requires a new knownness/version representation: a clear
// bit in an existing non-nil mask may only describe these fields.
func HeaderPresenceBit(key string) (int16, bool) {
	switch key {
	case "from":
		return 1 << 0, true
	case "to":
		return 1 << 1, true
	case "cc":
		return 1 << 2, true
	case "bcc":
		return 1 << 3, true
	case "sender":
		return 1 << 4, true
	case "reply-to":
		return 1 << 5, true
	case "subject":
		return 1 << 6, true
	case "message-id":
		return 1 << 7, true
	case "in-reply-to":
		return 1 << 8, true
	case "references":
		return 1 << 9, true
	default:
		return 0, false
	}
}

// ExtractHeaderPresence records field existence, independent of whether its
// value is empty, a group, or an invalid address list. Call on the final headers
// that accompany stored bytes, including after Sieve edits. No old body is read.
func ExtractHeaderPresence(header message.Header) *int16 {
	var mask int16
	for _, key := range []string{"from", "to", "cc", "bcc", "sender", "reply-to", "subject", "message-id", "in-reply-to", "references"} {
		if header.Has(key) {
			bit, _ := HeaderPresenceBit(key)
			mask |= bit
		}
	}
	return &mask
}
