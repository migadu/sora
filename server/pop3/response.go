package pop3

import (
	"github.com/migadu/sora/db"
)

// computeMaildropStats returns the count and total octet size of the messages in
// the session snapshot that are NOT marked deleted. STAT reports the maildrop as
// this session sees it — a fixed snapshot taken at first access (RFC 1939 §3, §5)
// — so it is derived from the same slice LIST/UIDL/RETR use, never from live
// database totals (which drift and would observe concurrent deliveries).
func computeMaildropStats(messages []db.POP3Message, deleted map[int]bool) (count int, size int64) {
	for i, msg := range messages {
		if !deleted[i] {
			count++
			size += int64(msg.Size)
		}
	}
	return count, size
}
