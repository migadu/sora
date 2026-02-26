package pop3

import (
	"fmt"

	"github.com/migadu/sora/db"
)

// buildListResponseLines builds the multi-line response body for the LIST command.
// Per RFC 1939 §5, message numbers must remain stable throughout a POP3 session.
// Deleted messages must be skipped, but remaining messages keep their original numbers.
func buildListResponseLines(messages []db.Message, deleted map[int]bool) []string {
	var lines []string
	for i, msg := range messages {
		if !deleted[i] {
			// POP3 message numbers are 1-indexed
			lines = append(lines, fmt.Sprintf("%d %d", i+1, msg.Size))
		}
	}
	return lines
}

// buildUIDLResponseLines builds the multi-line response body for the UIDL command.
// Per RFC 1939 §5, message numbers must remain stable throughout a POP3 session.
// Deleted messages must be skipped, but remaining messages keep their original numbers.
func buildUIDLResponseLines(messages []db.Message, deleted map[int]bool) []string {
	var lines []string
	for i, msg := range messages {
		if !deleted[i] {
			// POP3 message numbers are 1-indexed
			lines = append(lines, fmt.Sprintf("%d %d", i+1, msg.UID))
		}
	}
	return lines
}

// countNonDeletedMessages returns the count of messages not marked as deleted.
func countNonDeletedMessages(messages []db.Message, deleted map[int]bool) int {
	count := 0
	for i := range messages {
		if !deleted[i] {
			count++
		}
	}
	return count
}

// buildSingleListResponse builds the response for a single-message LIST query.
// Per RFC 1939 §5: "LIST msg" returns the scan listing for that message.
// Returns (true, "msgNumber size") on success, or (false, "") if the message
// number is invalid, out of range, or the message is deleted.
func buildSingleListResponse(messages []db.Message, deleted map[int]bool, msgNumber int) (bool, string) {
	if msgNumber < 1 || msgNumber > len(messages) {
		return false, ""
	}
	if deleted[msgNumber-1] {
		return false, ""
	}
	return true, fmt.Sprintf("%d %d", msgNumber, messages[msgNumber-1].Size)
}

// computeDeletedStats returns the count and total size of messages marked as deleted
// in the current session. This is used to adjust STAT results per RFC 1939 §5,
// which requires STAT to reflect the current session state excluding DELE'd messages.
func computeDeletedStats(messages []db.Message, deleted map[int]bool) (count int, size int64) {
	for i, msg := range messages {
		if deleted[i] {
			count++
			size += int64(msg.Size)
		}
	}
	return count, size
}
