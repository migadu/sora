package pop3

import (
	"testing"

	"github.com/migadu/sora/db"
)

// The session's List/Uidl methods skip deleted entries while preserving
// 1-indexed message numbers (RFC 1939 stable numbering); that behavior is
// covered by the pop3 integration suite. computeMaildropStats is the remaining
// shared helper: STAT must report the session snapshot minus deletions.
func TestComputeMaildropStats(t *testing.T) {
	tests := []struct {
		name          string
		messages      []db.POP3Message
		deleted       map[int]bool
		expectedCount int
		expectedSize  int64
	}{
		{
			name: "no deletions",
			messages: []db.POP3Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
				{Size: 300, UID: 3},
			},
			deleted:       map[int]bool{},
			expectedCount: 3,
			expectedSize:  600,
		},
		{
			name: "one deletion",
			messages: []db.POP3Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
				{Size: 300, UID: 3},
			},
			deleted:       map[int]bool{1: true},
			expectedCount: 2,
			expectedSize:  400, // 100 + 300
		},
		{
			name: "multiple deletions",
			messages: []db.POP3Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
				{Size: 300, UID: 3},
				{Size: 400, UID: 4},
			},
			deleted:       map[int]bool{0: true, 2: true},
			expectedCount: 2,
			expectedSize:  600, // 200 + 400
		},
		{
			name: "all deleted",
			messages: []db.POP3Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
			},
			deleted:       map[int]bool{0: true, 1: true},
			expectedCount: 0,
			expectedSize:  0,
		},
		{
			name:          "empty mailbox",
			messages:      []db.POP3Message{},
			deleted:       map[int]bool{},
			expectedCount: 0,
			expectedSize:  0,
		},
		{
			name:          "nil messages",
			messages:      nil,
			deleted:       map[int]bool{},
			expectedCount: 0,
			expectedSize:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, size := computeMaildropStats(tt.messages, tt.deleted)
			if count != tt.expectedCount {
				t.Errorf("count: expected %d, got %d", tt.expectedCount, count)
			}
			if size != tt.expectedSize {
				t.Errorf("size: expected %d, got %d", tt.expectedSize, size)
			}
		})
	}
}
