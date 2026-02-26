package pop3

import (
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
)

// TestListResponsePreservesMessageNumbers verifies that LIST preserves original
// message numbers after DELE, per RFC 1939 §5. Deleted messages must be skipped
// but remaining messages must keep their original numbering.
func TestListResponsePreservesMessageNumbers(t *testing.T) {
	tests := []struct {
		name     string
		messages []db.Message
		deleted  map[int]bool
		expected []string // expected lines in the multi-line response body
	}{
		{
			name: "no deletions",
			messages: []db.Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
				{Size: 300, UID: 3},
			},
			deleted: map[int]bool{},
			expected: []string{
				"1 100",
				"2 200",
				"3 300",
			},
		},
		{
			name: "middle message deleted",
			messages: []db.Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
				{Size: 300, UID: 3},
			},
			deleted: map[int]bool{1: true}, // message 2 (index 1) deleted
			expected: []string{
				"1 100",
				// message 2 is deleted - must be skipped
				"3 300",
			},
		},
		{
			name: "first message deleted",
			messages: []db.Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
				{Size: 300, UID: 3},
			},
			deleted: map[int]bool{0: true}, // message 1 (index 0) deleted
			expected: []string{
				// message 1 is deleted - must be skipped
				"2 200",
				"3 300",
			},
		},
		{
			name: "last message deleted",
			messages: []db.Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
				{Size: 300, UID: 3},
			},
			deleted: map[int]bool{2: true}, // message 3 (index 2) deleted
			expected: []string{
				"1 100",
				"2 200",
				// message 3 is deleted - must be skipped
			},
		},
		{
			name: "multiple non-contiguous deletions",
			messages: []db.Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
				{Size: 300, UID: 3},
				{Size: 400, UID: 4},
				{Size: 500, UID: 5},
			},
			deleted: map[int]bool{1: true, 3: true}, // messages 2 and 4 deleted
			expected: []string{
				"1 100",
				// message 2 deleted
				"3 300",
				// message 4 deleted
				"5 500",
			},
		},
		{
			name: "all messages deleted",
			messages: []db.Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
			},
			deleted:  map[int]bool{0: true, 1: true},
			expected: []string{},
		},
		{
			name:     "empty mailbox",
			messages: []db.Message{},
			deleted:  map[int]bool{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := buildListResponseLines(tt.messages, tt.deleted)

			if len(lines) != len(tt.expected) {
				t.Errorf("expected %d lines, got %d lines\n  expected: %v\n  got:      %v",
					len(tt.expected), len(lines), tt.expected, lines)
				return
			}

			for i, line := range lines {
				if line != tt.expected[i] {
					t.Errorf("line %d: expected %q, got %q", i, tt.expected[i], line)
				}
			}
		})
	}
}

// TestUIDLResponsePreservesMessageNumbers verifies that UIDL preserves original
// message numbers after DELE, per RFC 1939 §5. Deleted messages must be skipped
// but remaining messages must keep their original numbering.
func TestUIDLResponsePreservesMessageNumbers(t *testing.T) {
	tests := []struct {
		name     string
		messages []db.Message
		deleted  map[int]bool
		expected []string // expected lines in the multi-line response body
	}{
		{
			name: "no deletions",
			messages: []db.Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
				{Size: 300, UID: 3},
			},
			deleted: map[int]bool{},
			expected: []string{
				"1 1",
				"2 2",
				"3 3",
			},
		},
		{
			name: "middle message deleted",
			messages: []db.Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
				{Size: 300, UID: 3},
			},
			deleted: map[int]bool{1: true}, // message 2 (index 1) deleted
			expected: []string{
				"1 1",
				// message 2 is deleted - must be skipped
				"3 3",
			},
		},
		{
			name: "first message deleted",
			messages: []db.Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
				{Size: 300, UID: 3},
			},
			deleted: map[int]bool{0: true}, // message 1 (index 0) deleted
			expected: []string{
				// message 1 is deleted - must be skipped
				"2 2",
				"3 3",
			},
		},
		{
			name: "multiple non-contiguous deletions",
			messages: []db.Message{
				{Size: 100, UID: 10},
				{Size: 200, UID: 20},
				{Size: 300, UID: 30},
				{Size: 400, UID: 40},
				{Size: 500, UID: 50},
			},
			deleted: map[int]bool{1: true, 3: true}, // messages 2 and 4 deleted
			expected: []string{
				"1 10",
				// message 2 deleted
				"3 30",
				// message 4 deleted
				"5 50",
			},
		},
		{
			name: "all messages deleted",
			messages: []db.Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
			},
			deleted:  map[int]bool{0: true, 1: true},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := buildUIDLResponseLines(tt.messages, tt.deleted)

			if len(lines) != len(tt.expected) {
				t.Errorf("expected %d lines, got %d lines\n  expected: %v\n  got:      %v",
					len(tt.expected), len(lines), tt.expected, lines)
				return
			}

			for i, line := range lines {
				if line != tt.expected[i] {
					t.Errorf("line %d: expected %q, got %q", i, tt.expected[i], line)
				}
			}
		})
	}
}

// TestListResponseCount verifies that the count in the +OK header matches
// the number of non-deleted messages.
func TestListResponseCount(t *testing.T) {
	messages := []db.Message{
		{Size: 100, UID: 1},
		{Size: 200, UID: 2},
		{Size: 300, UID: 3},
	}
	deleted := map[int]bool{1: true} // message 2 deleted

	lines := buildListResponseLines(messages, deleted)
	count := countNonDeletedMessages(messages, deleted)

	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}
	if len(lines) != count {
		t.Errorf("count (%d) doesn't match number of lines (%d)", count, len(lines))
	}
}

// TestUIDLResponseCount verifies the same for UIDL.
func TestUIDLResponseCount(t *testing.T) {
	messages := []db.Message{
		{Size: 100, UID: 1},
		{Size: 200, UID: 2},
		{Size: 300, UID: 3},
	}
	deleted := map[int]bool{1: true} // message 2 deleted

	lines := buildUIDLResponseLines(messages, deleted)
	count := countNonDeletedMessages(messages, deleted)

	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}
	if len(lines) != count {
		t.Errorf("count (%d) doesn't match number of lines (%d)", count, len(lines))
	}
}

// TestSingleMessageListResponse verifies the single-message LIST response format
// per RFC 1939 §5: "LIST msg" returns "+OK msg size".
func TestSingleMessageListResponse(t *testing.T) {
	messages := []db.Message{
		{Size: 100, UID: 1},
		{Size: 200, UID: 2},
		{Size: 300, UID: 3},
	}

	tests := []struct {
		name        string
		msgNumber   int
		deleted     map[int]bool
		expectOK    bool
		expectedMsg string // expected response line (without +OK prefix or -ERR prefix)
	}{
		{
			name:        "valid message",
			msgNumber:   2,
			deleted:     map[int]bool{},
			expectOK:    true,
			expectedMsg: "2 200",
		},
		{
			name:        "first message",
			msgNumber:   1,
			deleted:     map[int]bool{},
			expectOK:    true,
			expectedMsg: "1 100",
		},
		{
			name:        "last message",
			msgNumber:   3,
			deleted:     map[int]bool{},
			expectOK:    true,
			expectedMsg: "3 300",
		},
		{
			name:      "deleted message",
			msgNumber: 2,
			deleted:   map[int]bool{1: true},
			expectOK:  false,
		},
		{
			name:      "out of range",
			msgNumber: 4,
			deleted:   map[int]bool{},
			expectOK:  false,
		},
		{
			name:      "zero",
			msgNumber: 0,
			deleted:   map[int]bool{},
			expectOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, line := buildSingleListResponse(messages, tt.deleted, tt.msgNumber)
			if ok != tt.expectOK {
				t.Errorf("expected ok=%v, got ok=%v", tt.expectOK, ok)
			}
			if tt.expectOK && line != tt.expectedMsg {
				t.Errorf("expected %q, got %q", tt.expectedMsg, line)
			}
		})
	}
}

// TestListResponseMessageNumbersAreOneIndexed verifies POP3 message numbers start at 1.
func TestListResponseMessageNumbersAreOneIndexed(t *testing.T) {
	messages := []db.Message{
		{Size: 999, UID: 42},
	}
	deleted := map[int]bool{}

	lines := buildListResponseLines(messages, deleted)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	if !strings.HasPrefix(lines[0], "1 ") {
		t.Errorf("expected message number to start at 1, got: %s", lines[0])
	}
}

// TestComputeDeletedStats verifies that deleted message count and size are
// correctly computed for adjusting STAT results per RFC 1939 §5.
func TestComputeDeletedStats(t *testing.T) {
	tests := []struct {
		name          string
		messages      []db.Message
		deleted       map[int]bool
		expectedCount int
		expectedSize  int64
	}{
		{
			name: "no deletions",
			messages: []db.Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
				{Size: 300, UID: 3},
			},
			deleted:       map[int]bool{},
			expectedCount: 0,
			expectedSize:  0,
		},
		{
			name: "one deletion",
			messages: []db.Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
				{Size: 300, UID: 3},
			},
			deleted:       map[int]bool{1: true},
			expectedCount: 1,
			expectedSize:  200,
		},
		{
			name: "multiple deletions",
			messages: []db.Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
				{Size: 300, UID: 3},
				{Size: 400, UID: 4},
			},
			deleted:       map[int]bool{0: true, 2: true},
			expectedCount: 2,
			expectedSize:  400, // 100 + 300
		},
		{
			name: "all deleted",
			messages: []db.Message{
				{Size: 100, UID: 1},
				{Size: 200, UID: 2},
			},
			deleted:       map[int]bool{0: true, 1: true},
			expectedCount: 2,
			expectedSize:  300,
		},
		{
			name:          "empty mailbox",
			messages:      []db.Message{},
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
			count, size := computeDeletedStats(tt.messages, tt.deleted)
			if count != tt.expectedCount {
				t.Errorf("count: expected %d, got %d", tt.expectedCount, count)
			}
			if size != tt.expectedSize {
				t.Errorf("size: expected %d, got %d", tt.expectedSize, size)
			}
		})
	}
}

// TestStatAdjustmentWithDeletions verifies the STAT adjustment logic:
// the DB-reported count/size minus deleted messages' count/size.
func TestStatAdjustmentWithDeletions(t *testing.T) {
	messages := []db.Message{
		{Size: 100, UID: 1},
		{Size: 200, UID: 2},
		{Size: 300, UID: 3},
	}

	// DB reports total: 3 messages, 600 octets
	dbCount := 3
	dbSize := int64(600)

	// Delete message 2 (index 1, size 200)
	deleted := map[int]bool{1: true}
	delCount, delSize := computeDeletedStats(messages, deleted)

	adjustedCount := dbCount - delCount
	adjustedSize := dbSize - delSize

	if adjustedCount != 2 {
		t.Errorf("adjusted count: expected 2, got %d", adjustedCount)
	}
	if adjustedSize != 400 {
		t.Errorf("adjusted size: expected 400, got %d", adjustedSize)
	}
}

// TestUIDLResponseUsesUID verifies that UIDL uses the UID as unique-id, not the index.
func TestUIDLResponseUsesUID(t *testing.T) {
	messages := []db.Message{
		{Size: 100, UID: imap.UID(42)},
		{Size: 200, UID: imap.UID(99)},
	}
	deleted := map[int]bool{}

	lines := buildUIDLResponseLines(messages, deleted)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	if lines[0] != "1 42" {
		t.Errorf("line 0: expected %q, got %q", "1 42", lines[0])
	}
	if lines[1] != "2 99" {
		t.Errorf("line 1: expected %q, got %q", "2 99", lines[1])
	}
}
