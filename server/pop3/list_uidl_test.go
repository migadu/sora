package pop3

import (
	"context"
	"errors"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
)

// listUidlSession builds a POP3Session with an injected message snapshot, so
// List/Uidl can be exercised without a database (loadMessagesIfNeeded is a
// no-op once s.messages is non-nil). deleted is keyed by 0-based index.
func listUidlSession(messages []db.POP3Message, deleted map[int]bool) *POP3Session {
	if deleted == nil {
		deleted = make(map[int]bool)
	}
	// The session methods dereference s.server for the per-command timeouts;
	// nil commandTimeouts means no deadline is applied.
	return &POP3Session{messages: messages, deleted: deleted, server: &POP3Server{}}
}

// RFC 1939 stable numbering: DELE must not renumber the remaining messages —
// LIST/UIDL skip deleted entries but keep each survivor's original 1-indexed
// message number, and UIDL reports the message UID, never the slice index.
func TestListUidlPreserveMessageNumbersAfterDele(t *testing.T) {
	messages := []db.POP3Message{
		{Size: 100, UID: imap.UID(4711)},
		{Size: 200, UID: imap.UID(4712)},
		{Size: 300, UID: imap.UID(4713)},
		{Size: 400, UID: imap.UID(4714)},
		{Size: 500, UID: imap.UID(4715)},
	}
	// Delete messages 2 and 4 (0-based indexes 1 and 3).
	s := listUidlSession(messages, map[int]bool{1: true, 3: true})
	ctx := context.Background()

	infos, err := s.List(ctx, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	wantNums := []int{1, 3, 5}
	wantSizes := []int64{100, 300, 500}
	if len(infos) != len(wantNums) {
		t.Fatalf("List returned %d entries, want %d", len(infos), len(wantNums))
	}
	for i := range infos {
		if infos[i].Num != wantNums[i] || infos[i].Size != wantSizes[i] {
			t.Errorf("List[%d] = (%d, %d), want (%d, %d)", i, infos[i].Num, infos[i].Size, wantNums[i], wantSizes[i])
		}
	}

	uidls, err := s.Uidl(ctx, 0)
	if err != nil {
		t.Fatalf("Uidl: %v", err)
	}
	wantUIDs := []string{"4711", "4713", "4715"}
	if len(uidls) != len(wantNums) {
		t.Fatalf("Uidl returned %d entries, want %d", len(uidls), len(wantNums))
	}
	for i := range uidls {
		if uidls[i].Num != wantNums[i] || uidls[i].UniqueID != wantUIDs[i] {
			t.Errorf("Uidl[%d] = (%d, %q), want (%d, %q)", i, uidls[i].Num, uidls[i].UniqueID, wantNums[i], wantUIDs[i])
		}
	}
}

// Single-message LIST/UIDL: first and last message answer with their own
// number; deleted and out-of-range numbers get the benign no-such-message
// error (which the library reports without an error-count penalty).
func TestListUidlSingleMessage(t *testing.T) {
	messages := []db.POP3Message{
		{Size: 100, UID: imap.UID(4711)},
		{Size: 200, UID: imap.UID(4712)},
		{Size: 300, UID: imap.UID(4713)},
	}
	s := listUidlSession(messages, map[int]bool{1: true}) // message 2 deleted
	ctx := context.Background()

	for _, tc := range []struct {
		msg      int
		wantSize int64
		wantUID  string
	}{
		{msg: 1, wantSize: 100, wantUID: "4711"},
		{msg: 3, wantSize: 300, wantUID: "4713"},
	} {
		infos, err := s.List(ctx, tc.msg)
		if err != nil || len(infos) != 1 || infos[0].Num != tc.msg || infos[0].Size != tc.wantSize {
			t.Errorf("List(%d) = %v, %v; want single entry (%d, %d)", tc.msg, infos, err, tc.msg, tc.wantSize)
		}
		uidls, err := s.Uidl(ctx, tc.msg)
		if err != nil || len(uidls) != 1 || uidls[0].Num != tc.msg || uidls[0].UniqueID != tc.wantUID {
			t.Errorf("Uidl(%d) = %v, %v; want single entry (%d, %q)", tc.msg, uidls, err, tc.msg, tc.wantUID)
		}
	}

	for _, msg := range []int{2, 4} { // deleted, out of range
		if _, err := s.List(ctx, msg); !errors.Is(err, errNoSuchMessage) {
			t.Errorf("List(%d) error = %v, want errNoSuchMessage", msg, err)
		}
		if _, err := s.Uidl(ctx, msg); !errors.Is(err, errNoSuchMessage) {
			t.Errorf("Uidl(%d) error = %v, want errNoSuchMessage", msg, err)
		}
	}
}

// computeMaildropStats is the shared STAT helper: it must report the session
// snapshot minus deletions.
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
