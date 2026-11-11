package imap

import (
	"testing"

	"github.com/migadu/go-imap"
)

func TestRecentUIDs_ConsumedBaselineNeverRewinds(t *testing.T) {
	var tracker recentUIDTracker
	tracker.Store(1, 99)
	// Concurrent SELECTs can finish out of order, or one can read a lagging
	// replica. Neither may revive Recent consumed by a newer selection.
	tracker.Store(1, 42)
	uid, ok := tracker.Load(1)
	if !ok || uid != 99 {
		t.Fatalf("consumed baseline = %v, %v; want 99, true", uid, ok)
	}
}

// TestRecentUIDs_Bounded covers RECENT-1: the server-wide \Recent bookkeeping is keyed
// by mailbox ID and nothing ever removes an entry, so on a multi-tenant node it grows
// for the lifetime of the process.
func TestRecentUIDs_Bounded(t *testing.T) {
	const wantMax = maxRecentUIDMailboxes
	srv := &IMAPServer{}

	for i := 1; i <= 3*wantMax; i++ {
		srv.mailboxRecentUIDs.Store(int64(i), imap.UID(i))
	}

	if count := srv.mailboxRecentUIDs.Len(); count > wantMax {
		t.Errorf("tracked mailboxes = %d, want at most %d", count, wantMax)
	}

	// The most recently selected mailboxes are the ones worth keeping.
	if uid, ok := srv.mailboxRecentUIDs.Load(int64(3 * wantMax)); !ok || uid != imap.UID(3*wantMax) {
		t.Errorf("most recent mailbox entry = (%v, %v), want (%d, true)", uid, ok, 3*wantMax)
	}
	// ...and a re-selected mailbox survives churn shorter than the bound.
	srv.mailboxRecentUIDs.Store(1, imap.UID(42))
	for i := 3*wantMax + 1; i <= 3*wantMax+wantMax/2; i++ {
		srv.mailboxRecentUIDs.Store(int64(i), imap.UID(i))
	}
	if uid, ok := srv.mailboxRecentUIDs.Load(1); !ok || uid != imap.UID(42) {
		t.Errorf("re-selected mailbox entry = (%v, %v), want (42, true)", uid, ok)
	}
}
