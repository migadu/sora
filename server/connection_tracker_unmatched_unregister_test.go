package server

import (
	"context"
	"testing"
)

// TestUnregisterThatReleasesNothingIsNotGossiped: an unregister for a connection
// this instance holds no count for decrements nothing here, so it must not be
// gossiped either. Peers count this instance's connections from its register and
// unregister events. An unregister with no register behind it finds nothing to
// subtract on a peer, which then holds it as a reordered decrement
// (deferredDecrements) for the dedup window, in the ledger whose bounded capacity
// the genuinely reordered pairs need (#796).
func TestUnregisterThatReleasesNothingIsNotGossiped(t *testing.T) {
	const (
		accountID = int64(796)
		username  = "user@example.com"
	)
	node := newSingleNodeCluster(t, "node-1")
	ct := NewConnectionTracker("IMAP", "imap-proxy", "mail", "node-1-imap-proxy", node, 0, 0, 0, false)
	defer ct.Stop()

	// The account's live session from 192.0.2.1.
	if err := ct.RegisterConnection(context.Background(), accountID, username, "IMAP", "192.0.2.1:40000"); err != nil {
		t.Fatalf("register: %v", err)
	}

	// A session from 192.0.2.2 that never registered ends.
	if event := ct.unregisterLocked(accountID, "IMAP", "192.0.2.2:40001"); event != nil {
		t.Errorf("an unregister that released nothing produced a %v event for peers, want none", event.Type)
	}
	if got := ct.GetLocalConnectionCount(accountID); got != 1 {
		t.Errorf("local count = %d, want 1 (the live session)", got)
	}

	// The live session ends: that unregister is gossiped.
	if event := ct.unregisterLocked(accountID, "IMAP", "192.0.2.1:40000"); event == nil || event.Type != ConnectionEventUnregister {
		t.Errorf("the live session's unregister produced %+v, want an unregister event for peers", event)
	}
	if got := ct.GetLocalConnectionCount(accountID); got != 0 {
		t.Errorf("local count = %d after the live session ended, want 0", got)
	}
}
