package imap

import (
	"testing"

	"github.com/migadu/go-imap"
)

// A capability check does not copy the session's capability set (#1206).
// STORE checked CONDSTORE once per message, FETCH once per message it set
// \Seen on, multi-mailbox ESEARCH once per mailbox, and go-imap asks the
// session once per MODSEQ item it writes, each time for a single Has. With
// GetCapabilities returning a fresh copy, STORE 1:* +FLAGS (\Seen) on N
// messages allocated N maps of the whole set.
func TestGetCapabilities_DoesNotCopy(t *testing.T) {
	srv := newDisabledCapsTestServer(t, IMAPServerOptions{})
	s := newDisabledCapsTestSession(srv)
	s.sessionCaps.Store(srv.caps.Copy())

	if !s.GetCapabilities().Has(imap.CapCondStore) {
		t.Fatal("test server does not offer CONDSTORE")
	}
	if n := testing.AllocsPerRun(100, func() {
		_ = s.GetCapabilities().Has(imap.CapCondStore)
	}); n != 0 {
		t.Errorf("GetCapabilities().Has(CONDSTORE) allocates %v times per call, want 0", n)
	}
	if n := testing.AllocsPerRun(100, func() {
		_ = s.requireCapability(imap.CapCondStore, "UNCHANGEDSINCE")
	}); n != 0 {
		t.Errorf("requireCapability(CONDSTORE) allocates %v times per call, want 0", n)
	}
}
