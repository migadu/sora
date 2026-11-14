package server

import (
	"testing"
	"time"
)

// The per-user-per-IP count is keyed by the client's IP. Callers pass either
// "host:port" or a bare IP; a bare IPv6 address was cut at its last colon, so
// 2001:db8::1 and 2001:db8::2 shared the key "2001:db8:".
func TestClientIPOf(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"192.0.2.1:143", "192.0.2.1"},
		{"192.0.2.1", "192.0.2.1"},
		{"[2001:db8::1]:143", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"2001:db8::2", "2001:db8::2"},
		{"::1", "::1"},
		{"", ""},
		// One client, other spellings: canonical form, IPv4-mapped unmapped.
		{"[2001:0DB8:0:0:0:0:0:1]:5678", "2001:db8::1"},
		{"2001:0DB8::1", "2001:db8::1"},
		{"::ffff:192.0.2.1", "192.0.2.1"},
		{"[::ffff:192.0.2.1]:143", "192.0.2.1"},
		// Not an IP: kept as given.
		{"unknown", "unknown"},
	} {
		if got := clientIPOf(tc.in); got != tc.want {
			t.Errorf("clientIPOf(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Two IPv6 clients of one user from different addresses have their own
// per-IP counts.
func TestConnectionTracker_PerUserPerIPSeparatesIPv6(t *testing.T) {
	ct := NewConnectionTracker("IMAP", "test", "localhost", "instance-1", nil, 10, 1, 0, false)
	defer ct.Stop()

	if err := ct.RegisterConnection(t.Context(), 1, "user@example.com", "IMAP", "2001:db8::1"); err != nil {
		t.Fatalf("first IPv6 client: %v", err)
	}
	if err := ct.RegisterConnection(t.Context(), 1, "user@example.com", "IMAP", "2001:db8::2"); err != nil {
		t.Fatalf("second IPv6 client, another address: %v", err)
	}
	if err := ct.RegisterConnection(t.Context(), 1, "user@example.com", "IMAP", "2001:db8::1"); err == nil {
		t.Fatal("second connection from 2001:db8::1 with a per-IP limit of 1 was accepted")
	}
}

// One IPv6 client spelled two ways is one client: the PROXY v1 header and
// IMAP ID forwarding carry the address as text, so the spelling is the
// sender's.
func TestPerUserIPLimitCanonicalisesClient(t *testing.T) {
	ct := NewConnectionTracker("IMAP", "ip-spelling-repro", "localhost", "instance-1", nil, 10, 1, 0, false)
	defer ct.Stop()

	if err := ct.RegisterConnection(t.Context(), 1, "user@example.com", "IMAP", "[2001:db8::1]:1234"); err != nil {
		t.Fatal(err)
	}
	if err := ct.RegisterConnection(t.Context(), 1, "user@example.com", "IMAP", "[2001:0DB8:0:0:0:0:0:1]:5678"); err == nil {
		t.Fatal("same IPv6 client admitted twice with per-user-per-IP limit 1")
	}

	// An IPv4 client and its IPv4-mapped IPv6 form are one client too.
	if err := ct.RegisterConnection(t.Context(), 2, "other@example.com", "IMAP", "192.0.2.1:1234"); err != nil {
		t.Fatal(err)
	}
	if err := ct.RegisterConnection(t.Context(), 2, "other@example.com", "IMAP", "[::ffff:192.0.2.1]:5678"); err == nil {
		t.Fatal("IPv4 client admitted again as its IPv4-mapped form with per-user-per-IP limit 1")
	}

	// Unregistering under another spelling frees the slot.
	if err := ct.UnregisterConnection(t.Context(), 1, "IMAP", "[2001:DB8::1]:1234"); err != nil {
		t.Fatal(err)
	}
	if err := ct.RegisterConnection(t.Context(), 1, "user@example.com", "IMAP", "2001:db8::1"); err != nil {
		t.Fatalf("slot not freed by an unregister of the same client spelled differently: %v", err)
	}
}

// A peer's register and unregister events carry the client address as the
// peer's session saw it; they move the same counter as a local connection
// from that client, whatever the spelling.
func TestConnectionTracker_GossipEventsCanonicaliseClientIP(t *testing.T) {
	ct := NewConnectionTracker("IMAP", "test", "localhost", "instance-1", nil, 10, 1, 0, false)
	defer ct.Stop()

	ct.handleRegister(ConnectionEvent{
		Type:       ConnectionEventRegister,
		AccountID:  1,
		Username:   "user@example.com",
		Protocol:   "IMAP",
		InstanceID: "instance-2",
		ClientAddr: "[2001:0DB8::1]:1111",
		Timestamp:  time.Now(),
	})
	if err := ct.RegisterConnection(t.Context(), 1, "user@example.com", "IMAP", "2001:db8::1"); err == nil {
		t.Fatal("client already connected via a peer admitted again under another spelling with per-user-per-IP limit 1")
	}

	ct.handleUnregister(ConnectionEvent{
		Type:       ConnectionEventUnregister,
		AccountID:  1,
		Username:   "user@example.com",
		Protocol:   "IMAP",
		InstanceID: "instance-2",
		ClientAddr: "[2001:db8:0::1]:1111",
		Timestamp:  time.Now(),
	})
	if got := ct.GetConnectionCount(1); got != 0 {
		t.Fatalf("peer's unregister spelled differently left %d connection(s) counted, want 0", got)
	}
}

// A peer's state snapshot is keyed by the peer's own spelling of each client
// (an older build keys by the address as given); the receiver counts it under
// the same key as everything else.
func TestConnectionTracker_SnapshotCanonicalisesClientIP(t *testing.T) {
	ct := NewConnectionTracker("IMAP", "test", "localhost", "instance-1", nil, 10, 2, 0, false)
	defer ct.Stop()

	ct.reconcileState(&ConnectionStateSnapshot{
		InstanceID: "instance-2",
		Protocol:   "IMAP",
		Timestamp:  time.Now(),
		Connections: map[int64]UserConnectionData{
			1: {AccountID: 1, Username: "user@example.com", LastUpdate: time.Now(),
				PerIPCount: map[string]int{"2001:0DB8::1": 1, "2001:db8:0::1": 1}},
		},
	})
	if err := ct.RegisterConnection(t.Context(), 1, "user@example.com", "IMAP", "[2001:db8::1]:1234"); err == nil {
		t.Fatal("client with two connections via a peer admitted a third with per-user-per-IP limit 2")
	}
}
