package server

import "testing"

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
