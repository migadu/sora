package server

import (
	"net"
	"testing"
)

func tcpAddr(ip string) net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: 12345}
}

func TestMasterSASLNetworkGate_Disabled(t *testing.T) {
	// Empty config => gate disabled => everything allowed (legacy behavior).
	g, err := NewMasterSASLNetworkGate(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Enabled() {
		t.Fatal("expected disabled gate for empty config")
	}
	if !g.Allowed(tcpAddr("203.0.113.7")) {
		t.Fatal("disabled gate must allow any source")
	}
	// A nil addr is still allowed when disabled (the gate isn't consulted).
	if !g.Allowed(nil) {
		t.Fatal("disabled gate must allow nil addr")
	}
}

func TestMasterSASLNetworkGate_Enforced(t *testing.T) {
	g, err := NewMasterSASLNetworkGate([]string{"10.0.0.0/24", "192.168.1.10"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !g.Enabled() {
		t.Fatal("expected enabled gate")
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},   // inside /24
		{"10.0.0.254", true}, // inside /24
		{"10.0.1.1", false},  // outside /24
		{"192.168.1.10", true},
		{"192.168.1.11", false}, // single-host /32 boundary
		{"127.0.0.1", false},    // loopback not listed
		{"203.0.113.7", false},
	}
	for _, c := range cases {
		if got := g.Allowed(tcpAddr(c.ip)); got != c.want {
			t.Errorf("Allowed(%s) = %v, want %v", c.ip, got, c.want)
		}
	}

	// An unparseable / nil peer must be denied when the gate is enforcing
	// (fail closed — we cannot prove the source is trusted).
	if g.Allowed(nil) {
		t.Error("enforcing gate must deny a nil peer")
	}
}

func TestMasterSASLNetworkGate_IPv6(t *testing.T) {
	g, err := NewMasterSASLNetworkGate([]string{"2001:db8::/32", "::1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !g.Allowed(tcpAddr("2001:db8::1")) {
		t.Error("expected 2001:db8::1 allowed")
	}
	if g.Allowed(tcpAddr("2001:dead::1")) {
		t.Error("expected 2001:dead::1 denied")
	}
	if !g.Allowed(tcpAddr("::1")) {
		t.Error("expected ::1 allowed")
	}
}

func TestMasterSASLNetworkGate_BadConfig(t *testing.T) {
	if _, err := NewMasterSASLNetworkGate([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected error for invalid CIDR/IP (fail closed at startup)")
	}
}

func TestMasterSASLNetworkGate_Equal(t *testing.T) {
	a, _ := NewMasterSASLNetworkGate([]string{"10.0.0.0/24", "192.168.1.10"})
	b, _ := NewMasterSASLNetworkGate([]string{"10.0.0.0/24", "192.168.1.10"})
	c, _ := NewMasterSASLNetworkGate([]string{"10.0.0.0/24"})
	empty1, _ := NewMasterSASLNetworkGate(nil)
	empty2, _ := NewMasterSASLNetworkGate([]string{})

	if !a.Equal(b) {
		t.Error("identical gates should be equal")
	}
	if a.Equal(c) {
		t.Error("gates with different network sets should not be equal")
	}
	if !empty1.Equal(empty2) {
		t.Error("two empty gates should be equal")
	}
	if a.Equal(empty1) {
		t.Error("enforcing gate should not equal a disabled gate")
	}
}
