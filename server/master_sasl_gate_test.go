package server

import (
	"context"
	"fmt"
	"net"
	"reflect"
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

// recordOnlyLimiter records RecordAuthAttemptWithProxy calls; any other method panics
// (nil embedded interface), which keeps AdmitMasterLogin from calling anything else.
type recordOnlyLimiter struct {
	AuthLimiter
	records []string
}

func (r *recordOnlyLimiter) RecordAuthAttemptWithProxy(_ context.Context, _ net.Conn, _ *ProxyProtocolInfo, key string, success bool) {
	r.records = append(r.records, fmt.Sprintf("%s:%v", key, success))
}

func TestAdmitMasterLogin(t *testing.T) {
	gate, err := NewMasterSASLNetworkGate([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Session{Protocol: "test"}
	inside := &mockAddrConn{remote: tcpAddr("10.0.0.5")}
	outside := &mockAddrConn{remote: tcpAddr("203.0.113.7")}
	ctx := context.Background()

	limiter := &recordOnlyLimiter{}
	if !s.AdmitMasterLogin(ctx, gate, limiter, inside, nil, "master:admin", "master username") {
		t.Fatal("a peer inside the gate was refused")
	}
	if len(limiter.records) != 0 {
		t.Fatalf("an admitted login recorded %v; its outcome is the caller's to record", limiter.records)
	}

	if s.AdmitMasterLogin(ctx, gate, limiter, outside, nil, "master:admin", "master username") {
		t.Fatal("a peer outside the gate was admitted")
	}
	if want := []string{"master:admin:false"}; !reflect.DeepEqual(limiter.records, want) {
		t.Fatalf("refusal recorded %v, want %v (one failure under the master credential's key)", limiter.records, want)
	}

	// No limiter configured: still refused, nothing to record.
	if s.AdmitMasterLogin(ctx, gate, nil, outside, nil, "master:admin", "master SASL") {
		t.Fatal("a peer outside the gate was admitted without a limiter")
	}

	// A disabled gate admits everyone.
	open, _ := NewMasterSASLNetworkGate(nil)
	if !s.AdmitMasterLogin(ctx, open, limiter, outside, nil, "master:admin", "master SASL") {
		t.Fatal("a disabled gate refused a login")
	}
}
