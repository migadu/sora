package userapi

import (
	"strings"
	"testing"
)

// TestNew_WiresMaxConnections confirms the configured connection cap reaches the
// field the LimitListener uses (catches an option-wiring typo).
func TestNew_WiresMaxConnections(t *testing.T) {
	s, err := New(nil, ServerOptions{JWTSecret: strings.Repeat("k", 32), MaxConnections: 7})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.maxConnections != 7 {
		t.Errorf("maxConnections = %d, want 7", s.maxConnections)
	}
}

// TestNew_RejectsWeakJWTSecret verifies the User API refuses to start with a missing
// or sub-32-byte JWT secret (audit H6 / RFC 7518 §3.2). The secret check runs before
// any DB use, so New can be called with a nil rdb here.
func TestNew_RejectsWeakJWTSecret(t *testing.T) {
	cases := []struct{ name, secret, wantErr string }{
		{"empty", "", "required"},
		{"15 chars", strings.Repeat("a", 15), "at least"},
		{"31 chars", strings.Repeat("a", 31), "at least"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(nil, ServerOptions{JWTSecret: c.secret})
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("JWTSecret=%q: got err=%v, want substring %q", c.secret, err, c.wantErr)
			}
		})
	}
}
