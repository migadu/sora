package pop3proxy

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/server"
)

// TestLoginErrorReply checks the reply doLogin sends for each kind of error
// authenticate returns. Backend errors arrive wrapped the way authenticate wraps
// connectToBackend's. A backend outage (dial, greeting, AUTH PLAIN to the backend, a
// timeout on any of them, or the backend refusing the proxy's own login) is -ERR
// [SYS/TEMP] (RFC 3206 section 4). [AUTH] "Authentication failed" says the client's
// credentials are wrong (RFC 3206 section 5), so it is reserved for refusals of
// those. TestBackendAuthTimeout and TestBackendConnectTimeout cover the timeouts end
// to end.
func TestLoginErrorReply(t *testing.T) {
	viaBackend := func(err error) error { return fmt.Errorf("failed to connect to backend: %w", err) }
	const (
		authFailed  = "Authentication failed"
		backendDown = "Backend server temporarily unavailable"
		serviceDown = "Service temporarily unavailable, please try again later"
	)
	for _, tc := range []struct {
		name      string
		err       error
		wantCode  string
		wantMsg   string
		wantClose bool
	}{
		{"backend auth reply read timeout", viaBackend(fmt.Errorf("%w: failed to read auth response: %w", server.ErrBackendAuthFailed, os.ErrDeadlineExceeded)), "SYS/TEMP", backendDown, false},
		{"backend auth context deadline", viaBackend(fmt.Errorf("%w: failed to read auth response: %w", server.ErrBackendAuthFailed, context.DeadlineExceeded)), "SYS/TEMP", backendDown, false},
		{"backend refuses the proxy login", viaBackend(fmt.Errorf("%w: -ERR [AUTH] Authentication failed", server.ErrBackendAuthFailed)), "SYS/TEMP", backendDown, false},
		{"sending AUTH PLAIN to the backend fails", viaBackend(fmt.Errorf("%w: failed to send AUTH PLAIN to backend: %w", server.ErrBackendAuthFailed, syscall.ECONNRESET)), "SYS/TEMP", backendDown, false},
		{"backend dial timeout", viaBackend(fmt.Errorf("%w: dial tcp 192.0.2.1:110: %w", server.ErrBackendConnectionFailed, os.ErrDeadlineExceeded)), "SYS/TEMP", backendDown, false},
		{"backend greeting timeout", viaBackend(fmt.Errorf("%w: failed to read backend greeting: %w", server.ErrBackendConnectionFailed, os.ErrDeadlineExceeded)), "SYS/TEMP", backendDown, false},
		{"backend timeout", viaBackend(server.ErrBackendTimeout), "SYS/TEMP", backendDown, false},
		{"backend unavailable", viaBackend(server.ErrBackendUnavailable), "SYS/TEMP", backendDown, false},
		{"server shutting down", server.ErrServerShuttingDown, "SYS/TEMP", serviceDown, false},
		{"auth service unavailable", fmt.Errorf("remote lookup: %w", server.ErrAuthServiceUnavailable), "SYS/TEMP", serviceDown, false},
		{"wrong password", consts.ErrAuthenticationFailed, "AUTH", authFailed, false},
		// Rate limited: the bad-password text, so the limiter is not an oracle, but the
		// connection is dropped.
		{"rate limited", &server.RateLimitError{Reason: "ip_blocked", IP: "192.0.2.1"}, "AUTH", authFailed, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := loginErrorReply(tc.err)
			if got.Code != tc.wantCode || got.Message != tc.wantMsg || got.Close != tc.wantClose {
				t.Errorf("loginErrorReply(%v) = {Code: %q, Message: %q, Close: %v}, want {Code: %q, Message: %q, Close: %v}",
					tc.err, got.Code, got.Message, got.Close, tc.wantCode, tc.wantMsg, tc.wantClose)
			}
		})
	}
}
