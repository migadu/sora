//go:build integration

package pop3

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// max_connections_per_user was counted but not enforced on the POP3 backend:
// the tracker refused the registration, the refusal was logged, and the login
// went through anyway (#345).
func TestPOP3_MaxConnectionsPerUserRefusesLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	srv, addr, account, tracker := setupPOP3ConnLimitsBehindProxy(t, 1, 0)
	const ip = "198.51.100.1"

	first := dialProxiedPOP3(t, addr, ip)
	// The refused logins and the STAT below each pay the library's progressive
	// error delay (3s, then 6s): about 12s before this session's QUIT, too
	// close to the helper's 15s deadline.
	first.conn.SetDeadline(time.Now().Add(60 * time.Second))
	first.login(account)

	// A second login is refused with a temporary error and leaves its session
	// in the AUTHORIZATION state: not logged in and not counted. Its
	// credentials were right, so it counts as a successful login attempt, as
	// on the IMAP backend, and not as a failed one.
	success := metrics.AuthenticationAttempts.WithLabelValues("pop3", "test", "localhost", "success")
	failure := metrics.AuthenticationAttempts.WithLabelValues("pop3", "test", "localhost", "failure")
	successBefore, failureBefore := testutil.ToFloat64(success), testutil.ToFloat64(failure)
	over := dialProxiedPOP3(t, addr, ip)
	if resp := over.tryLogin(account); !strings.HasPrefix(resp, "-ERR [SYS/TEMP]") {
		t.Fatalf("login over max_connections_per_user = %q, want -ERR [SYS/TEMP]", resp)
	}
	if d := testutil.ToFloat64(success) - successBefore; d != 1 {
		t.Errorf(`refused login: sora_authentication_attempts_total{result="success"} grew by %v, want 1`, d)
	}
	if d := testutil.ToFloat64(failure) - failureBefore; d != 0 {
		t.Errorf(`refused login: sora_authentication_attempts_total{result="failure"} grew by %v, want 0`, d)
	}
	if resp := over.do("STAT"); !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("STAT after the refused login = %q, want -ERR", resp)
	}
	expectTrackedPerIP(t, tracker, map[string]int{ip: 1})
	if n := srv.GetAuthenticatedConnections(); n != 1 {
		t.Fatalf("authenticated connections after the refused login = %d, want 1", n)
	}

	// Closing the refused session releases nothing: the first session still
	// holds the user's only slot, so the next login is refused too.
	if resp := over.do("QUIT"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("QUIT: %q", resp)
	}
	if _, err := io.ReadAll(over.r); err != nil {
		t.Fatalf("waiting for the server to close the session: %v", err)
	}
	retry := dialProxiedPOP3(t, addr, ip)
	if resp := retry.tryLogin(account); !strings.HasPrefix(resp, "-ERR [SYS/TEMP]") {
		t.Fatalf("login over max_connections_per_user after the refused session closed = %q, want -ERR [SYS/TEMP]", resp)
	}
	expectTrackedPerIP(t, tracker, map[string]int{ip: 1})

	// Once the first session quits, the refused session may authenticate again
	// on the same connection (RFC 1939 section 4) and takes the freed slot.
	if resp := first.do("QUIT"); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("QUIT: %q", resp)
	}
	waitTrackedEmpty(t, tracker)
	retry.login(account)
	expectTrackedPerIP(t, tracker, map[string]int{ip: 1})
	if n := srv.GetAuthenticatedConnections(); n != 1 {
		t.Fatalf("authenticated connections = %d, want 1", n)
	}
}
