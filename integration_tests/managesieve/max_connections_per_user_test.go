//go:build integration

package managesieve

import (
	"io"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// max_connections_per_user was counted but not enforced on the ManageSieve
// backend: the tracker refused the registration, the refusal was logged, and
// the login went through anyway (#345).
func TestManageSieve_MaxConnectionsPerUserRefusesLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	srv, addr, account, tracker := setupManageSieveConnLimitsBehindProxy(t, 1, 0)
	const ip = "198.51.100.1"

	first := dialProxiedManageSieve(t, addr, ip)
	first.login(account)

	// A second login is refused with a temporary error (RFC 5804 TRYLATER) and
	// leaves its session not logged in and not counted.
	over := dialProxiedManageSieve(t, addr, ip)
	if resp := over.tryLogin(account); !strings.HasPrefix(resp, "NO (TRYLATER)") {
		t.Fatalf("login over max_connections_per_user = %q, want NO (TRYLATER)", resp)
	}
	if resp := over.do("LISTSCRIPTS"); !strings.HasPrefix(resp, "NO") {
		t.Fatalf("LISTSCRIPTS after the refused login = %q, want NO", resp)
	}
	expectTrackedPerIP(t, tracker, map[string]int{ip: 1})
	if n := srv.GetAuthenticatedConnections(); n != 1 {
		t.Fatalf("authenticated connections after the refused login = %d, want 1", n)
	}

	// Closing the refused session releases nothing: the first session still
	// holds the user's only slot, so the next login is refused too.
	if resp := over.do("LOGOUT"); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("LOGOUT: %q", resp)
	}
	if _, err := io.ReadAll(over.r); err != nil {
		t.Fatalf("waiting for the server to close the session: %v", err)
	}
	retry := dialProxiedManageSieve(t, addr, ip)
	if resp := retry.tryLogin(account); !strings.HasPrefix(resp, "NO (TRYLATER)") {
		t.Fatalf("login over max_connections_per_user after the refused session closed = %q, want NO (TRYLATER)", resp)
	}
	expectTrackedPerIP(t, tracker, map[string]int{ip: 1})

	// Once the first session logs out, the refused session may authenticate
	// again on the same connection and takes the freed slot.
	if resp := first.do("LOGOUT"); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("LOGOUT: %q", resp)
	}
	waitTrackedEmpty(t, tracker)
	retry.login(account)
	expectTrackedPerIP(t, tracker, map[string]int{ip: 1})
	if n := srv.GetAuthenticatedConnections(); n != 1 {
		t.Fatalf("authenticated connections = %d, want 1", n)
	}
}
