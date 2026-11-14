//go:build integration

package managesieve

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieve"
	"github.com/prometheus/client_golang/prometheus/testutil"
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

// TestManageSieve_MaxConnectionsPerUserRefusalMetrics verifies that logins
// refused over max_connections_per_user via AUTHENTICATE PLAIN or LOGIN do not
// increment sora_authentication_attempts_total{result="success"} or
// {result="failure"}.
func TestManageSieve_MaxConnectionsPerUserRefusalMetrics(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)
	const name = "test-ms-connlimit-metrics"

	srv, err := managesieve.New(context.Background(), name, "localhost", address, rdb,
		managesieve.ManageSieveServerOptions{
			InsecureAuth:                true,
			ProxyProtocol:               true,
			ProxyProtocolTimeout:        "5s",
			ProxyProtocolTrustedProxies: []string{"127.0.0.0/8", "::1/128"},
			TrustedNetworks:             []string{"127.0.0.0/8", "::1/128"},
			SupportedExtensions:         []string{"fileinto"},
		})
	if err != nil {
		t.Fatalf("managesieve.New: %v", err)
	}
	tracker := server.NewConnectionTracker("ManageSieve", name, "localhost", "test-instance", nil, 1, 0, 0, false)
	t.Cleanup(tracker.Stop)
	srv.SetConnTracker(tracker)

	errChan := make(chan error, 1)
	go srv.Start(errChan)
	t.Cleanup(srv.Close)
	time.Sleep(100 * time.Millisecond)

	succ := metrics.AuthenticationAttempts.WithLabelValues("managesieve", name, "localhost", "success")
	fail := metrics.AuthenticationAttempts.WithLabelValues("managesieve", name, "localhost", "failure")

	const ip = "198.51.100.10"
	first := dialProxiedManageSieve(t, address, ip)
	first.login(account)

	// Refused AUTHENTICATE PLAIN
	s0, f0 := testutil.ToFloat64(succ), testutil.ToFloat64(fail)
	overSASL := dialProxiedManageSieve(t, address, ip)
	if resp := overSASL.tryLogin(account); !strings.HasPrefix(resp, "NO (TRYLATER)") {
		t.Fatalf("AUTHENTICATE PLAIN over max_connections_per_user = %q, want NO (TRYLATER)", resp)
	}
	if ds, df := testutil.ToFloat64(succ)-s0, testutil.ToFloat64(fail)-f0; ds != 0 || df != 0 {
		t.Errorf("connection-limited AUTHENTICATE PLAIN metric deltas = (success=%v, failure=%v), want (0, 0)", ds, df)
	}

	// Refused LOGIN
	s0, f0 = testutil.ToFloat64(succ), testutil.ToFloat64(fail)
	overLogin := dialProxiedManageSieve(t, address, ip)
	resp := overLogin.do(fmt.Sprintf("LOGIN %q %q", account.Email, account.Password))
	if !strings.HasPrefix(resp, "NO (TRYLATER)") {
		t.Fatalf("LOGIN over max_connections_per_user = %q, want NO (TRYLATER)", resp)
	}
	if ds, df := testutil.ToFloat64(succ)-s0, testutil.ToFloat64(fail)-f0; ds != 0 || df != 0 {
		t.Errorf("connection-limited LOGIN metric deltas = (success=%v, failure=%v), want (0, 0)", ds, df)
	}
}
