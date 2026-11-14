//go:build integration

package managesieveproxy_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestManageSieveProxyMasterLoginDuringDatabaseOutage: once the proxy has accepted the
// master password, an impersonation target the database cannot look up is a temporary
// failure, NO (TRYLATER) (RFC 5804 section 1.3), not a failed authentication, and it
// is not counted against the master credential by the auth rate limiter (three
// failures block it), so the master login works once the database is back.
func TestManageSieveProxyMasterLoginDuringDatabaseOutage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, account := common.SetupManageSieveServerWithMaster(t)
	defer backend.Close()

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	proxyAddr := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithMasterRateLimit(t, &common.TestServer{ResilientDB: rdb}, proxyAddr, []string{backend.Address})
	defer proxy.Close()

	masterLogin := account.Email + "@" + proxyMasterUsername

	authenticationAttempts := func(result string) float64 {
		return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", "test-managesieve-proxy-master-ratelimit", "test-managesieve-proxy-master-ratelimit", result))
	}
	unavailableBefore, failuresBefore := authenticationAttempts("unavailable"), authenticationAttempts("failure")

	outage.Begin()
	for i := 1; i <= 3; i++ {
		if reply := sieveProxyAuthReply(t, proxyAddr, masterLogin, proxyMasterPassword); !strings.HasPrefix(reply, "NO (TRYLATER)") {
			t.Errorf("master AUTHENTICATE %d during a database outage: %q, want NO (TRYLATER) ...", i, reply)
		}
	}
	outage.End()

	if grew := authenticationAttempts("unavailable") - unavailableBefore; grew != 3 {
		t.Errorf("outage logins counted as unavailable: %v, want 3", grew)
	}
	if grew := authenticationAttempts("failure") - failuresBefore; grew != 0 {
		t.Errorf("outage logins counted as credential failures: %v, want 0", grew)
	}

	if reply := sieveProxyAuthReply(t, proxyAddr, masterLogin, proxyMasterPassword); !strings.HasPrefix(reply, "OK") {
		t.Errorf("master AUTHENTICATE after the outage: %q, want OK (the outage was counted as failed logins)", reply)
	}
}
