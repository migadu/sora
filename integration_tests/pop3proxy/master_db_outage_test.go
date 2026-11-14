//go:build integration

package pop3proxy_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestPOP3ProxyMasterLoginDuringDatabaseOutage: once the proxy has accepted the master
// password, an impersonation target the database cannot look up is a temporary
// failure, -ERR [SYS/TEMP] (RFC 3206 section 4), not [AUTH], and it is not counted
// against the master credential by the auth rate limiter (three failures block it),
// so the master login works once the database is back.
func TestPOP3ProxyMasterLoginDuringDatabaseOutage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, account := common.SetupPOP3ServerWithMaster(t)
	defer backend.Close()

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	proxyAddr := common.GetRandomAddress(t)
	setupPOP3ProxyWithMasterRateLimit(t, &common.TestServer{ResilientDB: rdb}, proxyAddr, []string{backend.Address})

	masterLogin := account.Email + "@" + proxyMasterUsername

	authenticationAttempts := func(result string) float64 {
		return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "test-pop3-proxy-master-ratelimit", "test-pop3-proxy-master-ratelimit", result))
	}
	unavailableBefore, failuresBefore := authenticationAttempts("unavailable"), authenticationAttempts("failure")

	outage.Begin()
	for i := 1; i <= 3; i++ {
		if reply := pop3ProxyPassReply(t, proxyAddr, masterLogin, proxyMasterPassword); !strings.HasPrefix(reply, "-ERR [SYS/TEMP]") {
			t.Errorf("master PASS %d during a database outage: %q, want -ERR [SYS/TEMP] ...", i, reply)
		}
	}
	outage.End()

	if grew := authenticationAttempts("unavailable") - unavailableBefore; grew != 3 {
		t.Errorf("outage logins counted as unavailable: %v, want 3", grew)
	}
	if grew := authenticationAttempts("failure") - failuresBefore; grew != 0 {
		t.Errorf("outage logins counted as credential failures: %v, want 0", grew)
	}

	if reply := pop3ProxyPassReply(t, proxyAddr, masterLogin, proxyMasterPassword); !strings.HasPrefix(reply, "+OK") {
		t.Errorf("master PASS after the outage: %q, want +OK (the outage was counted as failed logins)", reply)
	}
}
