//go:build integration

package imapproxy_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestIMAPProxyMasterLoginDuringDatabaseOutage: once the proxy has accepted the master
// password, an impersonation target the database cannot look up is a temporary
// failure, NO [UNAVAILABLE] (RFC 5530 section 3), not a bad credential, and it is not
// counted against the master credential by the auth rate limiter, so the master login
// works once the database is back.
func TestIMAPProxyMasterLoginDuringDatabaseOutage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, account := common.SetupIMAPServerWithMaster(t)
	defer backend.Close()

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	proxyAddr := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithMasterAuthAndRateLimit(t, &common.TestServer{ResilientDB: rdb}, proxyAddr,
		[]string{backend.Address}, common.DBOutageAuthRateLimit())
	defer proxy.Close()

	masterLogin := account.Email + "@" + proxyMasterUsername

	authenticationAttempts := func(result string) float64 {
		return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", "test-proxy-master-ratelimit", "test-proxy-master-ratelimit", result))
	}
	unavailableBefore, failuresBefore := authenticationAttempts("unavailable"), authenticationAttempts("failure")

	outage.Begin()
	for i := 1; i <= 3; i++ {
		if reply := imapProxyLoginReply(t, proxyAddr, masterLogin, proxyMasterPassword); !strings.HasPrefix(reply, "a1 NO [UNAVAILABLE]") {
			t.Errorf("master LOGIN %d during a database outage: %q, want a1 NO [UNAVAILABLE] ...", i, reply)
		}
	}
	outage.End()

	if grew := authenticationAttempts("unavailable") - unavailableBefore; grew != 3 {
		t.Errorf("outage logins counted as unavailable: %v, want 3", grew)
	}
	if grew := authenticationAttempts("failure") - failuresBefore; grew != 0 {
		t.Errorf("outage logins counted as credential failures: %v, want 0", grew)
	}

	if reply := imapProxyLoginReply(t, proxyAddr, masterLogin, proxyMasterPassword); !strings.HasPrefix(reply, "a1 OK") {
		t.Errorf("master LOGIN after the outage: %q, want a1 OK (the outage was counted as failed logins)", reply)
	}
}
