//go:build integration

package pop3proxy_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
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

	outage.Begin()
	for i := 1; i <= 3; i++ {
		if reply := pop3ProxyPassReply(t, proxyAddr, masterLogin, proxyMasterPassword); !strings.HasPrefix(reply, "-ERR [SYS/TEMP]") {
			t.Errorf("master PASS %d during a database outage: %q, want -ERR [SYS/TEMP] ...", i, reply)
		}
	}
	outage.End()

	if reply := pop3ProxyPassReply(t, proxyAddr, masterLogin, proxyMasterPassword); !strings.HasPrefix(reply, "+OK") {
		t.Errorf("master PASS after the outage: %q, want +OK (the outage was counted as failed logins)", reply)
	}
}
