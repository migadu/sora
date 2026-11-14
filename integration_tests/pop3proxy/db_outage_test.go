//go:build integration

package pop3proxy_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// pop3ProxyPassReply sends USER and PASS on a fresh connection and returns the reply to PASS.
func pop3ProxyPassReply(t *testing.T, address, username, password string) string {
	t.Helper()
	client, err := NewPOP3Client(address)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()
	if err := client.SendCommand("USER " + username); err != nil {
		t.Fatalf("USER: %v", err)
	}
	if _, err := client.ReadResponse(); err != nil {
		t.Fatalf("USER read: %v", err)
	}
	if err := client.SendCommand("PASS " + password); err != nil {
		t.Fatalf("PASS: %v", err)
	}
	resp, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("PASS read: %v", err)
	}
	return resp
}

// TestPOP3ProxyLoginDuringDatabaseOutage: a proxy that authenticates against
// PostgreSQL answers a login the database cannot answer with -ERR [SYS/TEMP]
// (RFC 3206 section 4), not [AUTH], and does not count it in the auth rate limiter,
// so the user logs in once the database is back.
func TestPOP3ProxyLoginDuringDatabaseOutage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, account := common.SetupPOP3ServerWithMaster(t)
	defer backend.Close()

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	proxyAddr := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithRateLimiting(t, rdb, proxyAddr, []string{backend.Address}, common.DBOutageAuthRateLimit())
	defer proxy.Close()

	outage.Begin()
	for i := 1; i <= 3; i++ {
		if reply := pop3ProxyPassReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "-ERR [SYS/TEMP]") {
			t.Errorf("PASS %d during a database outage: %q, want -ERR [SYS/TEMP] ...", i, reply)
		}
	}
	outage.End()

	if reply := pop3ProxyPassReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "+OK") {
		t.Errorf("PASS after the outage: %q, want +OK (the outage was counted as failed logins)", reply)
	}
}
