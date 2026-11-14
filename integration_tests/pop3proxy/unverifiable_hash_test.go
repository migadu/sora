//go:build integration

package pop3proxy_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestPOP3ProxyLoginWithUnverifiableStoredHash: a stored hash sora cannot check says
// nothing about the submitted password, so a proxy that authenticates against
// PostgreSQL answers -ERR [SYS/TEMP] (RFC 3206 section 4), as it does for a lookup
// answer carrying such a hash, and does not count it in the auth rate limiter: the
// user logs in as soon as an administrator repairs the hash.
func TestPOP3ProxyLoginWithUnverifiableStoredHash(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, account := common.SetupPOP3ServerWithMaster(t)
	defer backend.Close()

	proxyAddr := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithRateLimiting(t, backend.ResilientDB, proxyAddr, []string{backend.Address}, common.DBOutageAuthRateLimit())
	defer proxy.Close()

	repair := common.StoreUnverifiableHash(t, backend.ResilientDB, account.Email, account.Password)
	for i := 1; i <= 3; i++ {
		if reply := pop3ProxyPassReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "-ERR [SYS/TEMP]") {
			t.Errorf("PASS %d against an unverifiable stored hash: %q, want -ERR [SYS/TEMP] ...", i, reply)
		}
	}
	repair()

	if reply := pop3ProxyPassReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "+OK") {
		t.Errorf("PASS after the hash was repaired: %q, want +OK (the unverifiable hash was counted as failed logins)", reply)
	}
}
