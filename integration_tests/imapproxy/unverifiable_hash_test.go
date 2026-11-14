//go:build integration

package imapproxy_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAPProxyLoginWithUnverifiableStoredHash: a stored hash sora cannot check says
// nothing about the submitted password, so a proxy that authenticates against
// PostgreSQL answers NO [UNAVAILABLE] (RFC 5530 section 3), as it does for a lookup
// answer carrying such a hash, and does not count it in the auth rate limiter: the
// user logs in as soon as an administrator repairs the hash.
func TestIMAPProxyLoginWithUnverifiableStoredHash(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, account := common.SetupIMAPServerWithMaster(t)
	defer backend.Close()

	proxyAddr := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithRateLimiting(t, backend.ResilientDB, proxyAddr, []string{backend.Address}, common.DBOutageAuthRateLimit())
	defer proxy.Close()

	repair := common.StoreUnverifiableHash(t, backend.ResilientDB, account.Email, account.Password)
	for i := 1; i <= 3; i++ {
		if reply := imapProxyLoginReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "a1 NO [UNAVAILABLE]") {
			t.Errorf("LOGIN %d against an unverifiable stored hash: %q, want a1 NO [UNAVAILABLE] ...", i, reply)
		}
	}
	repair()

	if reply := imapProxyLoginReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "a1 OK") {
		t.Errorf("LOGIN after the hash was repaired: %q, want a1 OK (the unverifiable hash was counted as failed logins)", reply)
	}
}
