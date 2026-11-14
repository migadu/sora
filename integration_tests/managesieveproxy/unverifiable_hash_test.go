//go:build integration

package managesieveproxy_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestManageSieveProxyLoginWithUnverifiableStoredHash: a stored hash sora cannot check
// says nothing about the submitted password, so a proxy that authenticates against
// PostgreSQL answers NO (TRYLATER) (RFC 5804 section 1.3), as it does for a lookup
// answer carrying such a hash, and does not count it in the auth rate limiter: the
// user logs in as soon as an administrator repairs the hash.
func TestManageSieveProxyLoginWithUnverifiableStoredHash(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, account := common.SetupManageSieveServerWithMaster(t)
	defer backend.Close()

	proxyAddr := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithRateLimiting(t, backend.ResilientDB, proxyAddr, []string{backend.Address}, common.DBOutageAuthRateLimit())
	defer proxy.Close()

	repair := common.StoreUnverifiableHash(t, backend.ResilientDB, account.Email, account.Password)
	for i := 1; i <= 3; i++ {
		if reply := sieveProxyAuthReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "NO (TRYLATER)") {
			t.Errorf("AUTHENTICATE %d against an unverifiable stored hash: %q, want NO (TRYLATER) ...", i, reply)
		}
	}
	repair()

	if reply := sieveProxyAuthReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "OK") {
		t.Errorf("AUTHENTICATE after the hash was repaired: %q, want OK (the unverifiable hash was counted as failed logins)", reply)
	}
}
