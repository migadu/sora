//go:build integration

package pop3proxy_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/pop3proxy"
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

// TestPOP3ProxyUnverifiableStoredHashDropsCachedLogin: a login cached before the stored
// hash became unverifiable vouches for a password the database no longer holds. A guess
// that misses the cached password goes to the database, which answers no verdict, so
// the guess is not counted; the cached login must go with it, or every later guess is
// checked against the cached password, uncounted, until the entry expires.
func TestPOP3ProxyUnverifiableStoredHashDropsCachedLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, account := common.SetupPOP3ServerWithMaster(t)
	defer backend.Close()

	proxyAddr := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithRateLimiting(t, backend.ResilientDB, proxyAddr, []string{backend.Address}, common.DBOutageAuthRateLimit(),
		func(o *pop3proxy.POP3ProxyServerOptions) { o.LookupCache = common.RevalidatingLookupCache() })
	defer proxy.Close()

	if reply := pop3ProxyPassReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "+OK") {
		t.Fatalf("PASS with a valid stored hash: %q, want +OK", reply)
	}
	common.StoreUnverifiableHash(t, backend.ResilientDB, account.Email, account.Password)
	time.Sleep(2 * common.LookupCacheRevalidationWindow)

	for i := 1; i <= 3; i++ {
		if reply := pop3ProxyPassReply(t, proxyAddr, account.Email, fmt.Sprintf("guess-%d", i)); !strings.HasPrefix(reply, "-ERR [SYS/TEMP]") {
			t.Errorf("PASS with guess %d against an unverifiable stored hash: %q, want -ERR [SYS/TEMP] ...", i, reply)
		}
	}
	if reply := pop3ProxyPassReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "-ERR [SYS/TEMP]") {
		t.Errorf("PASS with the cached password after the guesses: %q, want -ERR [SYS/TEMP] (the uncounted guesses were checked against the cached login)", reply)
	}
}
