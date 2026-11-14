//go:build integration

package imapproxy_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/imapproxy"
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

// TestIMAPProxyUnverifiableStoredHashDropsCachedLogin: a login cached before the stored
// hash became unverifiable vouches for a password the database no longer holds. A guess
// that misses the cached password goes to the database, which answers no verdict, so
// the guess is not counted; the cached login must go with it, or every later guess is
// checked against the cached password, uncounted, until the entry expires.
func TestIMAPProxyUnverifiableStoredHashDropsCachedLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, account := common.SetupIMAPServerWithMaster(t)
	defer backend.Close()

	proxyAddr := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithRateLimiting(t, backend.ResilientDB, proxyAddr, []string{backend.Address}, common.DBOutageAuthRateLimit(),
		func(o *imapproxy.ServerOptions) { o.LookupCache = common.RevalidatingLookupCache() })
	defer proxy.Close()

	if reply := imapProxyLoginReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "a1 OK") {
		t.Fatalf("LOGIN with a valid stored hash: %q, want a1 OK", reply)
	}
	common.StoreUnverifiableHash(t, backend.ResilientDB, account.Email, account.Password)
	time.Sleep(2 * common.LookupCacheRevalidationWindow)

	for i := 1; i <= 3; i++ {
		if reply := imapProxyLoginReply(t, proxyAddr, account.Email, fmt.Sprintf("guess-%d", i)); !strings.HasPrefix(reply, "a1 NO [UNAVAILABLE]") {
			t.Errorf("LOGIN with guess %d against an unverifiable stored hash: %q, want a1 NO [UNAVAILABLE] ...", i, reply)
		}
	}
	if reply := imapProxyLoginReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "a1 NO [UNAVAILABLE]") {
		t.Errorf("LOGIN with the cached password after the guesses: %q, want a1 NO [UNAVAILABLE] (the uncounted guesses were checked against the cached login)", reply)
	}
}
