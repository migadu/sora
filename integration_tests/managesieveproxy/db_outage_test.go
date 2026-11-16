//go:build integration

package managesieveproxy_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/managesieveproxy"
)

// sieveProxyAuthReply sends one AUTHENTICATE PLAIN on a fresh connection and returns the reply.
func sieveProxyAuthReply(t *testing.T, address, username, password string) string {
	t.Helper()
	client, err := NewManageSieveClient(address)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()
	encoded := base64.StdEncoding.EncodeToString([]byte("\x00" + username + "\x00" + password))
	if err := client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded)); err != nil {
		t.Fatalf("AUTHENTICATE: %v", err)
	}
	resp, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("AUTHENTICATE read: %v", err)
	}
	return resp
}

// TestManageSieveProxyLoginDuringDatabaseOutage: a proxy that authenticates against
// PostgreSQL answers a login the database cannot answer with NO (TRYLATER) (RFC 5804
// section 1.3), not as a failed authentication, and does not count it in the auth
// rate limiter, so the user logs in once the database is back.
func TestManageSieveProxyLoginDuringDatabaseOutage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, account := common.SetupManageSieveServerWithMaster(t)
	defer backend.Close()

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	proxyAddr := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithRateLimiting(t, rdb, proxyAddr, []string{backend.Address}, common.DBOutageAuthRateLimit())
	defer proxy.Close()

	outage.Begin()
	for i := 1; i <= 3; i++ {
		if reply := sieveProxyAuthReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "NO (TRYLATER)") {
			t.Errorf("AUTHENTICATE %d during a database outage: %q, want NO (TRYLATER) ...", i, reply)
		}
	}
	outage.End()

	if reply := sieveProxyAuthReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "OK") {
		t.Errorf("AUTHENTICATE after the outage: %q, want OK (the outage was counted as failed logins)", reply)
	}
}

// TestManageSieveProxyDatabaseOutageDropsCachedLogin: a password that misses a cached
// login older than positive_revalidation_window goes to the database. During an outage
// that gives no verdict, so the attempt is answered NO (TRYLATER) and is not counted in
// the auth rate limiter. The cached login must go with it, or the cached password still
// signs in and every guess during the outage is checked against it, unseen by the rate
// limiter, until the entry expires. Only the miss ends it: before the guesses, the
// cached password still signs in during the outage. Once the database is back the user
// logs in: the guesses were not counted.
func TestManageSieveProxyDatabaseOutageDropsCachedLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, account := common.SetupManageSieveServerWithMaster(t)
	defer backend.Close()

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	proxyAddr := common.GetRandomAddress(t)
	proxy := setupManageSieveProxyWithRateLimiting(t, rdb, proxyAddr, []string{backend.Address}, common.DBOutageAuthRateLimit(),
		func(o *managesieveproxy.ServerOptions) { o.LookupCache = common.RevalidatingLookupCache() })
	defer proxy.Close()

	if reply := sieveProxyAuthReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "OK") {
		t.Fatalf("AUTHENTICATE before the outage: %q, want OK", reply)
	}
	outage.Begin()
	time.Sleep(2 * common.LookupCacheRevalidationWindow)

	if reply := sieveProxyAuthReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "OK") {
		t.Fatalf("AUTHENTICATE with the cached password during the outage, before any guess: %q, want OK (a cached login serves until a password misses it)", reply)
	}

	for i := 1; i <= 3; i++ {
		if reply := sieveProxyAuthReply(t, proxyAddr, account.Email, fmt.Sprintf("guess-%d", i)); !strings.HasPrefix(reply, "NO (TRYLATER)") {
			t.Errorf("AUTHENTICATE with guess %d during a database outage: %q, want NO (TRYLATER) ...", i, reply)
		}
	}
	if reply := sieveProxyAuthReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "NO (TRYLATER)") {
		t.Errorf("AUTHENTICATE with the cached password after the guesses: %q, want NO (TRYLATER) (the uncounted guesses were checked against the cached login)", reply)
	}
	outage.End()

	if reply := sieveProxyAuthReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "OK") {
		t.Errorf("AUTHENTICATE after the outage: %q, want OK (the guesses were counted as failed logins)", reply)
	}
}
