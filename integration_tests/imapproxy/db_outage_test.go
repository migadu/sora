//go:build integration

package imapproxy_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/imapproxy"
)

// imapProxyLoginReply sends one LOGIN on a fresh connection and returns the tagged reply.
func imapProxyLoginReply(t *testing.T, address, username, password string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	fmt.Fprintf(conn, "a1 LOGIN %q %q\r\n", username, password)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("LOGIN reply: %v", err)
		}
		if strings.HasPrefix(line, "a1 ") {
			return strings.TrimSpace(line)
		}
	}
}

// TestIMAPProxyLoginDuringDatabaseOutage: a proxy that authenticates against
// PostgreSQL answers a login the database cannot answer with NO [UNAVAILABLE]
// (RFC 5530 section 3), not as a wrong password, and does not count it in the auth
// rate limiter, so the user logs in once the database is back.
func TestIMAPProxyLoginDuringDatabaseOutage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, account := common.SetupIMAPServerWithMaster(t)
	defer backend.Close()

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	proxyAddr := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithRateLimiting(t, rdb, proxyAddr, []string{backend.Address}, common.DBOutageAuthRateLimit())
	defer proxy.Close()

	outage.Begin()
	for i := 1; i <= 3; i++ {
		if reply := imapProxyLoginReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "a1 NO [UNAVAILABLE]") {
			t.Errorf("LOGIN %d during a database outage: %q, want a1 NO [UNAVAILABLE] ...", i, reply)
		}
	}
	outage.End()

	if reply := imapProxyLoginReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "a1 OK") {
		t.Errorf("LOGIN after the outage: %q, want a1 OK (the outage was counted as failed logins)", reply)
	}
}

// TestIMAPProxyDatabaseOutageDropsCachedLogin: a password that misses a cached login
// older than positive_revalidation_window goes to the database. During an outage that
// gives no verdict, so the attempt is answered NO [UNAVAILABLE] and is not counted in the
// auth rate limiter. The cached login must go with it, or the cached password still signs
// in and every guess during the outage is checked against it, unseen by the rate limiter,
// until the entry expires. Once the database is back the user logs in: the guesses were
// not counted.
func TestIMAPProxyDatabaseOutageDropsCachedLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, account := common.SetupIMAPServerWithMaster(t)
	defer backend.Close()

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	proxyAddr := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithRateLimiting(t, rdb, proxyAddr, []string{backend.Address}, common.DBOutageAuthRateLimit(),
		func(o *imapproxy.ServerOptions) { o.LookupCache = common.RevalidatingLookupCache() })
	defer proxy.Close()

	if reply := imapProxyLoginReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "a1 OK") {
		t.Fatalf("LOGIN before the outage: %q, want a1 OK", reply)
	}
	outage.Begin()
	time.Sleep(2 * common.LookupCacheRevalidationWindow)

	for i := 1; i <= 3; i++ {
		if reply := imapProxyLoginReply(t, proxyAddr, account.Email, fmt.Sprintf("guess-%d", i)); !strings.HasPrefix(reply, "a1 NO [UNAVAILABLE]") {
			t.Errorf("LOGIN with guess %d during a database outage: %q, want a1 NO [UNAVAILABLE] ...", i, reply)
		}
	}
	if reply := imapProxyLoginReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "a1 NO [UNAVAILABLE]") {
		t.Errorf("LOGIN with the cached password after the guesses: %q, want a1 NO [UNAVAILABLE] (the uncounted guesses were checked against the cached login)", reply)
	}
	outage.End()

	if reply := imapProxyLoginReply(t, proxyAddr, account.Email, account.Password); !strings.HasPrefix(reply, "a1 OK") {
		t.Errorf("LOGIN after the outage: %q, want a1 OK (the guesses were counted as failed logins)", reply)
	}
}
