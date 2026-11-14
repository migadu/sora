package pop3proxy

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestPOP3ProxyUnparseableUsernameIsAFailedLogin: on a proxy that authenticates
// against the database (no remote lookup), a login whose username does not parse
// as an address is a failed login like any other: recorded as a failure by the auth
// rate limiter and counted in
// sora_authentication_attempts_total{protocol="pop3_proxy",result="failure"}.
func TestPOP3ProxyUnparseableUsernameIsAFailedLogin(t *testing.T) {
	const name = "unparseable-username"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeTestAddr(t)
	srv, err := New(ctx, "localhost", addr, &resilient.ResilientDatabase{}, POP3ProxyServerOptions{
		Name: name, RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
		InsecureAuth: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	limiter := &failureCountingLimiter{}
	srv.authLimiter = limiter
	go func() { _ = srv.Start() }()
	defer srv.Stop()

	conn, r := dialTest(t, addr)
	readLineWithPrefix(t, r, "+OK")

	failures := func() float64 {
		return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", name, "localhost", "failure"))
	}
	recorded, before := limiter.failures.Load(), failures()
	conn.Write([]byte("USER not-an-address\r\n"))
	readLineWithPrefix(t, r, "+OK", "-ERR")
	conn.Write([]byte("PASS secret\r\n"))
	if reply := readLineWithPrefix(t, r, "+OK", "-ERR"); reply != "-ERR [AUTH] Authentication failed" {
		t.Errorf("login with an unparseable username: %q, want -ERR [AUTH] Authentication failed", reply)
	}
	if n := limiter.failures.Load() - recorded; n != 1 {
		t.Errorf("%d failed attempts recorded in the auth rate limiter, want 1", n)
	}
	if grew := failures() - before; grew != 1 {
		t.Errorf("sora_authentication_attempts_total{protocol=\"pop3_proxy\",result=\"failure\"} grew by %v, want 1", grew)
	}
}
