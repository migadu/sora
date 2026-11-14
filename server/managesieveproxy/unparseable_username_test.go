package managesieveproxy

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestManageSieveProxyUnparseableUsernameIsAFailedLogin: on a proxy that
// authenticates against the database (no remote lookup), a login whose username
// does not parse as an address is a failed login like any other: recorded as a
// failure by the auth rate limiter and counted in
// sora_authentication_attempts_total{protocol="managesieve_proxy",result="failure"}.
func TestManageSieveProxyUnparseableUsernameIsAFailedLogin(t *testing.T) {
	const name = "unparseable-username"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeTestAddr(t)
	srv, err := New(ctx, &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name: name, Addr: addr, RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
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
	readLineWithPrefix(t, r, "OK")

	failures := func() float64 {
		return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", name, "localhost", "failure"))
	}
	recorded, before := limiter.failures.Load(), failures()
	// "\x00not-an-address\x00secret"
	const plain = "AG5vdC1hbi1hZGRyZXNzAHNlY3JldA=="
	conn.Write([]byte(`AUTHENTICATE "PLAIN" "` + plain + "\"\r\n"))
	if reply := readLineWithPrefix(t, r, "OK", "NO", "BYE"); reply != `NO "Authentication failed"` {
		t.Errorf("login with an unparseable username: %q, want NO \"Authentication failed\"", reply)
	}
	if n := limiter.failures.Load() - recorded; n != 1 {
		t.Errorf("%d failed attempts recorded in the auth rate limiter, want 1", n)
	}
	if grew := failures() - before; grew != 1 {
		t.Errorf("sora_authentication_attempts_total{protocol=\"managesieve_proxy\",result=\"failure\"} grew by %v, want 1", grew)
	}
}
