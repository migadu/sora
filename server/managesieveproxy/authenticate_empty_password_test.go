package managesieveproxy

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestManageSieveProxyAuthenticateEmptyPasswordIsAFailedLogin: AUTHENTICATE PLAIN
// with an empty password, over the wire, is refused with the bad-credentials reply
// without asking the lookup service, but like any other failed login: recorded by
// the auth rate limiter and in
// sora_authentication_attempts_total{protocol="managesieve_proxy",result="failure"}
// (docs/AUTHENTICATION.md section 3). (#2067)
func TestManageSieveProxyAuthenticateEmptyPasswordIsAFailedLogin(t *testing.T) {
	const name = "authenticate-empty-password"
	var lookups atomic.Int32
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookups.Add(1)
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer lookup.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := freeTestAddr(t)
	srv, err := New(ctx, &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name: name, Addr: addr, RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
		InsecureAuth: true,
		RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "2s"},
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
	counter := metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", name, "localhost", "failure")
	before := testutil.ToFloat64(counter)
	conn.Write([]byte(`AUTHENTICATE "PLAIN" "` + base64.StdEncoding.EncodeToString([]byte("\x00user@example.com\x00")) + "\"\r\n"))
	if reply := readLineWithPrefix(t, r, "OK", "NO", "BYE"); reply != `NO "Authentication failed"` {
		t.Errorf("reply %q, want NO \"Authentication failed\"", reply)
	}
	if n := lookups.Load(); n != 0 {
		t.Errorf("the lookup service was asked %d times", n)
	}
	if n := limiter.failures.Load(); n != 1 {
		t.Errorf("%d failed attempts recorded in the auth rate limiter, want 1", n)
	}
	if grew := testutil.ToFloat64(counter) - before; grew != 1 {
		t.Errorf("sora_authentication_attempts_total{protocol=\"managesieve_proxy\",result=\"failure\"} grew by %v, want 1", grew)
	}
}
