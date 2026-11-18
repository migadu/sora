package managesieveproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestManageSieveProxyEmptyPasswordIsAFailedLogin: an empty password is a credential
// no account can have. The proxy's credential check refuses it without asking the
// lookup service, but like any other failed login: recorded by the auth rate limiter
// and in sora_authentication_attempts_total{protocol="managesieve_proxy",
// result="failure"}, the rule of docs/AUTHENTICATION.md section 3 (#1987). (#2067)
func TestManageSieveProxyEmptyPasswordIsAFailedLogin(t *testing.T) {
	const name = "empty-password"
	var lookups atomic.Int32
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookups.Add(1)
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer lookup.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := New(ctx, &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name: name, Addr: freeTestAddr(t), RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
		InsecureAuth: true,
		RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "2s"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	limiter := &failureCountingLimiter{}
	srv.authLimiter = limiter

	client, remote := net.Pipe()
	defer client.Close()
	defer remote.Close()
	sess := &Session{server: srv, clientConn: remote, listenerConn: remote, ctx: ctx, cancel: cancel}
	counter := metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", name, "localhost", "failure")
	before := testutil.ToFloat64(counter)
	if err := sess.authenticateUserWithAuthzID("", "user@example.com", "", time.Now()); !errors.Is(err, consts.ErrAuthenticationFailed) {
		t.Errorf("login: %v, want %v", err, consts.ErrAuthenticationFailed)
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
