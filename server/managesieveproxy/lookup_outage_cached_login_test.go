package managesieveproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

// TestManageSieveProxyLookupOutageDropsCachedLogin: a password that misses a cached login
// older than positive_revalidation_window goes to the lookup service. During an outage
// that gives no verdict, so the attempt is answered NO (TRYLATER) and is not counted in
// the auth rate limiter. The cached login must not outlive that attempt: while it did,
// the cached password still signed in, so every guess during the outage was checked
// against it, unseen by the rate limiter, until the entry expired.
func TestManageSieveProxyLookupOutageDropsCachedLogin(t *testing.T) {
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer lookup.Close()

	srv, err := New(context.Background(), &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name: "outage-cached-login", Addr: "127.0.0.1:0", RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
		InsecureAuth: true,
		RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "2s"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Stop()
	limiter := &verdictlessLimiter{}
	srv.authLimiter = limiter

	// A login the lookup service vouched for before the outage: older than the
	// revalidation window (30s by default), still within positive_ttl.
	now := time.Now()
	srv.lookupCache.Set(srv.name, "anna@example.com", &lookupcache.CacheEntry{
		AccountID:        1,
		PasswordDigest:   lookupcache.NewPasswordDigest("secret"),
		ActualEmail:      "anna@example.com",
		Result:           lookupcache.AuthSuccess,
		FromRemoteLookup: true,
		CreatedAt:        now.Add(-time.Minute),
		ExpiresAt:        now.Add(time.Minute),
	})

	login := func(password string) error {
		client, remote := net.Pipe()
		defer client.Close()
		defer remote.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sess := &Session{server: srv, clientConn: remote, listenerConn: remote, ctx: ctx, cancel: cancel}
		return sess.authenticateUser("anna@example.com", password, time.Now())
	}

	const guesses = 3
	for i := 1; i <= guesses; i++ {
		if err := login(fmt.Sprintf("guess-%d", i)); !errors.Is(err, server.ErrAuthServiceUnavailable) {
			t.Errorf("guess %d during a lookup outage: %v, want %v", i, err, server.ErrAuthServiceUnavailable)
		}
	}
	if err := login("secret"); !errors.Is(err, server.ErrAuthServiceUnavailable) {
		t.Errorf("cached password after %d uncounted guesses: %v, want %v (the guesses were checked against the cached login)", guesses, err, server.ErrAuthServiceUnavailable)
	}
	if n := limiter.failures.Load(); n != 0 {
		t.Errorf("%d failed login(s) recorded in the auth rate limiter during a lookup outage, want 0", n)
	}
}
