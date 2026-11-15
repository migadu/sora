package lmtpproxy

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
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// newNotFoundProxy is an LMTP proxy whose remote lookup answers 404 for everyone,
// without database fallback, with the default lookup cache.
func newNotFoundProxy(t *testing.T, opts ServerOptions, response string) (*Server, *atomic.Int32) {
	t.Helper()
	var lookups atomic.Int32
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookups.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(lookup.Close)
	opts.Name = "neg-cache"
	opts.RemotePort = 24
	opts.ConnectTimeout = time.Second
	opts.RemoteLookup = &config.RemoteLookupConfig{
		Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "1s",
		LookupLocalUsers: false, UserNotFoundResponse: response,
	}
	srv, err := New(context.Background(), nil, "test-host", opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })
	return srv, &lookups
}

func recipientError(t *testing.T, srv *Server, to string) error {
	t.Helper()
	conn, peer := net.Pipe()
	t.Cleanup(func() { conn.Close(); peer.Close() })
	sess := newSession(srv, conn, nil)
	t.Cleanup(sess.cancel)
	return sess.handleRecipient(to, time.Now())
}

// TestLMTPCachedUnknownRecipientGetsTheFreshReply: the remote lookup is the authority
// on whether its users exist, so a cached "not found" from it gets the reply the fresh
// answer got, whatever the health of the default pool. With named pools and no default
// pool (valid when the lookup routes everyone) there is no default-pool backend at all,
// and every cached 404 used to become a 450 the MTA retries for days.
func TestLMTPCachedUnknownRecipientGetsTheFreshReply(t *testing.T) {
	noDefaultPool := ServerOptions{Pools: []proxy.PoolSpec{{Name: "sora1", Backends: []string{"127.0.0.1:1"}}}}
	flatList := ServerOptions{RemoteAddrs: []string{"127.0.0.1:1"}}

	for _, tc := range []struct {
		name     string
		opts     ServerOptions
		response string
		want     error
	}{
		{"named pools without default, reject", noDefaultPool, "reject", server.ErrUserNotFound},
		{"named pools without default, tempfail", noDefaultPool, "tempfail", server.ErrUserNotFoundTempFail},
		{"flat list, reject", flatList, "reject", server.ErrUserNotFound},
		{"flat list, tempfail", flatList, "tempfail", server.ErrUserNotFoundTempFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, lookups := newNotFoundProxy(t, tc.opts, tc.response)

			fresh := recipientError(t, srv, "nobody@example.com")
			if !errors.Is(fresh, tc.want) {
				t.Fatalf("fresh lookup: got %v, want %v", fresh, tc.want)
			}
			cached := recipientError(t, srv, "nobody@example.com")
			if n := lookups.Load(); n != 1 {
				t.Fatalf("remote lookup asked %d times, want 1 (the second recipient must be a cache hit)", n)
			}
			if !errors.Is(cached, tc.want) {
				t.Errorf("cache hit: got %v, want %v (the reply the fresh answer got)", cached, tc.want)
			}
		})
	}
}

// TestLMTPCachedDatabaseUnknownRecipientKeepsTheBackendGuard: a "not found" from the
// proxy's own database (which may lag the backends) is still deferred while no backend
// of the default pool is healthy, and is otherwise the 550 the fresh database lookup
// gives (user_not_found_response does not apply to the database fallback).
func TestLMTPCachedDatabaseUnknownRecipientKeepsTheBackendGuard(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts ServerOptions
		want error
	}{
		{"no default-pool backend", ServerOptions{Pools: []proxy.PoolSpec{{Name: "sora1", Backends: []string{"127.0.0.1:1"}}}}, server.ErrUserNotFoundTempFail},
		{"healthy backend", ServerOptions{RemoteAddrs: []string{"127.0.0.1:1"}}, server.ErrUserNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, lookups := newNotFoundProxy(t, tc.opts, "tempfail")
			// What the database fallback caches for an address it does not know.
			srv.lookupCache.Set(srv.name, "local-nobody@example.com", &lookupcache.CacheEntry{
				Result: lookupcache.AuthUserNotFound, IsNegative: true,
			})
			got := recipientError(t, srv, "local-nobody@example.com")
			if n := lookups.Load(); n != 0 {
				t.Fatalf("remote lookup asked %d times, want 0 (cache hit)", n)
			}
			if !errors.Is(got, tc.want) {
				t.Errorf("cache hit: got %v, want %v", got, tc.want)
			}
		})
	}
}
