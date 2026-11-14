package pop3proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestPOP3CachedLoginRoutesUnderBaseAddress: a login answered from the lookup cache must
// leave the session with the same username as the uncached login it replays. That
// username is the routing key (affinity, consistent hash), the authorization identity
// sent to the backend with master SASL credentials and the connection tracker's key.
// The main-database path names the user by the base address (without +detail or
// @SUFFIX) and caches no ActualEmail, so a cache hit without one must fall back to the
// base address, not to the name exactly as submitted (#681).
func TestPOP3CachedLoginRoutesUnderBaseAddress(t *testing.T) {
	cases := []struct {
		name        string
		submitted   string
		actualEmail string
		want        string
	}{
		{name: "plain address", submitted: "user@example.com", want: "user@example.com"},
		{name: "+detail", submitted: "user+tag@example.com", want: "user@example.com"},
		{name: "master suffix", submitted: "user@example.com@admin", want: "user@example.com"},
		{name: "+detail and master suffix", submitted: "user+tag@example.com@admin", want: "user@example.com"},
		{name: "case folded", submitted: "User+Tag@Example.COM", want: "user@example.com"},
		// A remote-lookup entry carries the address the lookup resolved; it still wins.
		{name: "resolved address", submitted: "user@example.com@TOKEN", actualEmail: "resolved@example.org", want: "resolved@example.org"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cache := newPOP3TestLookupCache(t)
			srv := &POP3ProxyServer{
				name:                       "test",
				hostname:                   "test-host",
				appCtx:                     ctx,
				cancel:                     cancel,
				connManager:                newPOP3TestConnManager(t, "127.0.0.1:1", 500*time.Millisecond), // nothing listens here
				lookupCache:                cache,
				authLimiter:                (*server.AuthRateLimiter)(nil), // rate limiting disabled
				positiveRevalidationWindow: 30 * time.Second,
				activeSessions:             make(map[*POP3ProxySession]struct{}),
				masterUsername:             "admin",
				masterPassword:             "master-secret",
			}

			// The entry a previous login with this name and password left behind.
			cache.Set("test", tc.submitted, &lookupcache.CacheEntry{
				AccountID:      42,
				PasswordDigest: lookupcache.NewPasswordDigest("secret"),
				ActualEmail:    tc.actualEmail,
				Result:         lookupcache.AuthSuccess,
			})

			client, remote := net.Pipe()
			defer client.Close()
			defer remote.Close()
			sess := &POP3ProxySession{server: srv, clientConn: client, listenerConn: client, ctx: ctx, cancel: cancel}

			// A cache hit goes on to connect to the backend, routed by the session
			// username; nothing listens there, so the login ends in a backend error.
			err := sess.authenticate(tc.submitted, "secret")
			if err == nil || errors.Is(err, consts.ErrAuthenticationFailed) {
				t.Fatalf("cached login: err = %v, want the unreachable backend's error (the cache hit was not taken)", err)
			}
			if sess.username != tc.want {
				t.Errorf("cached login %q: session username (routing key) = %q, want %q", tc.submitted, sess.username, tc.want)
			}
			if sess.submittedUsername != tc.submitted {
				t.Errorf("submittedUsername (lookup-cache key) = %q, want %q", sess.submittedUsername, tc.submitted)
			}
		})
	}
}

// replayAuthCache is the persistent auth cache of a proxy that knows the user, so the
// main-database login needs no PostgreSQL. It counts the logins that reached it.
type replayAuthCache struct {
	hash string
	gets atomic.Int32
}

func (c *replayAuthCache) Get(context.Context, string) (int64, string, error) {
	c.gets.Add(1)
	return 42, c.hash, nil
}
func (c *replayAuthCache) Put(context.Context, string, int64, string) error { return nil }
func (c *replayAuthCache) Invalidate(context.Context, string) error         { return nil }
func (c *replayAuthCache) InvalidateAccount(context.Context, int64) error   { return nil }

// authzidBackend is a POP3 backend that accepts every AUTH PLAIN and sends the
// authorization identity of each on the returned channel.
func authzidBackend(t *testing.T) (addr string, authzids <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan string, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				io.WriteString(conn, "+OK fake backend ready\r\n")
				line, _ := bufio.NewReader(conn).ReadString('\n')
				decoded, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(line, "AUTH PLAIN ")))
				got <- strings.SplitN(string(decoded), "\x00", 2)[0]
				io.WriteString(conn, "+OK logged in\r\n")
			}()
		}
	}()
	return ln.Addr().String(), got
}

// TestPOP3CachedLoginReplaysUncachedLogin runs the uncached main-database login and the
// lookup-cache hit that replays it, and compares them: the cached login must name the user
// exactly as the uncached one did, as the routing key, as the authorization identity sent
// to the backend and as the per-user activity metric, so none of them is split between the
// base address and the +detail form (#681).
func TestPOP3CachedLoginReplaysUncachedLogin(t *testing.T) {
	// Per-user metrics on, every user tracked from its first connection under its own name.
	enable, domain, threshold, maxUsers, hashNames := metrics.EnableUserMetrics, metrics.EnableDomainMetrics, metrics.UserMetricsThreshold, metrics.MaxTrackedUsers, metrics.HashUsernames
	metrics.Configure(true, domain, 1, 1000, false)
	t.Cleanup(func() { metrics.Configure(enable, domain, threshold, maxUsers, hashNames) })

	hash, err := db.GenerateBcryptHash("secret")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	authCache := &replayAuthCache{hash: hash}
	rdb := &resilient.ResilientDatabase{}
	rdb.SetAuthCache(authCache)
	backendAddr, authzids := authzidBackend(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &POP3ProxyServer{
		name:                       "test",
		hostname:                   "test-host",
		appCtx:                     ctx,
		cancel:                     cancel,
		connManager:                newPOP3TestConnManager(t, backendAddr, 2*time.Second),
		lookupCache:                newPOP3TestLookupCache(t),
		authLimiter:                (*server.AuthRateLimiter)(nil), // rate limiting disabled
		positiveRevalidationWindow: 30 * time.Second,
		activeSessions:             make(map[*POP3ProxySession]struct{}),
		rdb:                        rdb,
	}

	const (
		submitted = "Replay+Tag@Example.COM"
		base      = "replay@example.com"
		detailed  = "replay+tag@example.com"
	)
	activity := func(user string) float64 {
		return testutil.ToFloat64(metrics.HeavyUserOperations.WithLabelValues("pop3_proxy", user, "connection"))
	}
	baseBefore, detailedBefore := activity(base), activity(detailed)

	// Either login goes on to log in to the backend for the session username.
	login := func() (username, authzid string) {
		client, remote := net.Pipe()
		defer client.Close()
		defer remote.Close()
		sess := &POP3ProxySession{server: srv, clientConn: client, listenerConn: client, ctx: ctx, cancel: cancel}
		if err := sess.authenticate(submitted, "secret"); err != nil {
			t.Fatalf("login %q: %v", submitted, err)
		}
		sess.backendConn.Close()
		select {
		case authzid = <-authzids:
		case <-time.After(5 * time.Second):
			t.Fatal("the backend saw no AUTH PLAIN")
		}
		return sess.username, authzid
	}

	uncached, uncachedAuthzid := login()
	if n := authCache.gets.Load(); n != 1 {
		t.Fatalf("first login asked the database %d times, want 1", n)
	}
	cached, cachedAuthzid := login()
	if n := authCache.gets.Load(); n != 1 {
		t.Fatalf("second login asked the database again (%d times in all): not a lookup-cache hit", n)
	}

	if uncached != base || uncachedAuthzid != base {
		t.Errorf("uncached login: session username = %q, backend authorization identity = %q, want %q", uncached, uncachedAuthzid, base)
	}
	if cached != uncached {
		t.Errorf("cached login: session username (routing key) = %q, the uncached login it replays had %q", cached, uncached)
	}
	if cachedAuthzid != uncachedAuthzid {
		t.Errorf("cached login: backend authorization identity = %q, the uncached login it replays sent %q", cachedAuthzid, uncachedAuthzid)
	}
	if got := activity(base) - baseBefore; got != 2 {
		t.Errorf("per-user connections counted under %q: %v, want 2 (one per login)", base, got)
	}
	if got := activity(detailed) - detailedBefore; got != 0 {
		t.Errorf("per-user connections counted under %q: %v, want 0 (the +detail form names no user of its own)", detailed, got)
	}
}
