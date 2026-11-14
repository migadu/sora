package imapproxy

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestCachedLoginRoutesUnderBaseAddress: a login answered from the lookup cache must
// leave the session with the same username as the uncached login it replays. That
// username is the routing key (affinity, consistent hash), the authorization identity
// sent to the backend with master SASL credentials and the connection tracker's key.
// The main-database path names the user by the base address (without +detail or
// @SUFFIX) and caches no ActualEmail, so a cache hit without one must fall back to the
// base address, not to the name exactly as submitted (#681).
func TestCachedLoginRoutesUnderBaseAddress(t *testing.T) {
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

			cache := newTestLookupCache(t)
			srv := &Server{
				name:                       "test",
				hostname:                   "test-host",
				ctx:                        ctx,
				cancel:                     cancel,
				activeSessions:             make(map[*Session]struct{}),
				connManager:                newTestConnManager(t, "127.0.0.1:1"),
				lookupCache:                cache,
				authLimiter:                &fakeAuthLimiter{},
				positiveRevalidationWindow: 30 * time.Second,
				masterUsername:             []byte("admin"),
				masterPassword:             []byte("master-secret"),
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
			sess := newSession(srv, client)

			if err := sess.authenticateUser(tc.submitted, "secret"); err != nil {
				t.Fatalf("cached login: %v", err)
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

// TestCachedLoginReplaysUncachedLogin runs the uncached main-database login and the
// lookup-cache hit that replays it, and compares them: the cached login must name the user
// exactly as the uncached one did, as the routing key and as the per-user activity metric,
// so neither is split between the base address and the +detail form (#681).
func TestCachedLoginReplaysUncachedLogin(t *testing.T) {
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &Server{
		name:                       "test",
		hostname:                   "test-host",
		ctx:                        ctx,
		cancel:                     cancel,
		activeSessions:             make(map[*Session]struct{}),
		connManager:                newTestConnManager(t, "127.0.0.1:1"),
		lookupCache:                newTestLookupCache(t),
		authLimiter:                &fakeAuthLimiter{},
		positiveRevalidationWindow: 30 * time.Second,
		rdb:                        rdb,
	}

	const (
		submitted = "Replay+Tag@Example.COM"
		base      = "replay@example.com"
		detailed  = "replay+tag@example.com"
	)
	activity := func(user string) float64 {
		return testutil.ToFloat64(metrics.HeavyUserOperations.WithLabelValues("imap_proxy", user, "connection"))
	}
	baseBefore, detailedBefore := activity(base), activity(detailed)

	login := func() string {
		client, remote := net.Pipe()
		defer client.Close()
		defer remote.Close()
		sess := newSession(srv, client)
		if err := sess.authenticateUser(submitted, "secret"); err != nil {
			t.Fatalf("login %q: %v", submitted, err)
		}
		return sess.username
	}

	uncached := login()
	if n := authCache.gets.Load(); n != 1 {
		t.Fatalf("first login asked the database %d times, want 1", n)
	}
	cached := login()
	if n := authCache.gets.Load(); n != 1 {
		t.Fatalf("second login asked the database again (%d times in all): not a lookup-cache hit", n)
	}

	if uncached != base {
		t.Errorf("uncached login: session username = %q, want %q", uncached, base)
	}
	if cached != uncached {
		t.Errorf("cached login: session username (routing key) = %q, the uncached login it replays had %q", cached, uncached)
	}
	if got := activity(base) - baseBefore; got != 2 {
		t.Errorf("per-user connections counted under %q: %v, want 2 (one per login)", base, got)
	}
	if got := activity(detailed) - detailedBefore; got != 0 {
		t.Errorf("per-user connections counted under %q: %v, want 0 (the +detail form names no user of its own)", detailed, got)
	}
}
