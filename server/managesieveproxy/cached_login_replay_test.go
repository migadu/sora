package managesieveproxy

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/proxy"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

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

// TestManageSieveCachedLoginReplaysUncachedLogin runs the uncached main-database login and
// the lookup-cache hit that replays it, and compares them: the cached login must name the
// user exactly as the uncached one did, as the routing key and as the per-user activity
// metric, so neither is split between the base address and the +detail form (#681).
func TestManageSieveCachedLoginReplaysUncachedLogin(t *testing.T) {
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

	connManager, err := proxy.NewConnectionManager([]string{"127.0.0.1:1"}, 4190, false, false, false, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &Server{
		name:                       "test",
		hostname:                   "test-host",
		ctx:                        ctx,
		cancel:                     cancel,
		connManager:                connManager,
		lookupCache:                newMSTestLookupCache(t),
		authLimiter:                &verdictlessLimiter{},
		positiveRevalidationWindow: 30 * time.Second,
		activeSessions:             make(map[*Session]struct{}),
		rdb:                        rdb,
	}

	const (
		submitted = "Replay+Tag@Example.COM"
		base      = "replay@example.com"
		detailed  = "replay+tag@example.com"
	)
	activity := func(user string) float64 {
		return testutil.ToFloat64(metrics.HeavyUserOperations.WithLabelValues("managesieve_proxy", user, "connection"))
	}
	baseBefore, detailedBefore := activity(base), activity(detailed)

	login := func() string {
		client, remote := net.Pipe()
		defer client.Close()
		defer remote.Close()
		sess := &Session{server: srv, clientConn: remote, listenerConn: remote, ctx: ctx, cancel: cancel}
		if err := sess.authenticateUser(submitted, "secret", time.Now()); err != nil {
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
