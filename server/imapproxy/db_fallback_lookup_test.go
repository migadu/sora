package imapproxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/proxy"
)

// countingRoutingLookup is a remote lookup that knows nobody: every query is a
// 404. It counts the queries so a test can see how many one login costs.
type countingRoutingLookup struct {
	mu    sync.Mutex
	calls int
}

func (c *countingRoutingLookup) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *countingRoutingLookup) notFound() (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return nil, proxy.AuthUserNotFound, nil
}

func (c *countingRoutingLookup) LookupUserRoute(ctx context.Context, email, password string) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return c.notFound()
}

func (c *countingRoutingLookup) LookupUserRouteWithOptions(ctx context.Context, email, password string, routeOnly bool) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return c.notFound()
}

func (c *countingRoutingLookup) LookupUserRouteWithClientIP(ctx context.Context, email, password, clientIP string, routeOnly bool) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return c.notFound()
}

func (c *countingRoutingLookup) Close() error { return nil }

// stubAuthCache is the persistent auth cache of a proxy that has already seen
// this user, so AuthenticateWithRetry verifies the password locally and the
// test needs no PostgreSQL.
type stubAuthCache struct {
	accountID int64
	hash      string
}

func (s *stubAuthCache) Get(ctx context.Context, address string) (int64, string, error) {
	return s.accountID, s.hash, nil
}

func (s *stubAuthCache) Put(ctx context.Context, address string, accountID int64, hashedPassword string) error {
	return nil
}

func (s *stubAuthCache) Invalidate(ctx context.Context, address string) error { return nil }

func (s *stubAuthCache) InvalidateAccount(ctx context.Context, accountID int64) error { return nil }

// TestDBFallbackLoginQueriesRemoteLookupOnce covers PROXY-4: with remote lookup
// plus local DB fallback, a DB-authenticated user used to cost two lookup round
// trips per cache-miss login. Authentication queried the lookup and got a 404,
// then left routing info nil, so DetermineRoute queried it again for the same
// user in the same login — a request that 404s again by construction.
func TestDBFallbackLoginQueriesRemoteLookupOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lookup := &countingRoutingLookup{}
	// Nothing listens on 127.0.0.1:1, so the dial fails fast; the login's cost
	// in lookups is what this test is about.
	connManager, err := proxy.NewConnectionManagerWithRouting([]string{"127.0.0.1:1"}, 143, false, false, false, 200*time.Millisecond, lookup, "test")
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}

	hash, err := db.GenerateBcryptHash("secret")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	rdb := &resilient.ResilientDatabase{}
	rdb.SetAuthCache(&stubAuthCache{accountID: 42, hash: hash})

	srv := &Server{
		name:                       "test",
		hostname:                   "test-host",
		ctx:                        ctx,
		cancel:                     cancel,
		activeSessions:             make(map[*Session]struct{}),
		connManager:                connManager,
		lookupCache:                newTestLookupCache(t),
		authLimiter:                &fakeAuthLimiter{},
		positiveRevalidationWindow: 30 * time.Second,
		rdb:                        rdb,
		remotelookupConfig:         &config.RemoteLookupConfig{LookupLocalUsers: true},
	}

	client, remote := net.Pipe()
	defer client.Close()
	defer remote.Close()

	sess := newSession(srv, client)

	if err := sess.authenticateUser("user@example.com", "secret"); err != nil {
		t.Fatalf("DB fallback authentication failed: %v", err)
	}
	if got := lookup.count(); got != 1 {
		t.Fatalf("authentication made %d remote lookups, want 1", got)
	}

	if err := sess.connectToBackend(); err == nil {
		t.Fatal("expected the backend dial to fail, nothing listens on 127.0.0.1:1")
	}
	if got := lookup.count(); got != 1 {
		t.Errorf("the login made %d remote lookups, want 1: the 404 from the first was not remembered, so routing repeated it", got)
	}
}
