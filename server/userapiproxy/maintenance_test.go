package userapiproxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

const (
	drainedBackend = "10.0.0.5:8081"
	otherBackend   = "10.0.0.6:8081"
)

// newMaintenanceTestServer is a User API proxy over two backends whose first one can be
// put in maintenance through the returned set.
func newMaintenanceTestServer(t *testing.T) (*Server, *proxy.Maintenance) {
	t.Helper()
	cm, err := proxy.NewConnectionManager([]string{drainedBackend, otherBackend}, 8081, false, false, false, 2*time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	m := proxy.NewMaintenance()
	m.Set(nil) // loaded, nothing in maintenance
	cm.SetMaintenance(m)
	return &Server{name: "test", connManager: cm}, m
}

func backendFor(t *testing.T, s *Server) string {
	t.Helper()
	got, err := s.getBackendForUser(context.Background(), "user@example.com", 42)
	if err != nil {
		t.Fatalf("getBackendForUser: %v", err)
	}
	return got
}

// A cached route to a backend in maintenance is not used, and the route chosen instead
// replaces the cache entry.
func TestGetBackendForUser_CachedRouteToMaintenanceBackend(t *testing.T) {
	s, m := newMaintenanceTestServer(t)
	s.lookupCache = lookupcache.New(5*time.Minute, time.Minute, 100, time.Hour, 0)
	t.Cleanup(func() { _ = s.lookupCache.Stop(context.Background()) })
	s.lookupCache.Set(s.name, "user@example.com", &lookupcache.CacheEntry{
		AccountID: 42, ServerAddress: drainedBackend, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	if got := backendFor(t, s); got != drainedBackend {
		t.Fatalf("before maintenance: %q, want the cached %q", got, drainedBackend)
	}

	m.Set([]string{"10.0.0.5"})
	if got := backendFor(t, s); got != otherBackend {
		t.Fatalf("in maintenance: %q, want %q", got, otherBackend)
	}
	if cached, ok := s.lookupCache.Get(s.name, "user@example.com"); !ok || cached.ServerAddress != otherBackend {
		t.Fatalf("cache entry not replaced by the new route: %+v", cached)
	}
}

// A remote-lookup route naming a backend in maintenance gives way to consistent hashing,
// and the pin returns when maintenance ends.
func TestGetBackendForUser_RemoteLookupRouteToMaintenanceBackend(t *testing.T) {
	s, m := newMaintenanceTestServer(t)
	s.routingLookup = &fakeRoutingLookup{backend: drainedBackend}

	m.Set([]string{"10.0.0.5"})
	if got := backendFor(t, s); got != otherBackend {
		t.Fatalf("in maintenance: %q, want %q", got, otherBackend)
	}
	m.Set(nil)
	if got := backendFor(t, s); got != drainedBackend {
		t.Fatalf("after maintenance: %q, want the remote-lookup route %q", got, drainedBackend)
	}
}

// withAffinity gives s a real affinity manager (on a loopback gossip node).
func withAffinity(t *testing.T, s *Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gossipAddr := ln.Addr().String()
	ln.Close()
	clusterMgr, err := cluster.New(config.ClusterConfig{
		Enabled:   true,
		Addr:      gossipAddr,
		NodeID:    "userapi-maintenance-test",
		SecretKey: "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
	})
	if err != nil {
		t.Fatalf("cluster.New: %v", err)
	}
	t.Cleanup(func() { _ = clusterMgr.Shutdown() })
	s.affinityManager = server.NewAffinityManager(clusterMgr, true, time.Hour, time.Hour)
}

// An affinity to a backend in maintenance is not used; the user's affinity moves to the
// backend chosen instead and stays there after maintenance ends.
func TestGetBackendForUser_AffinityToMaintenanceBackend(t *testing.T) {
	s, m := newMaintenanceTestServer(t)
	withAffinity(t, s)
	s.affinityManager.SetBackend("user@example.com", drainedBackend, "userapi")

	m.Set([]string{"10.0.0.5"})
	if got := backendFor(t, s); got != otherBackend {
		t.Fatalf("in maintenance: %q, want %q", got, otherBackend)
	}
	m.Set(nil)
	if got := backendFor(t, s); got != otherBackend {
		t.Fatalf("after maintenance: %q, want %q (the user's new affinity)", got, otherBackend)
	}
}

// A remote-lookup route naming a backend in maintenance by another name (here
// "localhost", while maintenance lists its addresses) is skipped like one naming it.
func TestGetBackendForUser_RemoteLookupRouteByAnotherName(t *testing.T) {
	s, m := newMaintenanceTestServer(t)
	s.routingLookup = &fakeRoutingLookup{backend: "localhost:8081"}

	m.Set([]string{"127.0.0.1", "::1"})
	if got := backendFor(t, s); got == "localhost:8081" {
		t.Fatalf("routed to %q, a name of a backend in maintenance", got)
	}
}

// newHTTPTestProxy is a real User API proxy (New) in front of one backend, with its
// maintenance set not loaded yet.
func newHTTPTestProxy(t *testing.T, backend string) (*Server, *proxy.Maintenance) {
	t.Helper()
	s, err := New(context.Background(), &resilient.ResilientDatabase{}, ServerOptions{
		Name:        "test-proxy",
		Addr:        "127.0.0.1:0",
		RemoteAddrs: []string{backend},
		JWTSecret:   "test-secret-key-at-least-32-bytes!!",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m := proxy.NewMaintenance()
	s.connManager.SetMaintenance(m)
	return s, m
}

// Until the maintenance list has been read, every request is refused without reaching a
// backend: any of them might be in maintenance.
func TestUserAPIProxy_RefusesRequestsUntilMaintenanceLoaded(t *testing.T) {
	var hits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(backend.Close)
	s, m := newHTTPTestProxy(t, strings.TrimPrefix(backend.URL, "http://"))
	handler := s.setupHandler()

	login := func() int {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("POST", "/user/auth/login", strings.NewReader("{}")))
		return rec.Code
	}
	if code := login(); code != http.StatusServiceUnavailable || hits.Load() != 0 {
		t.Fatalf("before the list was read: status %d, %d backend hits; want 503 and none", code, hits.Load())
	}
	m.Set(nil)
	if code := login(); code != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("once the list was read: status %d, %d backend hits; want 200 and one", code, hits.Load())
	}
}

// The proxy's transport refuses to connect to an address in maintenance, whatever name it
// was asked to dial.
func TestUserAPIProxy_TransportRefusesAddressInMaintenance(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	s, m := newHTTPTestProxy(t, ln.Addr().String())

	m.Set([]string{"127.0.0.1", "::1"})
	if conn, err := s.transport.DialContext(context.Background(), "tcp", net.JoinHostPort("localhost", port)); err == nil {
		conn.Close()
		t.Fatal("dialed an address in maintenance")
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("backend in maintenance accepted %d connections", n)
	}

	m.Set(nil)
	conn, err := s.transport.DialContext(context.Background(), "tcp", net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatalf("dial after maintenance: %v", err)
	}
	conn.Close()
}

// With the lookup cache and affinity both on, as in production: a remote-lookup pin given
// up for maintenance comes back once it ends (here once the cached detour expires), as it
// does on the other proxies, where the remote lookup outranks affinity. The detour must
// not become the user's affinity, which the User API proxy consults before remote lookup.
func TestGetBackendForUser_RemoteLookupPinReturnsWithCacheAndAffinity(t *testing.T) {
	s, m := newMaintenanceTestServer(t)
	withAffinity(t, s)
	s.lookupCache = lookupcache.New(5*time.Minute, time.Minute, 100, time.Hour, 0)
	t.Cleanup(func() { _ = s.lookupCache.Stop(context.Background()) })
	s.routingLookup = &fakeRoutingLookup{backend: drainedBackend}

	if got := backendFor(t, s); got != drainedBackend {
		t.Fatalf("before maintenance: %q, want the remote-lookup route %q", got, drainedBackend)
	}
	m.Set([]string{"10.0.0.5"})
	if got := backendFor(t, s); got != otherBackend {
		t.Fatalf("in maintenance: %q, want %q", got, otherBackend)
	}
	m.Set(nil)
	s.lookupCache.InvalidateUser(s.name, "user@example.com") // the cached detour expires
	if got := backendFor(t, s); got != drainedBackend {
		t.Fatalf("after maintenance: %q, want the remote-lookup route %q back", got, drainedBackend)
	}
}

// A keep-alive connection the proxy opened to a backend before it entered maintenance
// would be reused without a dial, past the dial's maintenance check: idle connections
// are closed when the maintenance list changes.
func TestUserAPIProxy_ClosesIdleBackendConnectionsWhenMaintenanceChanges(t *testing.T) {
	var closed atomic.Int32
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	backend.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed.Add(1)
		}
	}
	backend.Start()
	t.Cleanup(backend.Close)
	addr := strings.TrimPrefix(backend.URL, "http://")
	s, m := newHTTPTestProxy(t, addr)
	m.Set(nil)

	rec := httptest.NewRecorder()
	s.setupHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/user/auth/login", strings.NewReader("{}")))
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status %d", rec.Code)
	}
	time.Sleep(50 * time.Millisecond)
	if closed.Load() != 0 {
		t.Fatal("test setup: the keep-alive connection closed on its own")
	}

	m.Set([]string{"127.0.0.1"})
	deadline := time.Now().Add(5 * time.Second)
	for closed.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("idle keep-alive connection to the backend still open after it entered maintenance")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Cached routes expire after the configured positive TTL, as the lookup cache does for
// every other proxy: a detour around a backend in maintenance lasts that long, not a fixed
// five minutes.
func TestGetBackendForUser_CachedRoutesUseThePositiveTTL(t *testing.T) {
	s, _ := newMaintenanceTestServer(t)
	s.lookupCache = lookupcache.New(30*time.Second, time.Minute, 100, time.Hour, 0)
	t.Cleanup(func() { _ = s.lookupCache.Stop(context.Background()) })

	backendFor(t, s)
	entry, ok := s.lookupCache.Get(s.name, "user@example.com")
	if !ok {
		t.Fatal("route not cached")
	}
	if left := time.Until(entry.ExpiresAt); left > 31*time.Second {
		t.Fatalf("cached route expires in %v, want the configured 30s", left)
	}
}
