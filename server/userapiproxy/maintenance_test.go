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

// An affinity to a backend in maintenance is not used; the user's affinity moves to the
// backend chosen instead and stays there after maintenance ends.
func TestGetBackendForUser_AffinityToMaintenanceBackend(t *testing.T) {
	s, m := newMaintenanceTestServer(t)

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
