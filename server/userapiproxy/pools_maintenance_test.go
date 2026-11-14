package userapiproxy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/server/proxy"
)

// newPoolsMaintenanceServer is a User API proxy over two named pools, sora0 (the default,
// one backend) and sora1 (two), whose maintenance set the returned handle controls.
func newPoolsMaintenanceServer(t *testing.T) (*Server, *proxy.Maintenance) {
	t.Helper()
	cm, err := proxy.NewConnectionManagerWithPools([]proxy.PoolSpec{
		{Name: "sora0", Backends: []string{"10.0.0.1"}, Default: true},
		{Name: "sora1", Backends: []string{"10.0.1.1", "10.0.1.2"},
			Settings: proxy.BackendSettings{TLS: true, TLSVerify: true, UseProxyProtocol: true}},
	}, 8081, 2*time.Second, nil, "test", true)
	if err != nil {
		t.Fatalf("NewConnectionManagerWithPools: %v", err)
	}
	m := proxy.NewMaintenance()
	m.Set(nil)
	cm.SetMaintenance(m)
	return &Server{name: "test", connManager: cm}, m
}

// A lookup pin to a backend in maintenance is routed among its own pool's siblings with
// that pool's backend-leg settings, never into the default pool, and the pin returns once
// maintenance ends; the same holds when the pin comes from the lookup cache.
func TestGetBackendForUser_PinInMaintenanceStaysInItsPool(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprintf("cached=%v", cached), func(t *testing.T) {
			s, m := newPoolsMaintenanceServer(t)
			withAffinity(t, s)
			s.routingLookup = &fakeRoutingLookup{backend: "10.0.1.1:8081"}
			if cached {
				s.lookupCache = lookupcache.New("test", "test", 5*time.Minute, time.Minute, 100, time.Hour, 0)
				t.Cleanup(func() { _ = s.lookupCache.Stop(context.Background()) })
			}
			route := func() backendRoute {
				t.Helper()
				got, err := s.getBackendForUser(context.Background(), "user@example.com", 42)
				if err != nil {
					t.Fatalf("getBackendForUser: %v", err)
				}
				return got
			}

			if got := route(); got.addr != "10.0.1.1:8081" {
				t.Fatalf("before maintenance: %q, want the pin", got.addr)
			}
			if cached {
				s.routingLookup = nil // from here on only the cached answer can route
			}

			m.Set([]string{"10.0.1.1"})
			got := route()
			if got.addr != "10.0.1.2:8081" {
				t.Fatalf("in maintenance: %q, want the pinned backend's sibling 10.0.1.2:8081 (not sora0)", got.addr)
			}
			if !got.tls || !got.proxyProtocol {
				t.Fatalf("in maintenance: detour without sora1's settings: %+v", got)
			}
			if backend, ok := s.affinityManager.GetBackend("user@example.com", "userapi"); ok && backend == got.addr {
				t.Fatalf("the detour became the user's affinity (%q); only the pin should route this user", backend)
			}

			m.Set(nil)
			if got := route(); got.addr != "10.0.1.1:8081" {
				t.Fatalf("after maintenance: %q, want the pin back", got.addr)
			}
		})
	}
}

// With the whole pool of the pinned backend in maintenance the request is refused, not
// sent to the default pool.
func TestGetBackendForUser_PinInMaintenanceWholePool(t *testing.T) {
	s, m := newPoolsMaintenanceServer(t)
	s.routingLookup = &fakeRoutingLookup{backend: "10.0.1.1:8081"}
	m.Set([]string{"10.0.1.1", "10.0.1.2"})
	if got, err := s.getBackendForUser(context.Background(), "user@example.com", 42); err == nil {
		t.Fatalf("routed to %q while every backend of the user's pool is in maintenance", got.addr)
	}
}
