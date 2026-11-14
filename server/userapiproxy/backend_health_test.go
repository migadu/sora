package userapiproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/proxy"
)

// newHealthTestProxy is a real User API proxy (New) with backend health checks on
// (remote_health_checks, the default) and the maintenance list loaded (nothing in it).
func newHealthTestProxy(t *testing.T, opts ServerOptions) (*Server, *proxy.Maintenance) {
	t.Helper()
	opts.Name, opts.Addr, opts.JWTSecret = "health-proxy", "127.0.0.1:0", corsTestSecret
	opts.EnableBackendHealthCheck = true
	s, err := New(t.Context(), &resilient.ResilientDatabase{}, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m := proxy.NewMaintenance()
	m.Set(nil)
	s.connManager.SetMaintenance(m)
	return s, m
}

// liveBackend is a backend that answers every request 200, naming itself in X-Backend.
func liveBackend(t *testing.T, tlsOn bool) string {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "live")
		w.WriteHeader(http.StatusOK)
	})
	b := httptest.NewUnstartedServer(h)
	if tlsOn {
		b.StartTLS()
	} else {
		b.Start()
	}
	t.Cleanup(b.Close)
	return b.Listener.Addr().String()
}

// hangUpBackend accepts every connection and closes it at once: the TCP dial succeeds,
// a TLS handshake over it fails.
func hangUpBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().String()
}

// hashingTo is a key (an email, or a preflight's path) that the consistent hash of pool
// places on backend.
func hashingTo(t *testing.T, s *Server, pool, backend string, key func(int) string) string {
	t.Helper()
	for i := 0; i < 10000; i++ {
		if k := key(i); s.connManager.GetBackendByConsistentHashInPool(pool, k) == backend {
			return k
		}
	}
	t.Fatalf("no key hashes to %s", backend)
	return ""
}

func tokenFor(t *testing.T, email string) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTClaims{
		Email:            email,
		AccountID:        42,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
	}).SignedString([]byte(corsTestSecret))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// A backend that cannot be connected to is marked unhealthy after three consecutive
// failed connections, as on the other proxies, and its users are routed to another
// backend of the pool instead of being answered 502 for as long as it is down; an
// affinity to it is given up too. A TLS backend that takes the connection but fails
// the handshake is just as unusable and counts the same.
func TestUserAPIProxy_DeadBackendIsRoutedAround(t *testing.T) {
	for _, c := range []struct {
		name     string
		tls      bool
		affinity bool
	}{
		{name: "consistent hash"},
		{name: "affinity", affinity: true},
		{name: "TLS handshake fails", tls: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			dead := deadBackend(t)
			if c.tls {
				dead = hangUpBackend(t)
			}
			live := liveBackend(t, c.tls)
			s, _ := newHealthTestProxy(t, ServerOptions{RemoteAddrs: []string{dead, live}, RemoteTLS: c.tls})
			if c.affinity {
				withAffinity(t, s)
			}
			email := hashingTo(t, s, "", dead, func(i int) string { return fmt.Sprintf("user%d@example.com", i) })
			token := tokenFor(t, email)
			handler := s.setupHandler()

			for i := 1; i <= 4; i++ {
				r := httptest.NewRequest(http.MethodGet, "/user/mailboxes", nil)
				r.Header.Set("Authorization", "Bearer "+token)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if i <= 3 {
					if w.Code != http.StatusBadGateway {
						t.Fatalf("request %d: status %d, want 502 from the dead backend", i, w.Code)
					}
					continue
				}
				if w.Code != http.StatusOK || w.Header().Get("X-Backend") != "live" {
					t.Fatalf("request %d, after three failed connections: status %d from %q, want 200 from the live backend (body %q)", i, w.Code, w.Header().Get("X-Backend"), w.Body.String())
				}
			}
			if s.connManager.IsBackendHealthy(dead) {
				t.Errorf("%s is still reported healthy after three failed connections", dead)
			}
			if c.affinity {
				if backend, ok := s.affinityManager.GetBackend(email, "userapi"); !ok || backend != live {
					t.Errorf("affinity = %q (found %v), want the backend the user moved to (%s)", backend, ok, live)
				}
			}
		})
	}
}

// A CORS preflight is routed around a dead backend too: to another backend of the
// default pool, and, when no backend of a pool is left, to the next pool in
// configuration order.
func TestUserAPIProxy_PreflightRoutedAroundDeadBackend(t *testing.T) {
	for _, c := range []struct {
		name  string
		opts  func(dead, live string) ServerOptions
		hPool string // the pool whose hash places the preflight on the dead backend
	}{
		{"flat list", func(dead, live string) ServerOptions {
			return ServerOptions{RemoteAddrs: []string{dead, live}}
		}, ""},
		{"first pool down", func(dead, live string) ServerOptions {
			return ServerOptions{Pools: []proxy.PoolSpec{
				{Name: "down", Backends: []string{dead}},
				{Name: "up", Backends: []string{live}},
			}}
		}, "down"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dead, live := deadBackend(t), liveBackend(t, false)
			s, _ := newHealthTestProxy(t, c.opts(dead, live))
			path := hashingTo(t, s, c.hPool, dead, func(i int) string { return fmt.Sprintf("/user/messages/%d", i) })
			handler := s.setupHandler()

			for i := 1; i <= 4; i++ {
				w := preflight(handler, path, corsTestOrigin)
				if i <= 3 {
					if w.Code != http.StatusBadGateway {
						t.Fatalf("preflight %d: status %d, want 502 from the dead backend", i, w.Code)
					}
					continue
				}
				if w.Code != http.StatusOK || w.Header().Get("X-Backend") != "live" {
					t.Fatalf("preflight %d, after three failed connections: status %d from %q, want 200 from the live backend", i, w.Code, w.Header().Get("X-Backend"))
				}
			}
		})
	}
}

// Only a failure of the backend counts against it: not a dial the proxy refused itself
// (the backend is in maintenance), and not one its caller gave up on.
func TestUserAPIProxy_RefusedDialsDoNotCountAgainstTheBackend(t *testing.T) {
	dead := deadBackend(t)
	s, m := newHealthTestProxy(t, ServerOptions{RemoteAddrs: []string{dead}})
	binding, err := s.connManager.BindBackendRoute("", dead)
	if err != nil {
		t.Fatalf("BindBackendRoute: %v", err)
	}
	ctx := context.WithValue(context.Background(), backendRouteKey, binding)
	canceled, cancel := context.WithCancel(ctx)
	cancel()

	host, _, _ := net.SplitHostPort(dead)
	m.Set([]string{host})
	for i := 0; i < 3; i++ {
		if conn, err := s.transport.DialContext(ctx, "tcp", dead); err == nil {
			conn.Close()
			t.Fatal("dialed a backend in maintenance")
		}
	}
	m.Set(nil)
	for i := 0; i < 3; i++ {
		if conn, err := s.transport.DialContext(canceled, "tcp", dead); err == nil {
			conn.Close()
			t.Fatal("dial with a canceled context succeeded")
		}
	}
	if !s.connManager.IsBackendHealthy(dead) {
		t.Fatal("refused or abandoned dials marked the backend unhealthy")
	}
	for i := 0; i < 3; i++ {
		if conn, err := s.transport.DialContext(ctx, "tcp", dead); err == nil {
			conn.Close()
			t.Fatal("dialed a dead backend")
		}
	}
	if s.connManager.IsBackendHealthy(dead) {
		t.Fatal("three failed dials did not mark the backend unhealthy")
	}
}
