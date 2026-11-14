package userapiproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/userapi"
)

// preflight sends a CORS preflight for path, as a browser does before a cross-origin
// call: no credentials, no body (Fetch Standard, CORS-preflight fetch).
func preflight(handler http.Handler, path, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodOptions, path, nil)
	r.Header.Set("Origin", origin)
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// newPoolsProxy is a real User API proxy (New) over pools, with the maintenance set
// loaded (nothing in maintenance) and returned for the test to change.
func newPoolsProxy(t *testing.T, pools []proxy.PoolSpec, lookup proxy.UserRoutingLookup) (*Server, *proxy.Maintenance) {
	t.Helper()
	s, err := New(context.Background(), &resilient.ResilientDatabase{}, ServerOptions{
		Name: "test-proxy", Addr: "127.0.0.1:0", JWTSecret: "test-secret-key-at-least-32-bytes!!",
		Pools: pools,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.cancel)
	m := proxy.NewMaintenance()
	m.Set(nil)
	s.connManager.SetMaintenance(m)
	s.routingLookup = lookup
	return s, m
}

// With named pools and no default pool (remote_lookup without lookup_local_users, the
// last step of the pool rollout), a CORS preflight names no user, so it has no pool to
// be confined to. It reaches no account (the backend answers every OPTIONS in its CORS
// middleware), so it is answered by a backend, as with a default pool: a browser
// client must be able to log in and call authenticated endpoints through the proxy.
func TestUserAPIProxy_PreflightWithoutDefaultPool(t *testing.T) {
	const origin = "https://app.example.com"
	api, err := userapi.New(nil, userapi.ServerOptions{
		Name:           "test-backend",
		JWTSecret:      "test-secret-key-at-least-32-bytes!!",
		AllowedOrigins: []string{origin},
	})
	if err != nil {
		t.Fatalf("userapi.New: %v", err)
	}
	backend := httptest.NewServer(api.SetupRoutes())
	t.Cleanup(backend.Close)

	lookup := poolAnswer("sora0")
	s, _ := newPoolsProxy(t, []proxy.PoolSpec{
		{Name: "sora0", Backends: []string{strings.TrimPrefix(backend.URL, "http://")}},
	}, lookup)
	handler := s.setupHandler()

	for _, path := range []string{"/user/auth/login", "/user/auth/refresh", "/user/mailboxes", "/user/messages/1"} {
		w := preflight(handler, path, origin)
		if w.Code != http.StatusOK {
			t.Errorf("preflight %s: status %d, want 200 (body %q)", path, w.Code, w.Body.String())
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Errorf("preflight %s: Access-Control-Allow-Origin = %q, want %q", path, got, origin)
		}
	}
	if asked := lookup.asked(); len(asked) != 0 {
		t.Errorf("a preflight asked the routing lookup for %v; it names no user", asked)
	}
}

// Which backend answers a preflight: one of the default pool, as before pools; failing
// that (no default pool, or none of its backends available), one of the first pool in
// configuration order that has a backend available. Never a backend in maintenance.
func TestUserAPIProxy_PreflightPoolOrder(t *testing.T) {
	newBackend := func(name string, hits *atomic.Int32) string {
		b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.Header().Set("X-Backend", name)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(b.Close)
		return strings.TrimPrefix(b.URL, "http://")
	}
	var hitsA, hitsB atomic.Int32
	a, b := newBackend("a", &hitsA), newBackend("b", &hitsB)
	const drained = "10.0.0.1:8081" // never dialed: in maintenance

	for _, c := range []struct {
		name        string
		pools       []proxy.PoolSpec
		maintenance []string
		want        string
	}{
		{"default pool listed last", []proxy.PoolSpec{
			{Name: "a", Backends: []string{a}},
			{Name: "b", Backends: []string{b}, Default: true},
		}, nil, "b"},
		{"no default pool", []proxy.PoolSpec{
			{Name: "a", Backends: []string{a}},
			{Name: "b", Backends: []string{b}},
		}, nil, "a"},
		{"no default pool, first pool in maintenance", []proxy.PoolSpec{
			{Name: "drained", Backends: []string{drained}},
			{Name: "b", Backends: []string{b}},
		}, []string{"10.0.0.1"}, "b"},
		{"default pool in maintenance", []proxy.PoolSpec{
			{Name: "drained", Backends: []string{drained}, Default: true},
			{Name: "a", Backends: []string{a}},
		}, []string{"10.0.0.1"}, "a"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, m := newPoolsProxy(t, c.pools, poolAnswer("a"))
			m.Set(c.maintenance)
			w := preflight(s.setupHandler(), "/user/mailboxes", "https://app.example.com")
			if w.Code != http.StatusOK || w.Header().Get("X-Backend") != c.want {
				t.Fatalf("status %d from backend %q, want 200 from %q (body %q)", w.Code, w.Header().Get("X-Backend"), c.want, w.Body.String())
			}
		})
	}
}

// Only a preflight leaves the pools' fail-closed rule: an auth request that names no
// user the proxy can route by (a login without an email, a refresh whose token the proxy
// refuses) is not sent to some pool's backend when there is no default pool. A backend
// may accept a token the proxy refused (clock skew at expiry), and its refresh then
// looks the token's user up in its own pool's database.
func TestUserAPIProxy_NamelessAuthRequestStaysOutOfThePools(t *testing.T) {
	var hits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	t.Cleanup(backend.Close)
	s, _ := newPoolsProxy(t, []proxy.PoolSpec{
		{Name: "sora0", Backends: []string{strings.TrimPrefix(backend.URL, "http://")}},
	}, poolAnswer("sora0"))
	handler := s.setupHandler()

	for _, c := range []struct{ path, body string }{
		{"/user/auth/login", `{"password":"x"}`},
		{"/user/auth/refresh", `{"token":"not-a-valid-token"}`},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, c.path, strings.NewReader(c.body)))
		if hits.Load() != 0 {
			t.Fatalf("POST %s %s reached a backend (status %d)", c.path, c.body, w.Code)
		}
	}
}
