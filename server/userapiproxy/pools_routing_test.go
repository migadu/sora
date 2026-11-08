package userapiproxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/proxy"
)

// scriptedLookup answers every routing lookup with one scripted result.
type scriptedLookup struct {
	info   *proxy.UserRoutingInfo
	result proxy.AuthResult
	err    error

	mu     sync.Mutex
	emails []string
}

func (l *scriptedLookup) LookupUserRoute(ctx context.Context, email, password string) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return l.LookupUserRouteWithOptions(ctx, email, password, true)
}
func (l *scriptedLookup) LookupUserRouteWithOptions(_ context.Context, email, _ string, _ bool) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	l.mu.Lock()
	l.emails = append(l.emails, email)
	l.mu.Unlock()
	if l.info == nil {
		return nil, l.result, l.err
	}
	info := *l.info
	return &info, l.result, l.err
}
func (l *scriptedLookup) LookupUserRouteWithClientIP(ctx context.Context, email, password, _ string, routeOnly bool) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return l.LookupUserRouteWithOptions(ctx, email, password, routeOnly)
}
func (l *scriptedLookup) Close() error { return nil }

func (l *scriptedLookup) asked() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.emails...)
}

func poolAnswer(pool string) *scriptedLookup {
	return &scriptedLookup{info: &proxy.UserRoutingInfo{PoolName: pool, AccountID: 42}, result: proxy.AuthSuccess}
}

// With named pools, a lookup that fails or answers nothing usable is refused: a request
// carrying a token for account 42 must never reach the default pool's backends, where
// account 42 is someone else. Nothing is cached, so the next request asks again.
func TestRouteUser_NamedPoolsRefuseWhatTheLookupDidNotAnswer(t *testing.T) {
	for _, c := range []struct {
		name   string
		lookup *scriptedLookup
	}{
		{"lookup service down", &scriptedLookup{result: proxy.AuthTemporarilyUnavailable, err: errors.New("connection refused")}},
		{"answer without a route (e.g. 429)", &scriptedLookup{result: proxy.AuthFailed}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, _ := newPoolsMaintenanceServer(t) // sora0 is the default pool
			withAffinity(t, s)
			s.lookupCache = lookupcache.New(5*time.Minute, time.Minute, 100, time.Hour, 0)
			t.Cleanup(func() { _ = s.lookupCache.Stop(context.Background()) })
			s.routingLookup = c.lookup

			got, err := s.getBackendForUser(context.Background(), "user@example.com", 42)
			if err == nil {
				t.Fatalf("routed to %q without an answer naming the user's pool", got.addr)
			}
			if _, ok := s.lookupCache.Get(s.name, "user@example.com"); ok {
				t.Fatal("a non-answer was cached")
			}
			if backend, ok := s.affinityManager.GetBackend("user@example.com", "userapi"); ok {
				t.Fatalf("a non-answer wrote affinity %q", backend)
			}
			if _, err := s.getBackendForUser(context.Background(), "user@example.com", 42); err == nil || len(c.lookup.asked()) != 2 {
				t.Fatalf("second request: err %v after %d lookups, want a refusal after asking again", err, len(c.lookup.asked()))
			}
		})
	}
}

// A user the lookup does not know is routed into the default pool only when the proxy
// falls back to local users, as on every other proxy; the "not known" answer is cached
// (negative TTL) so a burst of requests asks once.
func TestRouteUser_UnknownUserNeedsLookupLocalUsers(t *testing.T) {
	notFound := func() *scriptedLookup { return &scriptedLookup{result: proxy.AuthUserNotFound} }

	s, _ := newPoolsMaintenanceServer(t)
	s.routingLookup = notFound()
	if got, err := s.getBackendForUser(context.Background(), "nobody@example.com", 42); err == nil {
		t.Fatalf("without lookup_local_users: routed to %q, want a refusal", got.addr)
	}

	s, _ = newPoolsMaintenanceServer(t)
	s.lookupLocalUsers = true
	lookup := notFound()
	s.routingLookup = lookup
	s.lookupCache = lookupcache.New(5*time.Minute, time.Minute, 100, time.Hour, 0)
	t.Cleanup(func() { _ = s.lookupCache.Stop(context.Background()) })
	for i := 0; i < 3; i++ {
		got, err := s.routeUser(context.Background(), "local@example.com", 0, true)
		if err != nil || got.addr != "10.0.0.1:8081" {
			t.Fatalf("with lookup_local_users: %q, %v; want the default pool's 10.0.0.1:8081", got.addr, err)
		}
	}
	if n := len(lookup.asked()); n != 1 {
		t.Fatalf("asked the lookup %d times, want once (the answer is cached)", n)
	}
}

// A flat remote_addrs list is one pool: a failed lookup still routes into it, as before
// pools existed.
func TestRouteUser_FlatListStillRoutesWhenTheLookupFails(t *testing.T) {
	s, _ := newMaintenanceTestServer(t)
	s.routingLookup = &scriptedLookup{result: proxy.AuthTemporarilyUnavailable, err: errors.New("down")}
	got, err := s.getBackendForUser(context.Background(), "user@example.com", 42)
	if err != nil || (got.addr != drainedBackend && got.addr != otherBackend) {
		t.Fatalf("flat list: %q, %v; want one of its backends", got.addr, err)
	}
}

// A login names a user nobody has authenticated yet: it is routed by that user's affinity
// and pool, but never writes or deletes affinity (no gossip per made-up user). A request
// with the user's token keeps affinity up to date.
func TestRouteUser_LoginsNeverWriteAffinity(t *testing.T) {
	s, _ := newPoolsMaintenanceServer(t)
	withAffinity(t, s)
	s.routingLookup = poolAnswer("sora1")

	if _, err := s.routeUser(context.Background(), "made-up@example.com", 0, true); err != nil {
		t.Fatalf("login route: %v", err)
	}
	if backend, ok := s.affinityManager.GetBackend("made-up@example.com", "userapi"); ok {
		t.Fatalf("a login wrote affinity %q", backend)
	}

	s.affinityManager.SetBackend("user@example.com", "10.0.0.1:8081", "userapi") // in sora0
	got, err := s.routeUser(context.Background(), "user@example.com", 0, true)
	if err != nil || !strings.HasPrefix(got.addr, "10.0.1.") {
		t.Fatalf("login with an out-of-pool affinity: %q, %v; want a sora1 backend", got.addr, err)
	}
	if backend, _ := s.affinityManager.GetBackend("user@example.com", "userapi"); backend != "10.0.0.1:8081" {
		t.Fatalf("a login changed the user's affinity to %q", backend)
	}
}

// Affinity is confined to the user's pool: an entry pointing into another pool (the user
// was moved by the lookup) is not followed, and the request with the user's token
// replaces it with a member of the new pool, which then keeps the user.
func TestRouteUser_AffinityFollowsThePool(t *testing.T) {
	s, _ := newPoolsMaintenanceServer(t)
	withAffinity(t, s)
	s.routingLookup = poolAnswer("sora1")
	s.affinityManager.SetBackend("user@example.com", "10.0.0.1:8081", "userapi") // sora0

	got, err := s.getBackendForUser(context.Background(), "user@example.com", 42)
	if err != nil || !strings.HasPrefix(got.addr, "10.0.1.") {
		t.Fatalf("%q, %v; want a sora1 backend", got.addr, err)
	}
	if backend, _ := s.affinityManager.GetBackend("user@example.com", "userapi"); backend != got.addr {
		t.Fatalf("affinity %q, want the new sora1 backend %q", backend, got.addr)
	}
	again, _ := s.getBackendForUser(context.Background(), "user@example.com", 42)
	if again.addr != got.addr {
		t.Fatalf("second request went to %q, want the affinity %q", again.addr, got.addr)
	}
}

// A pool route speaks to its backend with that pool's settings; a lookup pin with the
// proxy server's own, as the User API proxy always did.
func TestRouteUser_RouteSettings(t *testing.T) {
	s, _ := newPoolsMaintenanceServer(t) // sora1: TLS, verify, PROXY
	s.remoteTLS, s.remoteTLSVerify, s.remoteUseProxyProtocol = false, false, false
	s.routingLookup = poolAnswer("sora1")
	got, err := s.getBackendForUser(context.Background(), "user@example.com", 42)
	if err != nil || !got.tls || !got.tlsVerify || !got.proxyProtocol {
		t.Fatalf("pool route %+v, %v; want sora1's TLS, verify and PROXY settings", got, err)
	}

	s, _ = newPoolsMaintenanceServer(t)
	s.remoteTLS, s.remoteTLSVerify, s.remoteUseProxyProtocol = true, true, false
	s.routingLookup = &scriptedLookup{info: &proxy.UserRoutingInfo{ServerAddress: "10.0.1.1:8081", RemoteTLS: false}, result: proxy.AuthSuccess}
	got, err = s.getBackendForUser(context.Background(), "user@example.com", 42)
	if err != nil || got.addr != "10.0.1.1:8081" || !got.tls || !got.tlsVerify || got.proxyProtocol {
		t.Fatalf("pin %+v, %v; want the server's own settings (TLS, verify, no PROXY)", got, err)
	}
}

// newPoolsHTTPProxy is a real User API proxy (New) over named pools, with a loaded
// maintenance set and lookup answering every user with the given pool.
func newPoolsHTTPProxy(t *testing.T, opts ServerOptions, lookup proxy.UserRoutingLookup) http.Handler {
	t.Helper()
	opts.Name = "test-proxy"
	opts.Addr = "127.0.0.1:0"
	opts.JWTSecret = "test-secret-key-at-least-32-bytes!!"
	s, err := New(context.Background(), &resilient.ResilientDatabase{}, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m := proxy.NewMaintenance()
	m.Set(nil)
	s.connManager.SetMaintenance(m)
	s.routingLookup = lookup
	return s.setupHandler()
}

func login(handler http.Handler, body string) int {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("POST", "/user/auth/login", strings.NewReader(body)))
	return rec.Code
}

// Each pool's remote_tls_verify decides whether its backends' certificates are checked,
// whatever the [[server]] block says: a pool that verifies refuses a self-signed backend,
// and a pool that does not reaches it.
func TestUserAPIProxy_TLSVerifyIsPerPool(t *testing.T) {
	var hits atomic.Int32
	newBackend := func() string {
		b := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusTeapot)
		}))
		t.Cleanup(b.Close)
		return strings.TrimPrefix(b.URL, "https://")
	}
	verifying, trusting := newBackend(), newBackend() // both self-signed
	pools := []proxy.PoolSpec{
		{Name: "verifying", Backends: []string{verifying}, Settings: proxy.BackendSettings{TLS: true, TLSVerify: true}},
		{Name: "trusting", Backends: []string{trusting}, Settings: proxy.BackendSettings{TLS: true, TLSVerify: false}},
	}
	for _, serverVerify := range []bool{false, true} {
		handler := newPoolsHTTPProxy(t, ServerOptions{Pools: pools, RemoteTLSVerify: serverVerify}, poolAnswer("verifying"))
		before := hits.Load()
		if code := login(handler, `{"email":"user@example.com"}`); code != http.StatusBadGateway || hits.Load() != before {
			t.Fatalf("server verify=%v, pool verifies: status %d, backend hit %v; want 502 and no request served by the unverified backend", serverVerify, code, hits.Load() != before)
		}
		handler = newPoolsHTTPProxy(t, ServerOptions{Pools: pools, RemoteTLSVerify: serverVerify}, poolAnswer("trusting"))
		if code := login(handler, `{"email":"user@example.com"}`); code != http.StatusTeapot {
			t.Fatalf("server verify=%v, pool trusts: status %d, want the backend's 418", serverVerify, code)
		}
	}
}

// A login body over 64 KiB is refused with 413 before any backend or lookup is reached.
func TestUserAPIProxy_OversizedLoginBody(t *testing.T) {
	var hits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	t.Cleanup(backend.Close)
	lookup := poolAnswer("p")
	handler := newPoolsHTTPProxy(t, ServerOptions{Pools: []proxy.PoolSpec{
		{Name: "p", Backends: []string{strings.TrimPrefix(backend.URL, "http://")}, Default: true},
	}}, lookup)

	body := `{"email":"user@example.com","password":"` + strings.Repeat("x", 64<<10) + `"}`
	if code := login(handler, body); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", code)
	}
	if hits.Load() != 0 || len(lookup.asked()) != 0 {
		t.Fatalf("an oversized login reached the backend (%d) or the lookup (%d)", hits.Load(), len(lookup.asked()))
	}
}

// The proxy reads a login body as the backend does (the first JSON value), so trailing
// bytes cannot make it route by path while the backend logs the named user in.
func TestUserAPIProxy_LoginRoutedByTheUserTheBackendSees(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(backend.Close)
	lookup := poolAnswer("p")
	handler := newPoolsHTTPProxy(t, ServerOptions{Pools: []proxy.PoolSpec{
		{Name: "p", Backends: []string{strings.TrimPrefix(backend.URL, "http://")}, Default: true},
	}}, lookup)

	login(handler, `{"email":"user@example.com","password":"x"} trailing`)
	if asked := lookup.asked(); len(asked) != 1 || asked[0] != "user@example.com" {
		t.Fatalf("lookup asked for %v, want the login's user", asked)
	}
}
