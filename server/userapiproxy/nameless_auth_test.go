package userapiproxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/userapi"
)

// newNamelessAuthProxy is a real User API proxy (New) built from opts, with the
// maintenance list loaded (nothing in maintenance) and a routing lookup that answers
// pool "sora0", returned so a test can tell whether it was asked.
func newNamelessAuthProxy(t *testing.T, opts ServerOptions) (http.Handler, *scriptedLookup) {
	t.Helper()
	opts.Name, opts.Addr, opts.JWTSecret = "nameless-proxy", "127.0.0.1:0", corsTestSecret
	s, err := New(t.Context(), &resilient.ResilientDatabase{}, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.cancel)
	m := proxy.NewMaintenance()
	m.Set(nil)
	s.connManager.SetMaintenance(m)
	lookup := poolAnswer("sora0")
	s.routingLookup = lookup
	return s.setupHandler(), lookup
}

// countingBackend serves a real User API backend (no database) and counts the requests
// that reach it.
func countingBackend(t *testing.T) (reference http.Handler, addr string, hits *atomic.Int32) {
	t.Helper()
	api, err := userapi.New(nil, userapi.ServerOptions{Name: "nameless-backend", JWTSecret: corsTestSecret})
	if err != nil {
		t.Fatalf("userapi.New: %v", err)
	}
	reference = api.SetupRoutes()
	hits = new(atomic.Int32)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		reference.ServeHTTP(w, r)
	}))
	t.Cleanup(backend.Close)
	return reference, strings.TrimPrefix(backend.URL, "http://"), hits
}

// An auth request that names no user the proxy can route by (a login without an email,
// a refresh without a token, a body that is not JSON, a method or path the User API does
// not serve) reaches no account on any backend: a backend answers it from the request
// alone. So it is answered by a backend of any pool, like a CORS preflight, whatever
// pools the proxy has. With named pools and no default pool it used to be refused 503,
// which a client takes for an outage and retries instead of logging in again.
//
// A refresh whose token the proxy refuses (expired, or not signed with its jwt_secret)
// is answered 401 by the proxy itself, as on every other endpoint, and reaches no
// backend, with a default pool or without: a backend whose clock is behind the proxy's
// could accept the token, and its refresh then reads the token's user from its own
// pool's database, which need not be the user's.
func TestUserAPIProxy_AuthRequestNamingNobodyIsAnsweredAsTheBackendAnswersIt(t *testing.T) {
	reference, addr, hits := countingBackend(t)

	otherKey, err := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTClaims{
		Email:            "user@example.com",
		AccountID:        42,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
	}).SignedString([]byte("another-secret-key-at-least-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}

	requests := []struct {
		name, method, path, body string
		refused                  bool // a refresh whose token the proxy refuses
	}{
		{"refresh with an expired token", "POST", "/user/auth/refresh", `{"token":"` + corsTestToken(t, -time.Hour) + `"}`, true},
		{"refresh with a token signed with another key", "POST", "/user/auth/refresh", `{"token":"` + otherKey + `"}`, true},
		{"refresh with a malformed token", "POST", "/user/auth/refresh", `{"token":"not-a-valid-token"}`, true},
		{"refresh without a token", "POST", "/user/auth/refresh", `{}`, false},
		{"refresh with an empty token", "POST", "/user/auth/refresh", `{"token":""}`, false},
		{"refresh body not JSON", "POST", "/user/auth/refresh", `token=x`, false},
		{"refresh without a body", "POST", "/user/auth/refresh", ``, false},
		{"login without an email", "POST", "/user/auth/login", `{"password":"secret"}`, false},
		{"login with an empty email", "POST", "/user/auth/login", `{"email":"","password":"secret"}`, false},
		{"login without an email, password not a string", "POST", "/user/auth/login", `{"password":5}`, false},
		{"login body not JSON", "POST", "/user/auth/login", `email=user@example.com`, false},
		{"login without a body", "POST", "/user/auth/login", ``, false},
		{"login with GET", "GET", "/user/auth/login", ``, false},
		{"refresh with PUT and an expired token", "PUT", "/user/auth/refresh", `{"token":"` + corsTestToken(t, -time.Hour) + `"}`, false},
		{"auth path the User API does not serve", "POST", "/user/auth/logout", ``, false},
	}

	for _, config := range []struct {
		name string
		opts ServerOptions
	}{
		{"named pool, no default pool", ServerOptions{Pools: []proxy.PoolSpec{{Name: "sora0", Backends: []string{addr}}}}},
		{"named default pool", ServerOptions{Pools: []proxy.PoolSpec{{Name: "sora0", Backends: []string{addr}, Default: true}}}},
		{"remote_addrs", ServerOptions{RemoteAddrs: []string{addr}}},
	} {
		proxied, lookup := newNamelessAuthProxy(t, config.opts)
		for _, req := range requests {
			t.Run(config.name+"/"+req.name, func(t *testing.T) {
				send := func(h http.Handler) *httptest.ResponseRecorder {
					var body io.Reader
					if req.body != "" {
						body = strings.NewReader(req.body)
					}
					r := httptest.NewRequest(req.method, req.path, body)
					r.Header.Set("Content-Type", "application/json")
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					return w
				}
				direct := send(reference)
				before := hits.Load()
				viaProxy := send(proxied)

				if direct.Code < 400 || direct.Code >= 500 {
					t.Fatalf("backend answered %d (%q); the case should be the client's error", direct.Code, direct.Body.String())
				}
				if viaProxy.Code != direct.Code {
					t.Fatalf("proxy answered %d (%q), want the backend's %d (%q)", viaProxy.Code, viaProxy.Body.String(), direct.Code, direct.Body.String())
				}
				if got, want := viaProxy.Header().Get("Content-Type"), direct.Header().Get("Content-Type"); got != want {
					t.Errorf("proxy's Content-Type = %q, want the backend's %q", got, want)
				}
				if direct.Code == http.StatusUnauthorized && direct.Header().Get("WWW-Authenticate") == "" {
					t.Errorf("backend's 401 carries no WWW-Authenticate challenge")
				}
				if got, want := viaProxy.Header().Values("WWW-Authenticate"), direct.Header().Values("WWW-Authenticate"); !reflect.DeepEqual(got, want) {
					t.Errorf("proxy's WWW-Authenticate = %q, want the backend's %q", got, want)
				}
				var got, want map[string]any
				if err := json.Unmarshal(direct.Body.Bytes(), &want); err != nil {
					t.Fatalf("backend's body %q: %v", direct.Body.String(), err)
				}
				if err := json.Unmarshal(viaProxy.Body.Bytes(), &got); err != nil || !reflect.DeepEqual(got, want) {
					t.Errorf("proxy's body = %q, want the backend's %q", viaProxy.Body.String(), direct.Body.String())
				}
				n := hits.Load() - before
				if req.refused && n != 0 {
					t.Errorf("the refresh with a token the proxy refuses reached a backend (%d times)", n)
				}
				if !req.refused && n != 1 {
					t.Errorf("the request reached a backend %d times, want once (a backend answers it)", n)
				}
			})
		}
		if asked := lookup.asked(); len(asked) != 0 {
			t.Errorf("%s: the routing lookup was asked for %v", config.name, asked)
		}
	}
}

func TestUserAPIProxy_RefreshWithoutAccountIdentityIsRefusedOnWire(t *testing.T) {
	_, addr, hits := countingBackend(t)
	const origin = "https://mail.example.com"
	for _, config := range []struct {
		name string
		opts ServerOptions
	}{
		{"named pool without default", ServerOptions{Pools: []proxy.PoolSpec{{Name: "sora0", Backends: []string{addr}}}}},
		{"named default pool", ServerOptions{Pools: []proxy.PoolSpec{{Name: "sora0", Backends: []string{addr}, Default: true}}}},
		{"remote_addrs", ServerOptions{RemoteAddrs: []string{addr}}},
	} {
		config.opts.AllowedOrigins = []string{origin}
		handler, lookup := newNamelessAuthProxy(t, config.opts)
		front := httptest.NewServer(handler)
		t.Cleanup(front.Close)
		for _, identity := range []struct {
			name, email string
			id          int64
		}{
			{"zero account", "user@example.com", 0},
			{"negative account", "user@example.com", -1},
			{"missing email", "", 42},
			{"blank email", " \t ", 42},
		} {
			t.Run(config.name+"/"+identity.name, func(t *testing.T) {
				token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTClaims{
					Email: identity.email, AccountID: identity.id,
					RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
				}).SignedString([]byte(corsTestSecret))
				if err != nil {
					t.Fatal(err)
				}
				body, err := json.Marshal(map[string]string{"token": token})
				if err != nil {
					t.Fatal(err)
				}
				r, err := http.NewRequest(http.MethodPost, front.URL+"/user/auth/refresh", strings.NewReader(string(body)))
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", origin)
				before := hits.Load()
				resp, err := front.Client().Do(r)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				var result map[string]string
				if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != http.StatusUnauthorized || result["error"] != "Invalid or expired token" {
					t.Errorf("refused identity: status=%d body=%v", resp.StatusCode, result)
				}
				if got, want := resp.Header.Values("WWW-Authenticate"), []string{`Bearer realm="user-api", error="invalid_token"`}; !reflect.DeepEqual(got, want) {
					t.Errorf("WWW-Authenticate = %q, want %q", got, want)
				}
				if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
					t.Errorf("CORS origin=%q", got)
				}
				if got := resp.Header.Get("Content-Type"); got != "application/json" {
					t.Errorf("Content-Type=%q", got)
				}
				if delta := hits.Load() - before; delta != 0 {
					t.Errorf("refused refresh reached backend %d times", delta)
				}
			})
		}
		if asked := lookup.asked(); len(asked) != 0 {
			t.Errorf("refused identity reached routing lookup: %v", asked)
		}
	}
}

// An email of blanks names nobody at the proxy (it trims the email to route by it), so
// it is a login without an email, which a backend answers 400 without a database lookup.
func TestUserAPIProxy_LoginWithABlankEmailIsAnswered400(t *testing.T) {
	_, addr, hits := countingBackend(t)
	proxied, _ := newNamelessAuthProxy(t, ServerOptions{Pools: []proxy.PoolSpec{{Name: "sora0", Backends: []string{addr}}}})

	w := httptest.NewRecorder()
	proxied.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/user/auth/login", strings.NewReader(`{"email":" \t ","password":"secret"}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d (%q), want 400", w.Code, w.Body.String())
	}
	if msg := errorBody(t, w); msg != "Email and password are required" {
		t.Errorf("error %q, want %q", msg, "Email and password are required")
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("the login reached a backend %d times, want once", n)
	}
}
