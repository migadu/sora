package userapiproxy

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/userapi"
)

const (
	corsTestSecret = "test-secret-key-at-least-32-bytes!!"
	corsTestOrigin = "https://app.example.com"
)

// corsTestToken is a token for user@example.com signed with corsTestSecret, expiring
// after ttl (a negative ttl gives an expired one).
func corsTestToken(t *testing.T, ttl time.Duration) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTClaims{
		Email:            "user@example.com",
		AccountID:        42,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl))},
	}).SignedString([]byte(corsTestSecret))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// newCORSTestProxy is a real User API proxy (New) with allowed_origins in front of one
// backend, with its maintenance list not loaded yet.
func newCORSTestProxy(t *testing.T, backend string, origins []string) (*Server, *proxy.Maintenance) {
	t.Helper()
	s, err := New(t.Context(), &resilient.ResilientDatabase{}, ServerOptions{
		Name:           "cors-proxy",
		Addr:           "127.0.0.1:0",
		RemoteAddrs:    []string{backend},
		JWTSecret:      corsTestSecret,
		AllowedOrigins: origins,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m := proxy.NewMaintenance()
	s.connManager.SetMaintenance(m)
	return s, m
}

// deadBackend is an address nothing listens on.
func deadBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// corsHeaders is the part of a response header a CORS policy decides.
func corsHeaders(h http.Header) http.Header {
	out := http.Header{}
	for k, v := range h {
		if strings.HasPrefix(k, "Access-Control-") || k == "Vary" {
			out[k] = v
		}
	}
	return out
}

// varyOrigins counts the Origin entries of the Vary header.
func varyOrigins(h http.Header) int {
	n := 0
	for _, v := range h.Values("Vary") {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), "Origin") {
				n++
			}
		}
	}
	return n
}

// A browser hands a cross-origin page a response only if it carries the CORS headers
// that allow the page's origin (Fetch Standard, "CORS check"); otherwise fetch rejects as
// on a network error. A token the proxy refuses must therefore be answered with the CORS
// headers the backend sends with its own 401, or the page cannot tell an expired token
// (refresh it) from an outage.
func TestUserAPIProxy_RefusedTokenCarriesTheBackendsCORSHeaders(t *testing.T) {
	expired := corsTestToken(t, -time.Hour)
	for _, policy := range []struct {
		name    string
		origins []string
	}{
		{"listed", []string{corsTestOrigin}},
		{"wildcard", []string{"*"}},
		{"listed then wildcard", []string{corsTestOrigin, "*"}},
		{"none", nil},
	} {
		api, err := userapi.New(nil, userapi.ServerOptions{Name: "cors-backend", JWTSecret: corsTestSecret, AllowedOrigins: policy.origins})
		if err != nil {
			t.Fatalf("userapi.New: %v", err)
		}
		backend := api.SetupRoutes()
		s, m := newCORSTestProxy(t, deadBackend(t), policy.origins) // never dialed: the token is refused first
		m.Set(nil)
		proxied := s.setupHandler()

		for _, origin := range []string{corsTestOrigin, "https://other.example.org", ""} {
			t.Run(policy.name+"/origin="+origin, func(t *testing.T) {
				get := func(h http.Handler) *httptest.ResponseRecorder {
					r := httptest.NewRequest(http.MethodGet, "/user/mailboxes", nil)
					if origin != "" {
						r.Header.Set("Origin", origin)
					}
					r.Header.Set("Authorization", "Bearer "+expired)
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					return w
				}
				direct, viaProxy := get(backend), get(proxied)
				if direct.Code != http.StatusUnauthorized || viaProxy.Code != http.StatusUnauthorized {
					t.Fatalf("expired token: backend %d, proxy %d; want 401 from both", direct.Code, viaProxy.Code)
				}
				if got, want := corsHeaders(viaProxy.Header()), corsHeaders(direct.Header()); !reflect.DeepEqual(got, want) {
					t.Errorf("proxy's 401 CORS headers = %v, want the backend's %v", got, want)
				}
			})
		}
	}
}

// Every response the proxy writes itself, without a backend having answered, carries the
// CORS headers of its allowed_origins, Vary: Origin included (the answer depends on the
// request's Origin).
func TestUserAPIProxy_OwnErrorsCarryCORSHeaders(t *testing.T) {
	valid := corsTestToken(t, time.Hour)
	s, m := newCORSTestProxy(t, deadBackend(t), []string{corsTestOrigin})
	handler := s.setupHandler()

	for _, tc := range []struct {
		name        string
		maintenance []string // nil: loaded and empty
		notLoaded   bool
		method      string
		path        string
		token       string
		body        string
		want        int
	}{
		{name: "maintenance list not loaded", notLoaded: true, method: http.MethodGet, path: "/user/mailboxes", token: valid, want: http.StatusServiceUnavailable},
		{name: "no token", method: http.MethodGet, path: "/user/mailboxes", want: http.StatusUnauthorized},
		{name: "expired token", method: http.MethodGet, path: "/user/mailboxes", token: corsTestToken(t, -time.Hour), want: http.StatusUnauthorized},
		{name: "login body too large", method: http.MethodPost, path: "/user/auth/login", body: strings.Repeat("x", maxAuthBodyBytes+1), want: http.StatusRequestEntityTooLarge},
		{name: "no backend outside maintenance", maintenance: []string{"127.0.0.1"}, method: http.MethodGet, path: "/user/mailboxes", token: valid, want: http.StatusServiceUnavailable},
		{name: "backend unreachable", method: http.MethodGet, path: "/user/mailboxes", token: valid, want: http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.notLoaded {
				m.Set(tc.maintenance)
			}
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Origin", corsTestOrigin)
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			if w.Code != tc.want {
				t.Fatalf("status %d, want %d (body %q)", w.Code, tc.want, w.Body.String())
			}
			if got := w.Header().Values("Access-Control-Allow-Origin"); len(got) != 1 || got[0] != corsTestOrigin {
				t.Errorf("Access-Control-Allow-Origin = %q, want [%q]", got, corsTestOrigin)
			}
			if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
				t.Errorf("Access-Control-Allow-Credentials = %q, want \"true\"", got)
			}
			if n := varyOrigins(w.Header()); n != 1 {
				t.Errorf("Vary = %q, want Origin in it once", w.Header().Values("Vary"))
			}
		})
	}
}

// A response a backend answered already carries the backend's CORS headers: the proxy
// adds none of its own to it, or a browser sees two Access-Control-Allow-Origin values
// and fails the CORS check.
func TestUserAPIProxy_ForwardedResponseKeepsOnlyTheBackendsCORSHeaders(t *testing.T) {
	api, err := userapi.New(nil, userapi.ServerOptions{Name: "cors-backend", JWTSecret: corsTestSecret, AllowedOrigins: []string{corsTestOrigin}})
	if err != nil {
		t.Fatalf("userapi.New: %v", err)
	}
	backend := httptest.NewServer(api.SetupRoutes())
	t.Cleanup(backend.Close)
	s, m := newCORSTestProxy(t, strings.TrimPrefix(backend.URL, "http://"), []string{corsTestOrigin})
	m.Set(nil)

	r := httptest.NewRequest(http.MethodOptions, "/user/mailboxes", nil)
	r.Header.Set("Origin", corsTestOrigin)
	r.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	s.setupHandler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("preflight: status %d, want the backend's 200", w.Code)
	}
	if got := w.Header().Values("Access-Control-Allow-Origin"); len(got) != 1 || got[0] != corsTestOrigin {
		t.Errorf("Access-Control-Allow-Origin = %q, want the backend's one [%q]", got, corsTestOrigin)
	}
	if n := varyOrigins(w.Header()); n != 1 {
		t.Errorf("Vary = %q, want Origin in it once", w.Header().Values("Vary"))
	}
}

// allowed_origins is reloaded with the rest of the proxy's settings: a reload that adds an
// origin applies to the next response the proxy writes itself, and one that clears the
// list revokes it, as on the backend.
func TestUserAPIProxy_ReloadAllowedOrigins(t *testing.T) {
	s, m := newCORSTestProxy(t, deadBackend(t), nil)
	m.Set(nil)
	handler := s.setupHandler()
	allowOrigin := func() string {
		r := httptest.NewRequest(http.MethodGet, "/user/mailboxes", nil)
		r.Header.Set("Origin", corsTestOrigin)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", w.Code)
		}
		return w.Header().Get("Access-Control-Allow-Origin")
	}

	if got := allowOrigin(); got != "" {
		t.Fatalf("without allowed_origins: Access-Control-Allow-Origin = %q, want none", got)
	}
	if err := s.ReloadConfig(config.ServerConfig{Name: "cors-proxy", JWTSecret: corsTestSecret, AllowedOrigins: []string{corsTestOrigin}}); err != nil {
		t.Fatal(err)
	}
	if got := allowOrigin(); got != corsTestOrigin {
		t.Errorf("after a reload adding the origin: Access-Control-Allow-Origin = %q, want %q", got, corsTestOrigin)
	}
	if err := s.ReloadConfig(config.ServerConfig{Name: "cors-proxy", JWTSecret: corsTestSecret}); err != nil {
		t.Fatal(err)
	}
	if got := allowOrigin(); got != "" {
		t.Errorf("after a reload clearing allowed_origins: Access-Control-Allow-Origin = %q, want none", got)
	}
}

// syncBuffer is a bytes.Buffer the logger and the test can use at once.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The 502 handler is also called when the client goes away before the backend answers
// (a browser navigating away, an aborted fetch). That is no backend failure: it must not
// be logged as one at WARN, while a backend that cannot be reached still is.
func TestUserAPIProxy_ClientGoneIsNotLoggedAsBackendFailure(t *testing.T) {
	logs := &syncBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { logger.Swap(prev) })
	valid := corsTestToken(t, time.Hour)
	get := func(handler http.Handler, ctx context.Context) {
		r := httptest.NewRequest(http.MethodGet, "/user/mailboxes", nil).WithContext(ctx)
		r.Header.Set("Origin", corsTestOrigin)
		r.Header.Set("Authorization", "Bearer "+valid)
		handler.ServeHTTP(httptest.NewRecorder(), r)
	}
	warned := func(backend string) bool {
		for _, line := range strings.Split(logs.String(), "\n") {
			if strings.Contains(line, "level=WARN") && strings.Contains(line, backend) {
				return true
			}
		}
		return false
	}

	arrived := make(chan struct{}, 1)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-r.Context().Done()
	}))
	t.Cleanup(slow.Close)
	slowAddr := strings.TrimPrefix(slow.URL, "http://")
	s, m := newCORSTestProxy(t, slowAddr, nil)
	m.Set(nil)
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		<-arrived
		cancel()
	}()
	get(s.setupHandler(), ctx)
	if warned(slowAddr) {
		t.Errorf("client gone before the backend answered: logged at WARN:\n%s", logs.String())
	}

	dead := deadBackend(t)
	s, m = newCORSTestProxy(t, dead, nil)
	m.Set(nil)
	get(s.setupHandler(), t.Context())
	if !warned(dead) {
		t.Errorf("unreachable backend: no WARN logged:\n%s", logs.String())
	}
}
