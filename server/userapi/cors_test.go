package userapi

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// TestCORSMiddleware verifies the wildcard-vs-credentials hardening: a "*" allowlist
// must emit literal "*" WITHOUT Access-Control-Allow-Credentials (so an arbitrary site
// cannot make credentialed cross-origin reads), while a specific configured origin is
// reflected with credentials. Disallowed origins get no CORS headers.
func TestCORSMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	t.Run("wildcard emits * without credentials", func(t *testing.T) {
		s := &Server{}
		s.settings.Store(&reloadableSettings{allowedOrigins: []string{"*"}})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/user/mailboxes", nil)
		req.Header.Set("Origin", "https://evil.example")
		s.corsMiddleware(next).ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("Access-Control-Allow-Origin = %q, want \"*\"", got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
			t.Errorf("Access-Control-Allow-Credentials = %q, want empty (wildcard must not allow credentials)", got)
		}
	})

	t.Run("specific origin reflects with credentials", func(t *testing.T) {
		s := &Server{}
		s.settings.Store(&reloadableSettings{allowedOrigins: []string{"https://app.example.com"}})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/user/mailboxes", nil)
		req.Header.Set("Origin", "https://app.example.com")
		s.corsMiddleware(next).ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
			t.Errorf("Access-Control-Allow-Origin = %q, want the reflected origin", got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
			t.Errorf("Access-Control-Allow-Credentials = %q, want \"true\"", got)
		}
	})

	t.Run("disallowed origin gets no CORS headers", func(t *testing.T) {
		s := &Server{}
		s.settings.Store(&reloadableSettings{allowedOrigins: []string{"https://app.example.com"}})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/user/mailboxes", nil)
		req.Header.Set("Origin", "https://evil.example")
		s.corsMiddleware(next).ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("Access-Control-Allow-Origin = %q, want empty for a disallowed origin", got)
		}
	})
}

// TestCORSMiddlewareVaryOrigin covers the HTTP-cache side of CORS (Fetch Standard,
// "CORS protocol and HTTP caches"): when the answer depends on the request's Origin
// (a specific allowed_origins list), every response, including the ones that do not
// reflect an origin and preflights, must say Vary: Origin; with "*" the header is
// static and sent on every response, so no Vary is needed.
func TestCORSMiddlewareVaryOrigin(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	serve := func(origins []string, method, origin string) *httptest.ResponseRecorder {
		s := &Server{}
		s.settings.Store(&reloadableSettings{allowedOrigins: origins})
		rec := httptest.NewRecorder()
		rec.Header().Set("Vary", "Accept-Encoding") // set earlier in the chain; must be kept
		req := httptest.NewRequest(method, "/user/mailboxes", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		s.corsMiddleware(next).ServeHTTP(rec, req)
		return rec
	}
	hasVaryOrigin := func(h http.Header) bool {
		for _, v := range h.Values("Vary") {
			for _, f := range strings.Split(v, ",") {
				if strings.EqualFold(strings.TrimSpace(f), "Origin") {
					return true
				}
			}
		}
		return false
	}

	specific := []string{"https://app.example.com"}
	for _, tc := range []struct{ name, method, origin string }{
		{"allowed origin", http.MethodGet, "https://app.example.com"},
		{"disallowed origin", http.MethodGet, "https://evil.example"},
		{"no origin", http.MethodGet, ""},
		{"allowed preflight", http.MethodOptions, "https://app.example.com"},
		{"disallowed preflight", http.MethodOptions, "https://evil.example"},
	} {
		t.Run("specific/"+tc.name, func(t *testing.T) {
			rec := serve(specific, tc.method, tc.origin)
			if !hasVaryOrigin(rec.Header()) {
				t.Errorf("Vary = %q, want it to include Origin", rec.Header().Values("Vary"))
			}
			if !slices.Contains(rec.Header().Values("Vary"), "Accept-Encoding") {
				t.Errorf("Vary = %q, an existing Vary value was dropped", rec.Header().Values("Vary"))
			}
		})
	}

	t.Run("wildcard without origin still sends *", func(t *testing.T) {
		rec := serve([]string{"*"}, http.MethodGet, "")
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("Access-Control-Allow-Origin = %q, want \"*\" on every response", got)
		}
		if hasVaryOrigin(rec.Header()) {
			t.Errorf("Vary = %q, a static \"*\" needs no Vary: Origin", rec.Header().Values("Vary"))
		}
	})

	t.Run("no allowed origins", func(t *testing.T) {
		rec := serve(nil, http.MethodGet, "https://app.example.com")
		if hasVaryOrigin(rec.Header()) {
			t.Errorf("Vary = %q, want no Vary: Origin without CORS", rec.Header().Values("Vary"))
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("Access-Control-Allow-Origin = %q, want empty", got)
		}
	})
}
