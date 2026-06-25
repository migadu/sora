package userapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCORSMiddleware verifies the wildcard-vs-credentials hardening: a "*" allowlist
// must emit literal "*" WITHOUT Access-Control-Allow-Credentials (so an arbitrary site
// cannot make credentialed cross-origin reads), while a specific configured origin is
// reflected with credentials. Disallowed origins get no CORS headers.
func TestCORSMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	t.Run("wildcard emits * without credentials", func(t *testing.T) {
		s := &Server{allowedOrigins: []string{"*"}}
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
		s := &Server{allowedOrigins: []string{"https://app.example.com"}}
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
		s := &Server{allowedOrigins: []string{"https://app.example.com"}}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/user/mailboxes", nil)
		req.Header.Set("Origin", "https://evil.example")
		s.corsMiddleware(next).ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("Access-Control-Allow-Origin = %q, want empty for a disallowed origin", got)
		}
	})
}
