package userapiproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/migadu/sora/server/userapi"
)

// A browser sends a CORS preflight before any authenticated cross-origin call, and never
// with credentials (Fetch Standard, CORS-preflight fetch). The proxy must let it reach a
// backend, whose CORS policy answers it as it does when the backend is reached directly;
// a request that needs a token still needs one.
func TestUserAPIProxy_ForwardsCORSPreflightWithoutToken(t *testing.T) {
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

	s, m := newHTTPTestProxy(t, strings.TrimPrefix(backend.URL, "http://"))
	m.Set(nil)
	handler := s.setupHandler()

	serve := func(method, path string, header map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		for k, v := range header {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}

	for _, path := range []string{"/user/mailboxes", "/user/messages/1", "/user/filters/main"} {
		w := serve(http.MethodOptions, path, map[string]string{
			"Origin":                         origin,
			"Access-Control-Request-Method":  "GET",
			"Access-Control-Request-Headers": "authorization",
		})
		if w.Code != http.StatusOK {
			t.Errorf("preflight %s: status %d, want 200 (body %q)", path, w.Code, w.Body.String())
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Errorf("preflight %s: Access-Control-Allow-Origin = %q, want %q", path, got, origin)
		}
		if got := w.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Authorization") {
			t.Errorf("preflight %s: Access-Control-Allow-Headers = %q, want it to allow Authorization", path, got)
		}
	}

	// Not a preflight: the token is still required.
	if w := serve(http.MethodGet, "/user/mailboxes", map[string]string{"Origin": origin}); w.Code != http.StatusUnauthorized {
		t.Errorf("GET without token: status %d, want 401", w.Code)
	}
	if w := serve(http.MethodOptions, "/user/mailboxes", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("OPTIONS without Access-Control-Request-Method and token: status %d, want 401", w.Code)
	}
}
