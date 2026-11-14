package userapiproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/userapi"
)

// Preflights may use a pool without a default, but the proxy must still leave the
// backend's origin policy intact. Its own policy applies only to its own errors.
func TestUserAPIProxy_PoolPreflightKeepsBackendOriginPolicy(t *testing.T) {
	const backendOrigin = "https://backend-app.example.com"
	const proxyOrigin = "https://proxy-app.example.com"
	api, err := userapi.New(nil, userapi.ServerOptions{
		Name: "pool-backend", JWTSecret: corsTestSecret, AllowedOrigins: []string{backendOrigin},
	})
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(api.SetupRoutes())
	t.Cleanup(backend.Close)
	s, _ := newPoolsProxy(t, []proxy.PoolSpec{
		{Name: "pool", Backends: []string{strings.TrimPrefix(backend.URL, "http://")}},
	}, poolAnswer("pool"))
	if err := s.ReloadConfig(config.ServerConfig{JWTSecret: corsTestSecret, AllowedOrigins: []string{proxyOrigin}}); err != nil {
		t.Fatal(err)
	}
	h := s.setupHandler()
	for _, origin := range []string{backendOrigin, proxyOrigin} {
		w := preflight(h, "/user/mailboxes", origin)
		want := ""
		if origin == backendOrigin {
			want = backendOrigin
		}
		if w.Code != http.StatusOK || w.Header().Get("Access-Control-Allow-Origin") != want {
			t.Errorf("preflight from %s: status %d, headers %v; want backend policy %q", origin, w.Code, w.Header(), want)
		}
		if n := varyOrigins(w.Header()); n != 1 {
			t.Errorf("preflight Vary: Origin appears %d times", n)
		}
		if want != "" && w.Header().Get("Access-Control-Allow-Credentials") != "true" {
			t.Error("listed backend origin lost its credential permission")
		}

		r := httptest.NewRequest(http.MethodGet, "/user/mailboxes", nil)
		r.Header.Set("Origin", origin)
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want = ""
		if origin == proxyOrigin {
			want = proxyOrigin
		}
		if w.Code != http.StatusUnauthorized || w.Header().Get("Access-Control-Allow-Origin") != want {
			t.Errorf("own error from %s: status %d, headers %v; want proxy policy %q", origin, w.Code, w.Header(), want)
		}
	}
}
