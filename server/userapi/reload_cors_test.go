package userapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/config"
)

// A SIGHUP reload receives a complete server config. Both an explicit empty
// list and removing the setting must have the same no-CORS behavior as startup.
func TestReloadConfig_ClearsAllowedOrigins(t *testing.T) {
	for _, origins := range []struct{ name, value string }{{"specific", "https://mail.example.com"}, {"wildcard", "*"}} {
		for _, setting := range []struct{ name, toml string }{{"empty", "allowed_origins = []"}, {"removed", ""}} {
			t.Run(origins.name+"/"+setting.name, func(t *testing.T) {
				s := newReloadTestServer(t, "reload-cors")
				if err := s.ReloadConfig(config.ServerConfig{AllowedOrigins: []string{origins.value}}); err != nil {
					t.Fatal(err)
				}
				h := s.corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
				request := func(method string) *httptest.ResponseRecorder {
					r := httptest.NewRequest(method, "/user/mailboxes", nil)
					r.Header.Set("Origin", "https://mail.example.com")
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					return w
				}
				if got := request(http.MethodGet).Header().Get("Access-Control-Allow-Origin"); got != origins.value {
					t.Fatalf("before reload: allow-origin = %q, want %q", got, origins.value)
				}
				var cfg config.ServerConfig
				if _, err := toml.Decode("name = 'reload-cors'\ntype = 'http_user_api'\n"+setting.toml, &cfg); err != nil {
					t.Fatal(err)
				}
				if err := s.ReloadConfig(cfg); err != nil {
					t.Fatal(err)
				}
				for _, method := range []string{http.MethodGet, http.MethodOptions} {
					w := request(method)
					if w.Code != http.StatusOK {
						t.Errorf("%s status = %d, want 200", method, w.Code)
					}
					for _, header := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Access-Control-Max-Age"} {
						if got := w.Header().Get(header); got != "" {
							t.Errorf("%s after removing allowed_origins: %s = %q, want no CORS authorization", method, header, got)
						}
					}
				}
			})
		}
	}
}

func TestReloadConfig_ClearsAllowedOriginsWhenJWTSecretRefused(t *testing.T) {
	s := newReloadTestServer(t, "reload-cors-secret")
	if err := s.ReloadConfig(config.ServerConfig{JWTSecret: "short", AllowedOrigins: []string{}}); err == nil {
		t.Fatal("expected the short JWT secret to be refused")
	}
	r := httptest.NewRequest(http.MethodGet, "/user/mailboxes", nil)
	r.Header.Set("Origin", "https://mail.example.com")
	w := httptest.NewRecorder()
	s.corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(w, r)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("removed origin still authorized after JWT rotation was refused: %q", got)
	}
}
