package userapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

var (
	reloadSecretA = strings.Repeat("a", 32)
	reloadSecretB = strings.Repeat("b", 32)
)

func newReloadTestServer(t *testing.T, name string) *Server {
	t.Helper()
	s, err := New(&resilient.ResilientDatabase{}, ServerOptions{
		Name:           name,
		JWTSecret:      reloadSecretA,
		AllowedOrigins: []string{"https://mail.example.com"},
		AllowedHosts:   []string{"192.0.2.0/24"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// SIGHUP runs ReloadConfig on its own goroutine while requests are served: the CORS and
// host middleware and the JWT signing and validation read what it replaces.
func TestReloadConfig_DuringRequests(t *testing.T) {
	s := newReloadTestServer(t, "reload-requests")
	h := s.allowedHostsMiddleware(s.corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	cfgs := []config.ServerConfig{
		{Name: "reload-requests", JWTSecret: reloadSecretB, AllowedOrigins: []string{"https://mail.example.com", "https://app.example.com"}, AllowedHosts: []string{"192.0.2.0/24", "198.51.100.0/24"}},
		{Name: "reload-requests", JWTSecret: reloadSecretA, AllowedOrigins: []string{"https://mail.example.com"}, AllowedHosts: []string{"192.0.2.0/24"}},
	}
	reloadWhile(t, s.ReloadConfig, cfgs, func() {
		for i := 0; i < 200; i++ {
			r := httptest.NewRequest(http.MethodGet, "/user/mailboxes", nil)
			r.RemoteAddr = "192.0.2.10:40000"
			r.Header.Set("Origin", "https://mail.example.com")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusOK || w.Header().Get("Access-Control-Allow-Origin") != "https://mail.example.com" {
				t.Fatalf("allowed origin from an allowed host: status %d, allow-origin %q", w.Code, w.Header().Get("Access-Control-Allow-Origin"))
			}
			// Signed and checked under different reloads, so only that it runs matters.
			if tok, _, err := s.generateToken("user@example.com", 1, 1); err == nil {
				_, _ = s.validateToken(tok)
			}
		}
	})
}

// A reloaded jwt_secret signs the tokens issued after the reload and is the only key
// they validate with; the User API proxy, which reloads it too, checks them with it.
func TestReloadConfig_JWTSecret(t *testing.T) {
	s := newReloadTestServer(t, "reload-jwt")
	before, _, err := s.generateToken("user@example.com", 1, 1)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.ReloadConfig(config.ServerConfig{Name: "reload-jwt", JWTSecret: reloadSecretB}); err != nil {
		t.Fatal(err)
	}

	after, _, err := s.generateToken("user@example.com", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jwt.Parse(after, func(*jwt.Token) (any, error) { return []byte(reloadSecretB), nil }); err != nil {
		t.Errorf("token issued after the reload is not signed with the new secret: %v", err)
	}
	if _, err := s.validateToken(after); err != nil {
		t.Errorf("token issued after the reload rejected: %v", err)
	}
	if _, err := s.validateToken(before); err == nil {
		t.Error("token signed with the replaced secret still validates")
	}

	// A secret New would refuse is not taken on reload either.
	// Refused loudly: the caller logs a failed reload naming the secret, never its value.
	if err := s.ReloadConfig(config.ServerConfig{Name: "reload-jwt", JWTSecret: "short"}); err == nil || !strings.Contains(err.Error(), "jwt_secret") || strings.Contains(err.Error(), "short") {
		t.Errorf("reloading a too-short jwt_secret: error %v, want one naming jwt_secret without its value", err)
	}
	if _, err := s.validateToken(after); err != nil {
		t.Errorf("a too-short jwt_secret replaced the secret: %v", err)
	}
}

// reloadWhile runs ReloadConfig every millisecond, alternating cfgs, until work returns.
func reloadWhile(t *testing.T, reload func(config.ServerConfig) error, cfgs []config.ServerConfig, work func()) {
	t.Helper()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := reload(cfgs[i%len(cfgs)]); err != nil {
				t.Errorf("ReloadConfig: %v", err)
				return
			}
			time.Sleep(time.Millisecond) // still overlapping every reader, without flooding the log
		}
	}()
	work()
	close(stop)
	wg.Wait()
}
