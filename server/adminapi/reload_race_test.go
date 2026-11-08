package adminapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

// SIGHUP runs ReloadConfig on its own goroutine while requests are served: the host
// and API-key middleware read what it replaces, on every request.
func TestReloadConfig_DuringRequests(t *testing.T) {
	const keyA = "reload-test-api-key-aaaaaaaaaaaaaaaaaaaaa"
	const keyB = "reload-test-api-key-bbbbbbbbbbbbbbbbbbbbb"
	s, err := New(&resilient.ResilientDatabase{}, ServerOptions{
		Name:         "reload",
		APIKey:       keyA,
		AllowedHosts: []string{"192.0.2.0/24"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := s.allowedHostsMiddleware(s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	cfgs := []config.ServerConfig{
		{Name: "reload", APIKey: keyB, AllowedHosts: []string{"192.0.2.0/24", "198.51.100.0/24"}},
		{Name: "reload", APIKey: keyA, AllowedHosts: []string{"192.0.2.0/24"}},
	}
	reloadWhile(t, s.ReloadConfig, cfgs, func() {
		for i := 0; i < 200; i++ {
			r := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
			r.RemoteAddr = "192.0.2.10:40000"
			r.Header.Set("Authorization", "Bearer wrong-key")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("wrong API key: status %d, want 403", w.Code)
			}
		}
	})
}

// A reloaded api_key replaces the old one, unless New would refuse it.
func TestReloadConfig_APIKey(t *testing.T) {
	const keyA = "reload-test-api-key-aaaaaaaaaaaaaaaaaaaaa"
	const keyB = "reload-test-api-key-bbbbbbbbbbbbbbbbbbbbb"
	s, err := New(&resilient.ResilientDatabase{}, ServerOptions{Name: "reload", APIKey: keyA})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	status := func(key string) int {
		r := httptest.NewRequest(http.MethodGet, "/admin/health", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	if err := s.ReloadConfig(config.ServerConfig{Name: "reload", APIKey: keyB}); err != nil {
		t.Fatal(err)
	}
	if got := status(keyB); got != http.StatusOK {
		t.Errorf("reloaded api_key: status %d, want 200", got)
	}
	if got := status(keyA); got != http.StatusForbidden {
		t.Errorf("replaced api_key: status %d, want 403", got)
	}

	for _, weak := range []string{"short", "your-api-key-here"} {
		// Refused loudly: the caller logs a failed reload naming the key, never its value.
		err := s.ReloadConfig(config.ServerConfig{Name: "reload", APIKey: weak})
		if err == nil || !strings.Contains(err.Error(), "api_key") || strings.Contains(err.Error(), weak) {
			t.Errorf("reloading api_key %q, which New refuses: error %v, want one naming api_key without its value", weak, err)
		}
		if got := status(weak); got != http.StatusForbidden {
			t.Errorf("api_key %q, which New refuses, was taken on reload: status %d", weak, got)
		}
		if got := status(keyB); got != http.StatusOK {
			t.Errorf("after refusing api_key %q: the previous key gets %d, want 200", weak, got)
		}
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
