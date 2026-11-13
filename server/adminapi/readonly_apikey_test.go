package adminapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

const (
	rwKey  = "full-access-api-key-aaaaaaaaaaaaaaaa"
	roKey  = "read-only-api-key-bbbbbbbbbbbbbbbbbb"
	roKey2 = "read-only-api-key-cccccccccccccccccc"
)

func authStatus(s *Server, method, key string) int {
	h := s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(method, "/admin/accounts/user@example.com", nil)
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

// The read-only key may read but not write; the full key may do both.
func TestAuthMiddleware_ReadOnlyAPIKey(t *testing.T) {
	s, err := New(&resilient.ResilientDatabase{}, ServerOptions{Name: "ro", APIKey: rwKey, ReadOnlyAPIKey: roKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := []struct {
		method, key string
		want        int
	}{
		{http.MethodGet, rwKey, http.StatusOK},
		{http.MethodPost, rwKey, http.StatusOK},
		{http.MethodDelete, rwKey, http.StatusOK},
		{http.MethodGet, roKey, http.StatusOK},
		{http.MethodHead, roKey, http.StatusForbidden},
		{http.MethodOptions, roKey, http.StatusForbidden},
		{http.MethodPost, roKey, http.StatusForbidden},
		{http.MethodPut, roKey, http.StatusForbidden},
		{http.MethodDelete, roKey, http.StatusForbidden},
		{http.MethodPatch, roKey, http.StatusForbidden},
		{http.MethodGet, "wrong-key", http.StatusForbidden},
	}
	for _, c := range cases {
		if got := authStatus(s, c.method, c.key); got != c.want {
			t.Errorf("%s with %q: status %d, want %d", c.method, c.key, got, c.want)
		}
	}
}

// Without a read-only key configured, an empty bearer token must not match it.
func TestAuthMiddleware_NoReadOnlyAPIKey(t *testing.T) {
	s, err := New(&resilient.ResilientDatabase{}, ServerOptions{Name: "ro", APIKey: rwKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := authStatus(s, http.MethodGet, ""); got == http.StatusOK {
		t.Errorf("empty token accepted with no read-only key configured")
	}
}

func TestNew_RejectsBadReadOnlyAPIKey(t *testing.T) {
	cases := []struct{ name, key, wantErr string }{
		{"too short", "short-key", "at least"},
		{"placeholder", "your-api-key-here", "placeholder"},
		{"same as api_key", rwKey, "differ"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(nil, ServerOptions{APIKey: rwKey, ReadOnlyAPIKey: c.key})
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("ReadOnlyAPIKey=%q: got err=%v, want substring %q", c.key, err, c.wantErr)
			}
		})
	}
}

// A reload can add, replace and revoke the read-only key, and refuses a weak one.
func TestReloadConfig_ReadOnlyAPIKey(t *testing.T) {
	s, err := New(&resilient.ResilientDatabase{}, ServerOptions{Name: "ro", APIKey: rwKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := s.ReloadConfig(config.ServerConfig{Name: "ro", APIKey: rwKey, ReadOnlyAPIKey: roKey}); err != nil {
		t.Fatal(err)
	}
	if got := authStatus(s, http.MethodGet, roKey); got != http.StatusOK {
		t.Errorf("added read_only_api_key: status %d, want 200", got)
	}

	if err := s.ReloadConfig(config.ServerConfig{Name: "ro", APIKey: rwKey, ReadOnlyAPIKey: roKey2}); err != nil {
		t.Fatal(err)
	}
	if got := authStatus(s, http.MethodGet, roKey); got != http.StatusForbidden {
		t.Errorf("replaced read_only_api_key: status %d, want 403", got)
	}

	const weak = "weak-ro-key"
	err = s.ReloadConfig(config.ServerConfig{Name: "ro", APIKey: rwKey, ReadOnlyAPIKey: weak})
	if err == nil || !strings.Contains(err.Error(), "read_only_api_key") || strings.Contains(err.Error(), weak) {
		t.Errorf("weak read_only_api_key: error %v, want one naming read_only_api_key without its value", err)
	}
	if got := authStatus(s, http.MethodGet, roKey2); got != http.StatusOK {
		t.Errorf("after refusing a weak key, the previous one gets %d, want 200", got)
	}

	if err := s.ReloadConfig(config.ServerConfig{Name: "ro", APIKey: rwKey}); err != nil {
		t.Fatal(err)
	}
	if got := authStatus(s, http.MethodGet, roKey2); got != http.StatusForbidden {
		t.Errorf("revoked read_only_api_key: status %d, want 403", got)
	}

	// Rotating api_key onto the value read-only clients hold is refused, whether or
	// not read_only_api_key changes in the same reload: it would grant them full access.
	for _, nextRO := range []string{roKey, roKey2, ""} {
		if err := s.ReloadConfig(config.ServerConfig{Name: "ro", APIKey: rwKey, ReadOnlyAPIKey: roKey}); err != nil {
			t.Fatal(err)
		}
		err := s.ReloadConfig(config.ServerConfig{Name: "ro", APIKey: roKey, ReadOnlyAPIKey: nextRO})
		if err == nil || !strings.Contains(err.Error(), "api_key refused") {
			t.Errorf("api_key rotated onto read_only_api_key (next read-only %q): error %v, want api_key refused", nextRO, err)
		}
		if got := authStatus(s, http.MethodPost, roKey); got != http.StatusForbidden {
			t.Errorf("former read-only key (next read-only %q): POST status %d, want 403", nextRO, got)
		}
		if got := authStatus(s, http.MethodPost, rwKey); got != http.StatusOK {
			t.Errorf("previous api_key (next read-only %q): POST status %d, want 200", nextRO, got)
		}
	}

	// Rotating api_key while moving the old one into the read-only slot keeps the
	// rotated-out (possibly leaked) key from living on as a read key.
	const rwKey2 = "full-access-api-key-dddddddddddddddd"
	err = s.ReloadConfig(config.ServerConfig{Name: "ro", APIKey: rwKey2, ReadOnlyAPIKey: rwKey})
	if err == nil || !strings.Contains(err.Error(), "read_only_api_key refused") {
		t.Errorf("old api_key moved to read_only_api_key: error %v, want read_only_api_key refused", err)
	}
	if got := authStatus(s, http.MethodGet, rwKey); got != http.StatusForbidden {
		t.Errorf("rotated-out api_key: GET status %d, want 403", got)
	}
	if got := authStatus(s, http.MethodPost, rwKey2); got != http.StatusOK {
		t.Errorf("new api_key: POST status %d, want 200", got)
	}
}
