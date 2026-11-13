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
}

// Every SIGHUP retries the complete config, including one a previous reload
// refused. A refusal must leave both keys in place so retries cannot bypass it.
func TestReloadConfig_RepeatedSIGHUPRejectsAPIKeyReuse(t *testing.T) {
	const nextRW = "full-access-api-key-dddddddddddddddd"
	cases := []struct {
		name, apiKey, readOnlyAPIKey, wantErr string
	}{
		{"read-only unchanged", roKey, roKey, "api_key refused"},
		{"read-only replaced", roKey, roKey2, "api_key refused"},
		{"read-only revoked", roKey, "", "api_key refused"},
		{"full-access moved to read-only", nextRW, rwKey, "read_only_api_key refused"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := New(&resilient.ResilientDatabase{}, ServerOptions{
				Name: "ro", APIKey: rwKey, ReadOnlyAPIKey: roKey,
				AllowedHosts: []string{"192.0.2.0/24"},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			cfg := config.ServerConfig{
				Name: "ro", APIKey: c.apiKey, ReadOnlyAPIKey: c.readOnlyAPIKey,
				AllowedHosts: []string{"198.51.100.0/24"},
			}
			for attempt := 1; attempt <= 3; attempt++ {
				if err := s.ReloadConfig(cfg); err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Errorf("reload %d: error %v, want %q", attempt, err, c.wantErr)
				}
				for _, check := range []struct {
					method, key string
					want        int
				}{
					{http.MethodGet, rwKey, http.StatusOK},
					{http.MethodPost, rwKey, http.StatusOK},
					{http.MethodGet, roKey, http.StatusOK},
					{http.MethodPost, roKey, http.StatusForbidden},
					{http.MethodGet, nextRW, http.StatusForbidden},
					{http.MethodPost, nextRW, http.StatusForbidden},
					{http.MethodGet, roKey2, http.StatusForbidden},
				} {
					if got := authStatus(s, check.method, check.key); got != check.want {
						t.Errorf("reload %d: %s with %q: status %d, want %d", attempt, check.method, check.key, got, check.want)
					}
				}
				// Unrelated host restrictions still reload when credentials are refused.
				h := s.allowedHostsMiddleware(okHandler)
				if got := hostStatus(h, "198.51.100.5:1234"); got != http.StatusOK {
					t.Errorf("reload %d: new allowed host status %d, want 200", attempt, got)
				}
				if got := hostStatus(h, "192.0.2.5:1234"); got != http.StatusForbidden {
					t.Errorf("reload %d: old allowed host status %d, want 403", attempt, got)
				}
			}
		})
	}
}

func TestReloadConfig_RotatesAPIKeysTogether(t *testing.T) {
	const nextRW = "full-access-api-key-dddddddddddddddd"
	s, err := New(&resilient.ResilientDatabase{}, ServerOptions{Name: "ro", APIKey: rwKey, ReadOnlyAPIKey: roKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cfg := config.ServerConfig{Name: "ro", APIKey: nextRW, ReadOnlyAPIKey: roKey2}
	if err := s.ReloadConfig(cfg); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		method, key string
		want        int
	}{
		{http.MethodGet, rwKey, http.StatusForbidden},
		{http.MethodGet, roKey, http.StatusForbidden},
		{http.MethodGet, nextRW, http.StatusOK},
		{http.MethodPost, nextRW, http.StatusOK},
		{http.MethodGet, roKey2, http.StatusOK},
		{http.MethodPost, roKey2, http.StatusForbidden},
	} {
		if got := authStatus(s, check.method, check.key); got != check.want {
			t.Errorf("%s with %q: status %d, want %d", check.method, check.key, got, check.want)
		}
	}
	cfg.ReadOnlyAPIKey = ""
	if err := s.ReloadConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if got := authStatus(s, http.MethodGet, roKey2); got != http.StatusForbidden {
		t.Errorf("revoked read-only key: status %d, want 403", got)
	}
	if got := authStatus(s, http.MethodPost, nextRW); got != http.StatusOK {
		t.Errorf("full-access key after revocation: status %d, want 200", got)
	}
}
