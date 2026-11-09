package userapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/config"
)

// A SIGHUP reload receives a complete server config. Both an explicit empty
// list and removing the setting must allow every host, as they do at startup.
func TestReloadConfig_ClearsAllowedHosts(t *testing.T) {
	for _, setting := range []struct{ name, toml string }{{"empty", "allowed_hosts = []"}, {"removed", ""}} {
		t.Run(setting.name, func(t *testing.T) {
			s := newReloadTestServer(t, "reload-hosts")
			h := s.allowedHostsMiddleware(okHandler)
			if got := hostStatus(h, "203.0.113.5:1234"); got != http.StatusForbidden {
				t.Fatalf("before reload: status from outside allowed_hosts = %d, want 403", got)
			}
			var cfg config.ServerConfig
			if _, err := toml.Decode("name = 'reload-hosts'\ntype = 'http_user_api'\n"+setting.toml, &cfg); err != nil {
				t.Fatal(err)
			}
			if err := s.ReloadConfig(cfg); err != nil {
				t.Fatal(err)
			}
			if got := hostStatus(h, "203.0.113.5:1234"); got != http.StatusOK {
				t.Errorf("after reload with allowed_hosts %s: status = %d, want 200 (every host allowed, as at startup)", setting.name, got)
			}
		})
	}
}

// A reload to a different non-empty list replaces the running one.
func TestReloadConfig_ReplacesAllowedHosts(t *testing.T) {
	s := newReloadTestServer(t, "reload-hosts-replace")
	h := s.allowedHostsMiddleware(okHandler)
	if err := s.ReloadConfig(config.ServerConfig{Name: "reload-hosts-replace", AllowedHosts: []string{"198.51.100.0/24"}}); err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]int{"198.51.100.7:1234": http.StatusOK, "192.0.2.10:1234": http.StatusForbidden, "203.0.113.5:1234": http.StatusForbidden} {
		if got := hostStatus(h, addr); got != want {
			t.Errorf("after reload to 198.51.100.0/24: %s status = %d, want %d", addr, got, want)
		}
	}
}

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

func hostStatus(h http.Handler, remoteAddr string) int {
	r := httptest.NewRequest(http.MethodGet, "/user/mailboxes", nil)
	r.RemoteAddr = remoteAddr
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}
