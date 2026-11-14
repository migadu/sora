package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
)

// The cleaner keeps redirect_log rows for the longest redirect_rate_window of the
// servers that apply the Sieve redirect limit (LMTP and the Admin API, which both
// deliver), so no row the limit still counts is deleted (#430).
func TestLongestRedirectRateWindow(t *testing.T) {
	tests := []struct {
		name    string
		servers string
		want    time.Duration
	}{
		{
			name: "no delivering server uses the default",
			servers: `
[[server]]
type = "imap"
name = "imap"
addr = ":1143"
limits.redirect_rate_window = "720h"
`,
			want: time.Hour,
		},
		{
			name: "the longest window of LMTP and the Admin API",
			servers: `
[[server]]
type = "lmtp"
name = "lmtp-default"
addr = ":2424"

[[server]]
type = "lmtp"
name = "lmtp-day"
addr = ":2425"
limits.redirect_rate_window = "24h"

[[server]]
type = "http_admin_api"
name = "admin"
addr = ":8080"
limits.redirect_rate_window = "6h"

[[server]]
type = "imap"
name = "imap"
addr = ":1143"
limits.redirect_rate_window = "720h"
`,
			want: 24 * time.Hour,
		},
		{
			name: "the Admin API alone",
			servers: `
[[server]]
type = "http_admin_api"
name = "admin"
addr = ":8080"
limits.redirect_rate_window = "2d"
`,
			want: 48 * time.Hour,
		},
		{
			name: "shorter and unparsable windows keep the default",
			servers: `
[[server]]
type = "lmtp"
name = "lmtp-short"
addr = ":2424"
limits.redirect_rate_window = "10m"

[[server]]
type = "lmtp"
name = "lmtp-bad"
addr = ":2425"
limits.redirect_rate_window = "soon"
`,
			want: time.Hour,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tt.servers), 0o600); err != nil {
				t.Fatal(err)
			}
			var cfg Config
			if err := LoadConfigFromFile(path, &cfg); err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}
			if got := cfg.LongestRedirectRateWindow(); got != tt.want {
				t.Errorf("LongestRedirectRateWindow() = %v, want %v", got, tt.want)
			}
		})
	}
}

func decodeRedirectWindowServer(t *testing.T, serverType, window string) ServerConfig {
	t.Helper()
	var cfg Config
	if _, err := toml.Decode(`
[[server]]
type = "`+serverType+`"
name = "s"
addr = ":2424"
limits.redirect_rate_window = "`+window+`"
`, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.DynamicServers[0]
}

// The redirect rate limit counts redirects newer than now - redirect_rate_window, so
// a zero or negative window counts none and every redirect is allowed. The limit is
// switched off with redirect_rate_limit = 0; a non-positive window on a server that
// applies the limit is refused at startup, SIGHUP reload and sora-admin config
// validate (#495).
func TestRedirectRateWindowNonPositiveRejected(t *testing.T) {
	for _, serverType := range []string{"lmtp", "http_admin_api"} {
		for _, window := range []string{"0", "0s", "0d", "-1h", "-2d"} {
			s := decodeRedirectWindowServer(t, serverType, window)
			err := s.Validate()
			if err == nil {
				t.Errorf("%s: redirect_rate_window = %q accepted", serverType, window)
				continue
			}
			if !strings.Contains(err.Error(), "redirect_rate_window") {
				t.Errorf("%s: redirect_rate_window = %q: error %q does not name the key", serverType, window, err)
			}
		}
	}
}

// Positive windows stay valid. An unparsable window keeps falling back to the 1h
// default at startup, and server types that never apply the limit do not read it.
func TestRedirectRateWindowAccepted(t *testing.T) {
	for _, tt := range []struct{ serverType, window string }{
		{"lmtp", "1h"},
		{"lmtp", "30m"},
		{"http_admin_api", "2d"},
		{"lmtp", "soon"},
		{"imap", "0"},
		{"pop3", "-1h"},
	} {
		s := decodeRedirectWindowServer(t, tt.serverType, tt.window)
		if err := s.Validate(); err != nil {
			t.Errorf("%s: redirect_rate_window = %q rejected: %v", tt.serverType, tt.window, err)
		}
	}
}
