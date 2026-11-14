package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
