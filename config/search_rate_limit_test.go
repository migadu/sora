package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// search_rate_limit_per_min = 0 switches the limit off, as documented; only a
// server that leaves the key out gets the default.
func TestGetSearchRateLimitPerMin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	content := `
[[server]]
type = "imap"
name = "unset"
addr = ":1143"

[[server]]
type = "imap"
name = "disabled"
addr = ":2143"
limits.search_rate_limit_per_min = 0

[[server]]
type = "imap"
name = "custom"
addr = ":3143"
limits.search_rate_limit_per_min = 25
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var cfg Config
	if err := LoadConfigFromFile(path, &cfg); err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	want := map[string]int{"unset": 60, "disabled": 0, "custom": 25}
	if len(cfg.DynamicServers) != len(want) {
		t.Fatalf("loaded %d servers, want %d", len(cfg.DynamicServers), len(want))
	}
	for _, server := range cfg.DynamicServers {
		if got := server.GetSearchRateLimitPerMin(); got != want[server.Name] {
			t.Errorf("server %q: GetSearchRateLimitPerMin() = %d, want %d", server.Name, got, want[server.Name])
		}
	}
}

// search_rate_limit_burst defaults to one window's worth, the per-window rate,
// so a server that leaves it out allows the bursts the sliding window allowed.
func TestGetSearchRateLimitBurst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	content := `
[[server]]
type = "imap"
name = "unset"
addr = ":1143"

[[server]]
type = "imap"
name = "rate-only"
addr = ":2143"
limits.search_rate_limit_per_min = 10

[[server]]
type = "imap"
name = "zero"
addr = ":3143"
limits.search_rate_limit_per_min = 10
limits.search_rate_limit_burst = 0

[[server]]
type = "imap"
name = "custom"
addr = ":4143"
limits.search_rate_limit_per_min = 10
limits.search_rate_limit_burst = 30
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var cfg Config
	if err := LoadConfigFromFile(path, &cfg); err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	want := map[string]int{"unset": 60, "rate-only": 10, "zero": 10, "custom": 30}
	if len(cfg.DynamicServers) != len(want) {
		t.Fatalf("loaded %d servers, want %d", len(cfg.DynamicServers), len(want))
	}
	for _, server := range cfg.DynamicServers {
		if got := server.GetSearchRateLimitBurst(); got != want[server.Name] {
			t.Errorf("server %q: GetSearchRateLimitBurst() = %d, want %d", server.Name, got, want[server.Name])
		}
	}
}

// search_rate_limit_window must be a positive duration. The rate limiter replaces a
// zero or negative window with 1m, so the getter reports one as invalid and the
// server logs the fallback, as for a window that does not parse (#648).
func TestGetSearchRateLimitWindow(t *testing.T) {
	tests := []struct {
		window  string
		want    time.Duration
		wantErr bool
	}{
		{window: "", want: time.Minute},
		{window: "2m", want: 2 * time.Minute},
		{window: "1d", want: 24 * time.Hour},
		{window: "1 min", wantErr: true},
		{window: "0", wantErr: true},
		{window: "0s", wantErr: true},
		{window: "-1m", wantErr: true},
	}
	for _, tt := range tests {
		server := ServerConfig{Name: "imap", Type: "imap", Limits: &ServerLimitsConfig{SearchRateLimitWindow: tt.window}}
		got, err := server.GetSearchRateLimitWindow()
		if tt.wantErr {
			if err == nil {
				t.Errorf("search_rate_limit_window = %q: got %v, want an error", tt.window, got)
			} else if !strings.Contains(err.Error(), strconv.Quote(tt.window)) {
				t.Errorf("search_rate_limit_window = %q: error %q does not quote the value", tt.window, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("search_rate_limit_window = %q: got %v, %v, want %v", tt.window, got, err, tt.want)
		}
	}
}
