package config

import (
	"os"
	"path/filepath"
	"testing"
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
