package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetThreadMaxMessages(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	content := `
[[server]]
type = "imap"
name = "unset"
addr = ":1143"

[[server]]
type = "imap"
name = "empty-limits"
addr = ":2143"
limits = {}

[[server]]
type = "imap"
name = "zero"
addr = ":3143"
limits.thread_max_messages = 0

[[server]]
type = "imap"
name = "negative"
addr = ":4143"
limits.thread_max_messages = -1

[[server]]
type = "imap"
name = "lower"
addr = ":5143"
limits.thread_max_messages = 3

[[server]]
type = "imap"
name = "higher"
addr = ":6143"
limits.thread_max_messages = 100000
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := LoadConfigFromFile(path, &cfg); err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	want := map[string]int{
		"unset":        50000,
		"empty-limits": 50000,
		"zero":         50000,
		"negative":     50000,
		"lower":        3,
		"higher":       100000,
	}
	if len(cfg.DynamicServers) != len(want) {
		t.Fatalf("loaded %d servers, want %d", len(cfg.DynamicServers), len(want))
	}
	for _, server := range cfg.DynamicServers {
		if got := server.GetThreadMaxMessages(); got != want[server.Name] {
			t.Errorf("server %q: GetThreadMaxMessages() = %d, want %d", server.Name, got, want[server.Name])
		}
	}
}
