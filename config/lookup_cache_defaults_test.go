package config

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func decodeLookupCacheTable(t *testing.T, table string) *LookupCacheConfig {
	t.Helper()
	var cfg Config
	if _, err := toml.Decode(`
[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = ":143"
remote_addrs = ["192.0.2.20:143"]

[server.lookup_cache]
`+table, &cfg); err != nil {
		t.Fatal(err)
	}
	lc := cfg.DynamicServers[0].LookupCache
	if lc == nil {
		t.Fatal("lookup_cache table was not decoded")
	}
	return lc
}

// A [server.lookup_cache] table that only tunes one key keeps the defaults for
// the others: the cache stays enabled and max_size stays 50000 (#334).
func TestLookupCacheTableKeepsDefaultsForAbsentKeys(t *testing.T) {
	lc := decodeLookupCacheTable(t, `positive_ttl = "10m"`)
	def := DefaultLookupCacheConfig()

	if !lc.Enabled {
		t.Error("a lookup_cache table without enabled turned the cache off")
	}
	if lc.MaxSize != def.MaxSize {
		t.Errorf("max_size = %d, want the default %d", lc.MaxSize, def.MaxSize)
	}
	if lc.PositiveTTL != "10m" {
		t.Errorf("positive_ttl = %q, want %q", lc.PositiveTTL, "10m")
	}
	if lc.NegativeTTL != def.NegativeTTL || lc.CleanupInterval != def.CleanupInterval ||
		lc.PositiveRevalidationWindow != def.PositiveRevalidationWindow {
		t.Errorf("absent durations not defaulted: %+v", *lc)
	}
}

func TestLookupCacheTableExplicitValuesWin(t *testing.T) {
	lc := decodeLookupCacheTable(t, "enabled = false\nmax_size = 200\nnegative_ttl = \"30s\"")
	if lc.Enabled {
		t.Error("enabled = false was not honoured")
	}
	if lc.MaxSize != 200 {
		t.Errorf("max_size = %d, want 200", lc.MaxSize)
	}
	if lc.NegativeTTL != "30s" {
		t.Errorf("negative_ttl = %q, want 30s", lc.NegativeTTL)
	}
}

func TestLookupCacheTableRejectsWrongType(t *testing.T) {
	var cfg Config
	_, err := toml.Decode("[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \":143\"\n[server.lookup_cache]\nenabled = \"yes\"\n", &cfg)
	if err == nil {
		t.Fatal("enabled = \"yes\" decoded without error")
	}
}

// A typo inside the table is still reported as an unknown key.
func TestLookupCacheTableUnknownKeyIsReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	content := "[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \":143\"\n[server.lookup_cache]\npositve_ttl = \"10m\"\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

	var cfg Config
	if err := LoadConfigFromFile(path, &cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "positve_ttl") {
		t.Errorf("unknown lookup_cache key not reported; log:\n%s", buf.String())
	}
}

// One default max_size for every server type; zero or negative means the default.
func TestLookupCacheGetMaxSize(t *testing.T) {
	def := DefaultLookupCacheConfig().MaxSize
	for _, tt := range []struct{ in, want int }{{0, def}, {-1, def}, {200, 200}} {
		c := LookupCacheConfig{MaxSize: tt.in}
		if got := c.GetMaxSize(); got != tt.want {
			t.Errorf("GetMaxSize() with max_size %d = %d, want %d", tt.in, got, tt.want)
		}
	}
}
