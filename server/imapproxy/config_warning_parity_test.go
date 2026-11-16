package imapproxy

import (
	"bytes"
	"context"
	"log"
	"log/slog"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

// New parses the positive revalidation window even when the credential cache is
// disabled. Config warnings must report the fallback the actual constructor logs.
func TestConfigWarningsMatchDisabledCacheRevalidationFallback(t *testing.T) {
	for _, ipRoute := range []bool{false, true} {
		name := "disabled"
		if ipRoute {
			name = "client-ip-route"
		}
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			prev, prevOut, prevFlags := slog.Default(), log.Writer(), log.Flags()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
			t.Cleanup(func() { slog.SetDefault(prev); log.SetOutput(prevOut); log.SetFlags(prevFlags) })
			cache := config.DefaultLookupCacheConfig()
			cache.Enabled = ipRoute
			cache.PositiveRevalidationWindow = "a while"
			var remote *config.RemoteLookupConfig
			if ipRoute {
				remote = &config.RemoteLookupConfig{Enabled: true, URL: "https://lookup.example.com/lookup?email=$email&ip=$ip"}
			}
			srv, err := New(context.Background(), &resilient.ResilientDatabase{}, "localhost", ServerOptions{Name: "warning-parity", Addr: "127.0.0.1:0", RemoteAddrs: []string{"127.0.0.1:143"}, LookupCache: &cache, RemoteLookup: remote})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Stop()
			if !strings.Contains(logs.String(), "Failed to parse lookup_cache.positive_revalidation_window") {
				t.Fatalf("actual constructor did not warn:\n%s", logs.String())
			}
			cfg := config.NewDefaultConfig()
			cfg.DynamicServers = []config.ServerConfig{{Type: "imap_proxy", Name: "warning-parity", Addr: "127.0.0.1:0", RemoteAddrs: []string{"127.0.0.1:143"}, LookupCache: &cache, RemoteLookup: remote}}
			if !strings.Contains(strings.Join(cfg.Warnings(), "\n"), "invalid 'lookup_cache.positive_revalidation_window'") {
				t.Fatalf("Warnings omitted the actual constructor fallback: %q", cfg.Warnings())
			}
		})
	}
}
