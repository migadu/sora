package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/errors"
)

// [cluster.affinity] enabled is the switch for the cluster affinity manager, which every
// proxy consults for enable_affinity and which gossips affinities to the other nodes
// (#431). A cluster config without the key keeps affinity on, as before the key was
// read; only an explicit false turns it off, and a proxy that sets enable_affinity is
// then named in a warning instead of losing its affinity silently.
func TestInitializeServices_ClusterAffinityEnabled(t *testing.T) {
	const clusterSection = `
[cluster]
enabled = true
addr = "127.0.0.1:0"
node_id = "affinity-switch"
secret_key = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
`
	// A remote_lookup proxy without lookup_local_users needs no database.
	const affinityProxy = `
[[server]]
type = "imap_proxy"
name = "affinity-proxy"
addr = "127.0.0.1:0"
remote_addrs = ["127.0.0.1:1"]
enable_affinity = true

[server.remote_lookup]
enabled = true
url = "http://127.0.0.1:1/lookup/$email"
`
	const warning = "enable_affinity has no effect"
	for _, tc := range []struct {
		name     string
		cluster  string
		affinity string
		want     bool
	}{
		{name: "key absent", cluster: clusterSection, affinity: "", want: true},
		{name: "section without enabled", cluster: clusterSection, affinity: "[cluster.affinity]\nttl = \"1h\"\n", want: true},
		{name: "enabled = true", cluster: clusterSection, affinity: "[cluster.affinity]\nenabled = true\n", want: true},
		{name: "enabled = false", cluster: clusterSection, affinity: "[cluster.affinity]\nenabled = false\n", want: false},
		{name: "no cluster", cluster: "", affinity: "[cluster.affinity]\nenabled = true\n", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cachePath := filepath.Join(dir, "affinity.db")
			body := tc.cluster + tc.affinity
			if tc.affinity != "" {
				body += "cache_path = " + strconv.Quote(cachePath) + "\n"
			}
			body += affinityProxy
			path := filepath.Join(dir, "config.toml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := config.NewDefaultConfig() // seeded as main seeds it
			if err := config.LoadConfigFromFile(path, &cfg); err != nil {
				t.Fatalf("load config: %v", err)
			}

			logs := &syncLogBuffer{}
			prev := logger.Swap(slog.New(slog.NewTextHandler(logs, nil)))
			t.Cleanup(func() { logger.Swap(prev) })

			ctx, cancel := context.WithCancel(context.Background())
			deps, err := initializeServices(ctx, cfg, errors.NewErrorHandler())
			if err != nil {
				cancel()
				t.Fatalf("initializeServices: %v", err)
			}
			t.Cleanup(func() {
				cancel()
				deps.healthIntegration.Stop()
				deps.affinityManager.Stop()
				if deps.clusterManager != nil {
					_ = deps.clusterManager.Shutdown()
				}
			})

			if tc.cluster != "" && deps.clusterManager == nil {
				t.Fatal("no cluster manager with [cluster] enabled = true")
			}
			if got := deps.affinityManager != nil; got != tc.want {
				t.Errorf("affinity manager running = %v, want %v", got, tc.want)
			}
			_, statErr := os.Stat(cachePath)
			if opened := statErr == nil; opened != (tc.want && tc.affinity != "") {
				t.Errorf("affinity cache %s opened = %v with affinity running = %v", cachePath, opened, tc.want)
			}
			out := logs.String()
			if warned := strings.Contains(out, warning) && strings.Contains(out, "affinity-proxy"); warned == tc.want {
				t.Errorf("warning naming affinity-proxy logged = %v with affinity running = %v; log:\n%s", warned, tc.want, out)
			}
		})
	}
}
