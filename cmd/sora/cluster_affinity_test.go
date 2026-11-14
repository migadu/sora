package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/errors"
)

// [cluster.affinity] enabled is the switch for the cluster affinity manager, which every
// proxy consults for enable_affinity and which gossips affinities to the other nodes
// (#431). A cluster config without the key keeps affinity on, as before the key was
// read; only an explicit false turns it off.
func TestInitializeServices_ClusterAffinityEnabled(t *testing.T) {
	const clusterSection = `
[cluster]
enabled = true
addr = "127.0.0.1:0"
node_id = "affinity-switch"
secret_key = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
`
	for _, tc := range []struct {
		name     string
		affinity string
		want     bool
	}{
		{name: "key absent", affinity: "", want: true},
		{name: "enabled = true", affinity: "[cluster.affinity]\nenabled = true\n", want: true},
		{name: "enabled = false", affinity: "[cluster.affinity]\nenabled = false\n", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cachePath := filepath.Join(dir, "affinity.db")
			body := clusterSection + tc.affinity
			if tc.affinity != "" {
				body += "cache_path = " + strconv.Quote(cachePath) + "\n"
			}
			path := filepath.Join(dir, "config.toml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := config.NewDefaultConfig() // seeded as main seeds it
			if err := config.LoadConfigFromFile(path, &cfg); err != nil {
				t.Fatalf("load config: %v", err)
			}

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

			if deps.clusterManager == nil {
				t.Fatal("no cluster manager with [cluster] enabled = true")
			}
			if got := deps.affinityManager != nil; got != tc.want {
				t.Errorf("affinity manager running = %v, want %v", got, tc.want)
			}
			if _, err := os.Stat(cachePath); err == nil && !tc.want {
				t.Errorf("affinity cache %s opened with affinity disabled", cachePath)
			}
		})
	}
}
