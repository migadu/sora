package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestClusterRateLimitSyncDefaults: [cluster.rate_limit_sync] is documented as on,
// with both sync_blocks and sync_failure_counts, unless the operator says
// otherwise. The server loads its file onto NewDefaultConfig, so that is where an
// absent key gets its value.
func TestClusterRateLimitSyncDefaults(t *testing.T) {
	cases := []struct {
		name string
		toml string
		want ClusterRateLimitSyncConfig
	}{
		{
			name: "section absent",
			toml: "[cluster]\nenabled = true\n",
			want: ClusterRateLimitSyncConfig{Enabled: true, SyncBlocks: true, SyncFailureCounts: true},
		},
		{
			name: "only enabled = false",
			toml: "[cluster]\nenabled = true\n[cluster.rate_limit_sync]\nenabled = false\n",
			want: ClusterRateLimitSyncConfig{Enabled: false, SyncBlocks: true, SyncFailureCounts: true},
		},
		{
			name: "failure counts off",
			toml: "[cluster]\nenabled = true\n[cluster.rate_limit_sync]\nsync_failure_counts = false\n",
			want: ClusterRateLimitSyncConfig{Enabled: true, SyncBlocks: true, SyncFailureCounts: false},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.toml), 0o600); err != nil {
				t.Fatal(err)
			}

			cfg := NewDefaultConfig()
			if err := LoadConfigFromFile(path, &cfg); err != nil {
				t.Fatalf("load config: %v", err)
			}
			if cfg.Cluster.RateLimitSync != tc.want {
				t.Errorf("rate_limit_sync = %+v, want %+v", cfg.Cluster.RateLimitSync, tc.want)
			}
		})
	}
}
