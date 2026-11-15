package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/metrics"
)

// metricsSettings is what metrics.Configure sets.
type metricsSettings struct {
	enableUser, enableDomain bool
	threshold, maxUsers      int
	hashNames                bool
}

func currentMetricsSettings() metricsSettings {
	return metricsSettings{
		metrics.EnableUserMetrics, metrics.EnableDomainMetrics,
		metrics.UserMetricsThreshold, metrics.MaxTrackedUsers,
		metrics.HashUsernames,
	}
}

// noMetricsBlockSettings are the settings of a node without a metrics block: the
// pkg/metrics defaults, read before any test can call metrics.Configure.
var noMetricsBlockSettings = currentMetricsSettings()

// configureMetricsFromFile loads body as a config file and configures metrics from
// its first server block, as startServers does, restoring the settings afterwards.
func configureMetricsFromFile(t *testing.T, body string) metricsSettings {
	t.Helper()
	saved := currentMetricsSettings()
	t.Cleanup(func() {
		metrics.Configure(saved.enableUser, saved.enableDomain, saved.threshold, saved.maxUsers, saved.hashNames)
	})

	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err := config.LoadConfigFromFile(path, &cfg); err != nil {
		t.Fatal(err)
	}
	servers := cfg.GetAllServers()
	if len(servers) != 1 || servers[0].Type != "metrics" {
		t.Fatalf("want one metrics server, got %+v", servers)
	}
	configureMetrics(servers[0])
	return currentMetricsSettings()
}

// A metrics block that sets only enable_user_metrics = true must leave every other
// setting as a node without a metrics block has it: domain metrics on, a 1000-event
// threshold, at most 1000 tracked users, hashed usernames (#297). Before, the absent
// keys arrived as false/0, so nobody was ever tracked and hashing was off.
func TestConfigureMetricsKeepsDefaultsForAbsentKeys(t *testing.T) {
	got := configureMetricsFromFile(t, `
[[server]]
type = "metrics"
name = "metrics"
addr = "127.0.0.1:9090"
path = "/metrics"
enable_user_metrics = true
`)
	want := noMetricsBlockSettings
	want.enableUser = true
	if got != want {
		t.Errorf("configured %+v, want the no-block defaults with user metrics on, %+v", got, want)
	}
	if want := (metricsSettings{true, true, 1000, 1000, true}); got != want {
		t.Errorf("configured %+v, want the documented defaults %+v", got, want)
	}
}

// Keys the block sets, including false and 0, replace the defaults.
func TestConfigureMetricsAppliesExplicitKeys(t *testing.T) {
	got := configureMetricsFromFile(t, `
[[server]]
type = "metrics"
name = "metrics"
addr = "127.0.0.1:9090"
path = "/metrics"
enable_user_metrics = true
enable_domain_metrics = false
user_metrics_threshold = 0
max_tracked_users = 100
hash_usernames = false
`)
	if want := (metricsSettings{true, false, 0, 100, false}); got != want {
		t.Errorf("configured %+v, want %+v", got, want)
	}
}
