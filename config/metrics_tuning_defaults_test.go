package config

import (
	"testing"

	"github.com/BurntSushi/toml"
)

// A metrics block keeps the documented tuning defaults for every key it leaves
// out: enable_user_metrics = true on its own must track up to 1000 users above
// a 1000-event threshold, with hashed usernames and domain metrics on (#297).
func TestMetricsTuningKeysAbsentKeepDefaults(t *testing.T) {
	var cfg Config
	if _, err := toml.Decode(`
[[server]]
type = "metrics"
name = "metrics"
addr = "127.0.0.1:9090"
enable_user_metrics = true
`, &cfg); err != nil {
		t.Fatal(err)
	}
	s := cfg.DynamicServers[0]

	if !s.EnableUserMetrics {
		t.Error("enable_user_metrics = true was not decoded")
	}
	if !s.GetEnableDomainMetrics() {
		t.Error("enable_domain_metrics absent: got false, want the default true")
	}
	if got := s.GetUserMetricsThreshold(); got != 1000 {
		t.Errorf("user_metrics_threshold absent: got %d, want the default 1000", got)
	}
	if got := s.GetMaxTrackedUsers(); got != 1000 {
		t.Errorf("max_tracked_users absent: got %d, want the default 1000", got)
	}
	if !s.GetHashUsernames() {
		t.Error("hash_usernames absent: got false, want the default true")
	}
}

// Explicit values, including false and 0, still override the defaults.
func TestMetricsTuningKeysExplicitValuesWin(t *testing.T) {
	var cfg Config
	if _, err := toml.Decode(`
[[server]]
type = "metrics"
name = "metrics"
addr = "127.0.0.1:9090"
enable_user_metrics = true
enable_domain_metrics = false
user_metrics_threshold = 0
max_tracked_users = 100
hash_usernames = false
`, &cfg); err != nil {
		t.Fatal(err)
	}
	s := cfg.DynamicServers[0]

	if s.GetEnableDomainMetrics() {
		t.Error("enable_domain_metrics = false: got true")
	}
	if got := s.GetUserMetricsThreshold(); got != 0 {
		t.Errorf("user_metrics_threshold = 0: got %d", got)
	}
	if got := s.GetMaxTrackedUsers(); got != 100 {
		t.Errorf("max_tracked_users = 100: got %d", got)
	}
	if s.GetHashUsernames() {
		t.Error("hash_usernames = false: got true")
	}
}
