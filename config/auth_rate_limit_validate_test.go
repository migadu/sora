package config

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func decodeAuthRateLimitServer(t *testing.T, settings string) ServerConfig {
	t.Helper()
	var cfg Config
	if _, err := toml.Decode(`
[[server]]
type = "imap"
name = "imap"
addr = ":143"

[server.auth_rate_limit]
`+settings, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.DynamicServers[0]
}

// Negative auth_rate_limit counts, durations and multipliers are refused at
// startup: max_attempts_per_ip = -1 blocked an address on its first failed IMAP
// login, while the same value disabled the IP block on the other protocols (#341).
func TestAuthRateLimitNegativeValuesRejected(t *testing.T) {
	for key, value := range map[string]string{
		"max_attempts_per_ip_username": "-1",
		"ip_username_block_duration":   `"-15m"`,
		"ip_username_window_duration":  `"-10m"`,
		"max_attempts_per_ip":          "-1",
		"ip_block_duration":            `"-30m"`,
		"ip_window_duration":           `"-30m"`,
		"max_attempts_per_username":    "-1",
		"username_window_duration":     `"-1h"`,
		"cleanup_interval":             `"-5m"`,
		"delay_start_threshold":        "-1",
		"initial_delay":                `"-1s"`,
		"max_delay":                    `"-30s"`,
		"delay_multiplier":             "-2.0",
		"max_ip_username_entries":      "-1",
		"max_ip_entries":               "-1",
		"max_username_entries":         "-1",
	} {
		for _, enabled := range []string{"true", "false"} {
			s := decodeAuthRateLimitServer(t, "enabled = "+enabled+"\n"+key+" = "+value+"\n")
			err := s.Validate()
			if err == nil {
				t.Errorf("enabled = %s, %s = %s: accepted", enabled, key, value)
				continue
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("%s = %s: error %q does not name the key", key, value, err)
			}
		}
	}
}

// Zero (use the default) and the documented values stay valid.
func TestAuthRateLimitValidValuesAccepted(t *testing.T) {
	for _, settings := range []string{
		"enabled = true\n",
		"enabled = true\nmax_attempts_per_ip = 0\nip_block_duration = \"0s\"\ndelay_multiplier = 0.0\n",
		"enabled = true\nmax_attempts_per_ip_username = 5\nip_username_block_duration = \"15m\"\nmax_attempts_per_ip = 50\n" +
			"ip_block_duration = \"30m\"\ndelay_start_threshold = 2\ninitial_delay = \"1s\"\nmax_delay = \"30s\"\ndelay_multiplier = 2.0\n",
	} {
		s := decodeAuthRateLimitServer(t, settings)
		if err := s.Validate(); err != nil {
			t.Errorf("%q rejected: %v", settings, err)
		}
	}
}

// TOML allows nan and inf, and both pass a "not negative" check. Neither is a
// multiplier: the limiter converts LastDelay*delay_multiplier to a time.Duration
// before capping it at max_delay, and on amd64 that conversion turns +Inf into the
// minimum int64, a negative delay that switches progressive delays off.
func TestAuthRateLimitNonFiniteMultiplierRejected(t *testing.T) {
	for _, value := range []string{"nan", "inf", "+inf", "-inf"} {
		for _, enabled := range []string{"true", "false"} {
			s := decodeAuthRateLimitServer(t, "enabled = "+enabled+"\ndelay_multiplier = "+value+"\n")
			err := s.Validate()
			if err == nil {
				t.Errorf("enabled = %s, delay_multiplier = %s: accepted", enabled, value)
				continue
			}
			if !strings.Contains(err.Error(), "delay_multiplier") {
				t.Errorf("delay_multiplier = %s: error %q does not name the key", value, err)
			}
		}
	}
}
