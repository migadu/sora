package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Keys the config accepts on a server type whose start function never reads them
// (#290). Each one is reported at startup, naming the key; a key the server type does
// apply is not.
func TestWarnUnusedConfigOptions_KeysTheServerTypeDoesNotApply(t *testing.T) {
	timeouts := func(t ServerTimeoutsConfig) *ServerTimeoutsConfig { return &t }
	tests := []struct {
		name    string
		server  ServerConfig
		wantKey string // "" for no warning
	}{
		// The timeout scheduler is one per process, sized by [timeout_scheduler].
		{"imap scheduler_shard_count", ServerConfig{Type: "imap", Timeouts: timeouts(ServerTimeoutsConfig{SchedulerShardCount: 4})}, "timeouts.scheduler_shard_count"},
		{"pop3_proxy scheduler_shard_count", ServerConfig{Type: "pop3_proxy", Timeouts: timeouts(ServerTimeoutsConfig{SchedulerShardCount: -1})}, "timeouts.scheduler_shard_count"},

		// A ManageSieve backend advertises [sieve] enabled_extensions.
		{"managesieve supported_extensions", ServerConfig{Type: "managesieve", SupportedExtensions: []string{"vacation"}}, "supported_extensions"},
		{"managesieve_proxy supported_extensions", ServerConfig{Type: "managesieve_proxy", SupportedExtensions: []string{"vacation"}}, ""},

		// Only proxies dial backends.
		{"imap remote_tls_ca_file", ServerConfig{Type: "imap", RemoteTLSCAFile: "/etc/sora/backend-ca.pem"}, "remote_tls_ca_file"},
		{"imap_proxy remote_tls_ca_file", ServerConfig{Type: "imap_proxy", RemoteTLSCAFile: "/etc/sora/backend-ca.pem"}, ""},
		{"user_api_proxy remote_tls_ca_file", ServerConfig{Type: "user_api_proxy", RemoteTLSCAFile: "/etc/sora/backend-ca.pem"}, ""},

		// LMTP backend: command_timeout is its idle timeout; the rest is not applied.
		{"lmtp command_timeout", ServerConfig{Type: "lmtp", Timeouts: timeouts(ServerTimeoutsConfig{CommandTimeout: "10m"})}, ""},
		{"lmtp absolute_session_timeout", ServerConfig{Type: "lmtp", Timeouts: timeouts(ServerTimeoutsConfig{AbsoluteSessionTimeout: "1h"})}, "timeouts.absolute_session_timeout"},
		{"lmtp min_bytes_per_minute", ServerConfig{Type: "lmtp", Timeouts: timeouts(ServerTimeoutsConfig{MinBytesPerMinute: 512})}, "timeouts.min_bytes_per_minute"},
		{"lmtp auth_idle_timeout", ServerConfig{Type: "lmtp", AuthIdleTimeout: "2m"}, "auth_idle_timeout"},
		{"lmtp session_memory_limit", ServerConfig{Type: "lmtp", Limits: &ServerLimitsConfig{SessionMemoryLimit: "100mb"}}, "limits.session_memory_limit"},
		{"lmtp max_connections_per_user", ServerConfig{Type: "lmtp", MaxConnectionsPerUser: 10}, "max_connections_per_user"},
		{"lmtp max_connections_per_user_per_ip", ServerConfig{Type: "lmtp", MaxConnectionsPerUserPerIP: 5}, "max_connections_per_user_per_ip"},
		{"lmtp max_connections_per_ip", ServerConfig{Type: "lmtp", MaxConnectionsPerIP: 5}, "max_connections_per_ip"},

		// LMTP proxy: absolute_session_timeout and auth_idle_timeout apply, these do not.
		{"lmtp_proxy command_timeout", ServerConfig{Type: "lmtp_proxy", Timeouts: timeouts(ServerTimeoutsConfig{CommandTimeout: "0"})}, "timeouts.command_timeout"},
		{"lmtp_proxy min_bytes_per_minute", ServerConfig{Type: "lmtp_proxy", Timeouts: timeouts(ServerTimeoutsConfig{MinBytesPerMinute: 512})}, "timeouts.min_bytes_per_minute"},
		{"lmtp_proxy max_connections_per_ip", ServerConfig{Type: "lmtp_proxy", MaxConnectionsPerIP: 20}, "max_connections_per_ip"},
		{"lmtp_proxy max_connections_per_user", ServerConfig{Type: "lmtp_proxy", MaxConnectionsPerUser: 10}, "max_connections_per_user"},
		{"lmtp_proxy max_connections_per_user_per_ip", ServerConfig{Type: "lmtp_proxy", MaxConnectionsPerUserPerIP: 5}, "max_connections_per_user_per_ip"},
		{"lmtp_proxy absolute_session_timeout", ServerConfig{Type: "lmtp_proxy", Timeouts: timeouts(ServerTimeoutsConfig{AbsoluteSessionTimeout: "5m"})}, ""},
		{"lmtp_proxy auth_idle_timeout", ServerConfig{Type: "lmtp_proxy", AuthIdleTimeout: "2m"}, ""},

		// auth_rate_limit: only servers that check passwords build the limiter. The
		// Admin API compares a bearer key and answers 403 at once, every time (#504).
		{"http_admin_api auth_rate_limit", ServerConfig{Type: "http_admin_api", AuthRateLimit: &AuthRateLimiterConfig{Enabled: true}}, "auth_rate_limit"},
		{"metrics auth_rate_limit", ServerConfig{Type: "metrics", AuthRateLimit: &AuthRateLimiterConfig{Enabled: true}}, "auth_rate_limit"},
		{"lmtp auth_rate_limit", ServerConfig{Type: "lmtp", AuthRateLimit: &AuthRateLimiterConfig{Enabled: true}}, "auth_rate_limit"},
		{"lmtp_proxy auth_rate_limit", ServerConfig{Type: "lmtp_proxy", AuthRateLimit: &AuthRateLimiterConfig{Enabled: true}}, "auth_rate_limit"},
		{"user_api_proxy auth_rate_limit", ServerConfig{Type: "user_api_proxy", AuthRateLimit: &AuthRateLimiterConfig{Enabled: true}}, "auth_rate_limit"},
		{"http_admin_api auth_rate_limit disabled", ServerConfig{Type: "http_admin_api", AuthRateLimit: &AuthRateLimiterConfig{Enabled: false}}, ""},
		{"imap auth_rate_limit", ServerConfig{Type: "imap", AuthRateLimit: &AuthRateLimiterConfig{Enabled: true}}, ""},
		{"pop3 auth_rate_limit", ServerConfig{Type: "pop3", AuthRateLimit: &AuthRateLimiterConfig{Enabled: true}}, ""},
		{"managesieve auth_rate_limit", ServerConfig{Type: "managesieve", AuthRateLimit: &AuthRateLimiterConfig{Enabled: true}}, ""},
		{"imap_proxy auth_rate_limit", ServerConfig{Type: "imap_proxy", AuthRateLimit: &AuthRateLimiterConfig{Enabled: true}}, ""},
		{"pop3_proxy auth_rate_limit", ServerConfig{Type: "pop3_proxy", AuthRateLimit: &AuthRateLimiterConfig{Enabled: true}}, ""},
		{"managesieve_proxy auth_rate_limit", ServerConfig{Type: "managesieve_proxy", AuthRateLimit: &AuthRateLimiterConfig{Enabled: true}}, ""},
		{"http_user_api auth_rate_limit", ServerConfig{Type: "http_user_api", AuthRateLimit: &AuthRateLimiterConfig{Enabled: true}}, ""},

		// The same keys on servers that apply them.
		{"imap min_bytes_per_minute", ServerConfig{Type: "imap", Timeouts: timeouts(ServerTimeoutsConfig{MinBytesPerMinute: 512}), MaxConnectionsPerIP: 10}, ""},
		{"pop3_proxy command_timeout", ServerConfig{Type: "pop3_proxy", Timeouts: timeouts(ServerTimeoutsConfig{CommandTimeout: "10m"}), MaxConnectionsPerIP: 10}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.server.Name = "server-290"
			var warnings []string
			tt.server.WarnUnusedConfigOptions(func(format string, args ...any) {
				warnings = append(warnings, fmt.Sprintf(format, args...))
			})
			if tt.wantKey == "" {
				if len(warnings) > 0 {
					t.Errorf("a key %s applies was warned about: %v", tt.server.Type, warnings)
				}
				return
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0], "'"+tt.wantKey+"'") || !strings.Contains(warnings[0], "server-290") {
				t.Errorf("want one warning naming '%s' on server-290, got %v", tt.wantKey, warnings)
			}
		})
	}
}

// The LMTP backend's command_timeout is its idle timeout. Absent, it is the 5
// minutes the server has always used, which RFC 5321 section 4.5.3.2.7 sets as
// the floor ("An SMTP server SHOULD have a timeout of at least 5 minutes while
// it is awaiting the next command from the sender"); RFC 2033 section 4 makes
// LMTP identical to SMTP except as it says.
func TestLMTPCommandTimeoutDefault(t *testing.T) {
	s := ServerConfig{Type: "lmtp", Name: "lmtp"}
	if got, err := s.GetCommandTimeout(); err != nil || got != 5*time.Minute {
		t.Errorf("lmtp command_timeout default = %v, %v; want 5m0s", got, err)
	}
	s.Timeouts = &ServerTimeoutsConfig{CommandTimeout: "five minutes"}
	if got := s.GetCommandTimeoutWithDefault(); got != 5*time.Minute {
		t.Errorf("lmtp invalid command_timeout = %v; want the default 5m0s", got)
	}
}

// [spam_training] async and max_attachment_size were never read: training always
// runs in the background, and attachments are always stripped. A config that sets
// them is told at startup that they are ignored.
func TestSpamTrainingKeysWithoutEffectAreReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(`
[spam_training]
enabled = true
endpoint = "https://spam.example.com/train"
async = false
max_attachment_size = "1mb"
max_message_size = "5mb"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := NewDefaultConfig()
	md, err := LoadConfigFromFileWithMetadata(path, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	var ignored []string
	for _, key := range md.Undecoded() {
		ignored = append(ignored, key.String())
	}
	for _, key := range []string{"spam_training.async", "spam_training.max_attachment_size"} {
		if !slices.Contains(ignored, key) {
			t.Errorf("%s is not reported as ignored (ignored: %v)", key, ignored)
		}
	}
	if slices.Contains(ignored, "spam_training.max_message_size") {
		t.Error("spam_training.max_message_size is applied but reported as ignored")
	}
}
