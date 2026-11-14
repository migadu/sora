package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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

// limitsAppliedBy is every [server.limits] key with the server types whose start
// functions read it (#619). The config accepts each key on every type.
var limitsAppliedBy = map[string]struct {
	set   func(*ServerLimitsConfig)
	types []string
}{
	// IMAP backend: buildIMAPServerOptions and the FETCH PREVIEW budgets.
	"search_rate_limit_per_min": {func(l *ServerLimitsConfig) { n := 30; l.SearchRateLimitPerMin = &n }, []string{"imap"}},
	"search_rate_limit_window":  {func(l *ServerLimitsConfig) { l.SearchRateLimitWindow = "2m" }, []string{"imap"}},
	"search_rate_limit_burst":   {func(l *ServerLimitsConfig) { n := 10; l.SearchRateLimitBurst = &n }, []string{"imap"}},
	"thread_max_messages":       {func(l *ServerLimitsConfig) { l.ThreadMaxMessages = 1000 }, []string{"imap"}},
	"preview_s3_per_min":        {func(l *ServerLimitsConfig) { n := 0; l.PreviewS3PerMin = &n }, []string{"imap"}},
	"preview_s3_burst":          {func(l *ServerLimitsConfig) { n := 5; l.PreviewS3Burst = &n }, []string{"imap"}},
	"preview_s3_node_per_min":   {func(l *ServerLimitsConfig) { n := 100; l.PreviewS3NodePerMin = &n }, []string{"imap"}},
	"preview_s3_max_size":       {func(l *ServerLimitsConfig) { l.PreviewS3MaxSize = "5mb" }, []string{"imap"}},
	// The session memory tracker exists in the IMAP and POP3 backends only.
	"session_memory_limit": {func(l *ServerLimitsConfig) { l.SessionMemoryLimit = "50mb" }, []string{"imap", "pop3"}},
	// The pre-authentication error counter exists in the three login proxies only.
	"max_auth_errors": {func(l *ServerLimitsConfig) { l.MaxAuthErrors = 3 }, []string{"imap_proxy", "pop3_proxy", "managesieve_proxy"}},
	// Sieve runs on delivery: LMTP and the Admin API's /admin/mail/deliver.
	"redirect_rate_limit":  {func(l *ServerLimitsConfig) { n := 0; l.RedirectRateLimit = &n }, []string{"lmtp", "http_admin_api"}},
	"redirect_rate_window": {func(l *ServerLimitsConfig) { l.RedirectRateWindow = "2h" }, []string{"lmtp", "http_admin_api"}},
	"max_redirect_hops":    {func(l *ServerLimitsConfig) { n := 1; l.MaxRedirectHops = &n }, []string{"lmtp", "http_admin_api"}},
}

// TestLimitsAppliedByCoversEveryKey keeps limitsAppliedBy complete: a new
// [server.limits] key needs a decision on which server types apply it.
func TestLimitsAppliedByCoversEveryKey(t *testing.T) {
	limitsType := reflect.TypeOf(ServerLimitsConfig{})
	keys := map[string]bool{}
	for i := range limitsType.NumField() {
		key, _, _ := strings.Cut(limitsType.Field(i).Tag.Get("toml"), ",")
		keys[key] = true
		if _, ok := limitsAppliedBy[key]; !ok {
			t.Errorf("limits.%s is not in limitsAppliedBy: say which server types apply it", key)
		}
	}
	for key := range limitsAppliedBy {
		if !keys[key] {
			t.Errorf("limitsAppliedBy lists limits.%s, which ServerLimitsConfig does not have", key)
		}
	}
}

// Each [server.limits] key set on a server type that does not apply it is reported
// at startup, naming the key and the server (#619); on a type that applies it,
// nothing is reported.
func TestWarnUnusedConfigOptions_LimitsTheServerTypeDoesNotApply(t *testing.T) {
	for key, spec := range limitsAppliedBy {
		for _, serverType := range ServerTypes {
			t.Run(key+"/"+serverType, func(t *testing.T) {
				var limits ServerLimitsConfig
				spec.set(&limits)
				s := ServerConfig{Type: serverType, Name: "server-619", Limits: &limits}
				var named []string
				s.WarnUnusedConfigOptions(func(format string, args ...any) {
					if w := fmt.Sprintf(format, args...); strings.Contains(w, "'limits."+key+"'") {
						named = append(named, w)
					}
				})
				if slices.Contains(spec.types, serverType) {
					if len(named) > 0 {
						t.Errorf("limits.%s applies to %s but was warned about: %v", key, serverType, named)
					}
					return
				}
				if len(named) != 1 || !strings.Contains(named[0], "server-619") {
					t.Errorf("limits.%s on %s (applied by %v only): want one warning naming it on server-619, got %v", key, serverType, spec.types, named)
				}
			})
		}
	}
}

// config.toml.example sets no key in a block whose server type does not apply it.
func TestExampleConfigSetsNoUnappliedKey(t *testing.T) {
	cfg := NewDefaultConfig()
	if err := LoadConfigFromFile("../config.toml.example", &cfg); err != nil {
		t.Fatalf("load config.toml.example: %v", err)
	}
	servers := cfg.GetAllServers()
	if len(servers) == 0 {
		t.Fatal("config.toml.example has no enabled [[server]] block")
	}
	for _, s := range servers {
		s.WarnUnusedConfigOptions(func(format string, args ...any) {
			t.Errorf("config.toml.example: %s", fmt.Sprintf(format, args...))
		})
	}
}
