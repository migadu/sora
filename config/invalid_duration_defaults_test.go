package config

import (
	"testing"
	"time"
)

// An unparsable timeout gets the value the key has when it is absent, not a
// separate hard-coded fallback (#295).
func TestInvalidServerTimeoutsFallBackToAbsentDefaults(t *testing.T) {
	for _, typ := range []string{"imap", "pop3", "managesieve", "imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy"} {
		absent := ServerConfig{Type: typ, Name: typ}
		invalid := ServerConfig{
			Type:            typ,
			Name:            typ,
			AuthIdleTimeout: "2 min",
			Timeouts: &ServerTimeoutsConfig{
				CommandTimeout:         "30 min",
				AbsoluteSessionTimeout: "1 day",
			},
		}

		if want, err := absent.GetCommandTimeout(); err != nil {
			t.Fatalf("%s: absent command_timeout: %v", typ, err)
		} else if got := invalid.GetCommandTimeoutWithDefault(); got != want {
			t.Errorf("%s: invalid command_timeout = %v, want the absent-key default %v", typ, got, want)
		}

		if want, err := absent.GetAbsoluteSessionTimeout(); err != nil {
			t.Fatalf("%s: absent absolute_session_timeout: %v", typ, err)
		} else if got := invalid.GetAbsoluteSessionTimeoutWithDefault(); got != want {
			t.Errorf("%s: invalid absolute_session_timeout = %v, want the absent-key default %v", typ, got, want)
		}

		if want, err := absent.GetAuthIdleTimeout(); err != nil {
			t.Fatalf("%s: absent auth_idle_timeout: %v", typ, err)
		} else if got := invalid.GetAuthIdleTimeoutWithDefault(); got != want {
			t.Errorf("%s: invalid auth_idle_timeout = %v, want the absent-key default %v", typ, got, want)
		}
	}
}

// RFC 9051 §5.4 / RFC 3501 §5.4: an IMAP inactivity autologout timer MUST be at
// least 30 minutes. RFC 1939 §3: a POP3 one MUST be at least 10 minutes. An
// unparsable command_timeout must not drop below them.
func TestInvalidCommandTimeoutKeepsRFCMinimums(t *testing.T) {
	for typ, min := range map[string]time.Duration{
		"imap":       30 * time.Minute,
		"imap_proxy": 30 * time.Minute,
		"pop3":       10 * time.Minute,
		"pop3_proxy": 10 * time.Minute,
	} {
		cfg := ServerConfig{Type: typ, Name: typ, Timeouts: &ServerTimeoutsConfig{CommandTimeout: "30 min"}}
		if got := cfg.GetCommandTimeoutWithDefault(); got < min {
			t.Errorf("%s: invalid command_timeout falls back to %v, below the RFC minimum %v", typ, got, min)
		}
	}
}

func TestInvalidAuthCacheDurationsFallBackToAbsentDefaults(t *testing.T) {
	absent := AuthCacheConfig{}
	invalid := AuthCacheConfig{MaxAge: "24", PurgeUnused: "1 week", CleanupInterval: "hourly"}

	if want, _ := absent.GetMaxAge(); invalid.GetMaxAgeWithDefault() != want {
		t.Errorf("invalid max_age = %v, want the absent-key default %v", invalid.GetMaxAgeWithDefault(), want)
	}
	if want, _ := absent.GetPurgeUnused(); invalid.GetPurgeUnusedWithDefault() != want {
		t.Errorf("invalid purge_unused = %v, want the absent-key default %v", invalid.GetPurgeUnusedWithDefault(), want)
	}
	if want, _ := absent.GetCleanupInterval(); invalid.GetCleanupIntervalWithDefault() != want {
		t.Errorf("invalid cleanup_interval = %v, want the absent-key default %v", invalid.GetCleanupIntervalWithDefault(), want)
	}
}

// The [auth_cache] values in config.toml.example must parse; max_age = "24" had
// no unit, so a copied example silently ran on the fallback.
func TestExampleConfigAuthCacheDurationsParse(t *testing.T) {
	var cfg Config
	if err := LoadConfigFromFile("../config.toml.example", &cfg); err != nil {
		t.Fatalf("load config.toml.example: %v", err)
	}
	if _, err := cfg.AuthCache.GetMaxAge(); err != nil {
		t.Errorf("[auth_cache] max_age: %v", err)
	}
	if _, err := cfg.AuthCache.GetPurgeUnused(); err != nil {
		t.Errorf("[auth_cache] purge_unused: %v", err)
	}
	if _, err := cfg.AuthCache.GetCleanupInterval(); err != nil {
		t.Errorf("[auth_cache] cleanup_interval: %v", err)
	}
}

// token_duration takes the same syntax as every other duration key, so the
// documented "7d" works, and a negative value is rejected (#295).
func TestGetTokenDuration(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"", 24 * time.Hour, false},
		{"12h", 12 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"-1h", 0, true},
		{"-7d", 0, true},
		{"one day", 0, true},
	}
	for _, tt := range tests {
		cfg := ServerConfig{Type: "http_user_api", Name: "user-api", TokenDuration: tt.in}
		got, err := cfg.GetTokenDuration()
		if (err != nil) != tt.wantErr {
			t.Errorf("GetTokenDuration(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("GetTokenDuration(%q) = %v, want %v", tt.in, got, tt.want)
		}
		if tt.wantErr {
			if d := cfg.GetTokenDurationWithDefault(); d != 24*time.Hour {
				t.Errorf("GetTokenDurationWithDefault(%q) = %v, want the default 24h", tt.in, d)
			}
		}
	}
}
