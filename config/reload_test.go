package config

import (
	"slices"
	"testing"
)

// startedServer is the config a server started with, fresh on every call so a case can
// change it through its pointers without touching the next case.
func startedServer() ServerConfig {
	return ServerConfig{
		Type: "imap", Name: "imap-1", Addr: ":143", TLS: true, MaxConnections: 1000,
		TokenDuration: "24h", AllowedHosts: []string{"10.0.0.0/8"},
		Timeouts:      &ServerTimeoutsConfig{CommandTimeout: "30m", SchedulerShardCount: 4},
		Limits:        &ServerLimitsConfig{SessionMemoryLimit: "100mb", MaxAuthErrors: 3},
		ClientFilters: []ClientCapabilityFilter{{ClientName: "iOS", DisableCaps: []string{"IDLE"}}},
	}
}

func TestRestartRequiredChanges(t *testing.T) {
	reloadable := []string{"timeouts.command_timeout", "limits.session_memory_limit", "master_sasl_username"}
	off := false

	tests := []struct {
		name   string
		change func(*ServerConfig)
		want   []string
	}{
		{"unchanged", func(*ServerConfig) {}, nil},
		{"a reloadable setting", func(c *ServerConfig) { c.MasterSASLUsername = "proxy" }, nil},
		{"a reloadable setting in a table", func(c *ServerConfig) { c.Timeouts.CommandTimeout = "45m" }, nil},
		{"addr", func(c *ServerConfig) { c.Addr = ":1143" }, []string{"addr"}},
		{"tls", func(c *ServerConfig) { c.TLS = false }, []string{"tls"}},
		{"token_duration", func(c *ServerConfig) { c.TokenDuration = "48h" }, []string{"token_duration"}},
		{"max_connections", func(c *ServerConfig) { c.MaxConnections = 2000 }, []string{"max_connections"}},
		{"type", func(c *ServerConfig) { c.Type = "pop3" }, []string{"type"}},
		{"a list grown", func(c *ServerConfig) { c.AllowedHosts = []string{"10.0.0.0/8", "192.0.2.0/24"} }, []string{"allowed_hosts"}},
		{"a list emptied", func(c *ServerConfig) { c.AllowedHosts = nil }, []string{"allowed_hosts"}},
		{"an array of tables", func(c *ServerConfig) { c.ClientFilters[0].Reason = "known IDLE issues" }, []string{"client_filters"}},
		{"a pointer flag set", func(c *ServerConfig) { c.RemoteHealthChecks = &off }, []string{"remote_health_checks"}},
		{"a setting in a table", func(c *ServerConfig) { c.Timeouts.SchedulerShardCount = 8 }, []string{"timeouts.scheduler_shard_count"}},
		{"a setting in a nested table", func(c *ServerConfig) {
			c.Timeouts.IMAPCommandTimeouts = &CommandTimeoutsConfig{Search: "10s"}
		}, []string{"timeouts.imap_command_timeouts.search"}},
		// session_memory_limit is reloadable; max_auth_errors goes from 3 to its zero.
		{"a table removed", func(c *ServerConfig) { c.Limits = nil }, []string{"limits.max_auth_errors"}},
		{"several, in declaration order", func(c *ServerConfig) {
			c.Timeouts.SchedulerShardCount = 1
			c.MaxConnections = 1
			c.Timeouts.CommandTimeout = "1m"
			c.Addr = ":1"
		}, []string{"addr", "max_connections", "timeouts.scheduler_shard_count"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			started, next := startedServer(), startedServer()
			tt.change(&next)
			if got := started.RestartRequiredChanges(next, reloadable); !slices.Equal(got, tt.want) {
				t.Errorf("RestartRequiredChanges = %v, want %v", got, tt.want)
			}
		})
	}
}

// With nothing reloadable, every change is reported.
func TestRestartRequiredChangesWithNothingReloadable(t *testing.T) {
	started, next := startedServer(), startedServer()
	next.Timeouts.CommandTimeout = "45m"
	if got, want := started.RestartRequiredChanges(next, nil), []string{"timeouts.command_timeout"}; !slices.Equal(got, want) {
		t.Errorf("RestartRequiredChanges = %v, want %v", got, want)
	}
}

// A table a config does not have is one with every value zero, so adding it to the file
// with only reloadable settings, or empty, changes nothing that needs a restart.
func TestRestartRequiredChangesTreatsAnAbsentTableAsDefaults(t *testing.T) {
	started := ServerConfig{Type: "imap", Name: "imap-1", Addr: ":143"}
	reloadable := []string{"timeouts.command_timeout"}

	tests := []struct {
		name     string
		timeouts *ServerTimeoutsConfig
		want     []string
	}{
		{"still absent", nil, nil},
		{"added empty", &ServerTimeoutsConfig{}, nil},
		{"added with a reloadable setting", &ServerTimeoutsConfig{CommandTimeout: "45m"}, nil},
		{"added with another setting", &ServerTimeoutsConfig{CommandTimeout: "45m", SchedulerShardCount: 2}, []string{"timeouts.scheduler_shard_count"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := started
			next.Timeouts = tt.timeouts
			if got := started.RestartRequiredChanges(next, reloadable); !slices.Equal(got, tt.want) {
				t.Errorf("RestartRequiredChanges = %v, want %v", got, tt.want)
			}
			// And the other way round: the table removed from the file.
			if got := next.RestartRequiredChanges(started, reloadable); !slices.Equal(got, tt.want) {
				t.Errorf("RestartRequiredChanges (removed) = %v, want %v", got, tt.want)
			}
		})
	}
}

// The keys are the leaves of [[server]] by their TOML names, tables dotted, each once;
// a table itself is not a key, so one listed as reloadable would match nothing.
func TestServerConfigKeys(t *testing.T) {
	keys := ServerConfigKeys()
	for _, want := range []string{
		"type", "name", "addr", "tls", "token_duration", "max_connections", "client_filters",
		"timeouts.command_timeout", "timeouts.imap_command_timeouts.search",
		"limits.max_auth_errors", "auth_rate_limit.exempt_networks",
		"remote_lookup.circuit_breaker.failure_ratio",
	} {
		if !slices.Contains(keys, want) {
			t.Errorf("ServerConfigKeys lacks %q", want)
		}
	}
	for _, table := range []string{"timeouts", "limits", "remote_lookup", "remote_lookup.circuit_breaker"} {
		if slices.Contains(keys, table) {
			t.Errorf("ServerConfigKeys names the table %q as a setting", table)
		}
	}
	seen := make(map[string]bool, len(keys))
	for _, key := range keys {
		if seen[key] {
			t.Errorf("ServerConfigKeys names %q twice", key)
		}
		seen[key] = true
	}
}
