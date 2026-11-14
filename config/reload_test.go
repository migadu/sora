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

// startedGlobal is the config a node started with, fresh on every call.
func startedGlobal() Config {
	cfg := NewDefaultConfig()
	cfg.Relay = RelayConfig{Type: "smtp", SMTPHost: "smtp.example.com:587"}
	cfg.Pools = []PoolConfig{{Name: "sora1", Backends: []string{"10.0.0.1:143"}, Default: true}}
	cfg.DynamicServers = []ServerConfig{{Type: "imap", Name: "imap-1", Addr: ":143"}}
	cfg.Database.Read = nil
	return cfg
}

// Every global section is compared, by TOML key, except the [[server]] blocks: those are
// each server's own report. Before #282 a reload compared only six sections and
// trusted_networks, so a change to [[pool]], [relay], [database] and the rest was
// neither applied nor reported.
func TestConfigRestartRequiredChanges(t *testing.T) {
	cost := 13
	reloadable := []string{"admin_cli.api_key"}

	tests := []struct {
		name   string
		change func(*Config)
		want   []string
	}{
		{"unchanged", func(*Config) {}, nil},
		{"a reloadable setting", func(c *Config) { c.AdminCLI.APIKey = "new" }, nil},
		{"a [[server]] block", func(c *Config) { c.DynamicServers[0].Addr = ":1143" }, nil},
		{"a [[server]] block added", func(c *Config) {
			c.DynamicServers = append(c.DynamicServers, ServerConfig{Type: "pop3", Name: "pop3-1", Addr: ":110"})
		}, nil},
		{"[[pool]] members", func(c *Config) { c.Pools[0].Backends = []string{"10.0.0.2:143"} }, []string{"pool"}},
		{"relay.smtp_host", func(c *Config) { c.Relay.SMTPHost = "smtp2.example.com:587" }, []string{"relay.smtp_host"}},
		{"bcrypt_cost", func(c *Config) { c.BcryptCost = &cost }, []string{"bcrypt_cost"}},
		{"logging.output and logging.format", func(c *Config) {
			c.Logging.Output = "/var/log/sora/sora.log"
			c.Logging.Format = "json"
		}, []string{"logging.output", "logging.format"}},
		{"database.write.hosts", func(c *Config) { c.Database.Write.Hosts = []string{"db2.example.com"} }, []string{"database.write.hosts"}},
		{"[database.read] added", func(c *Config) {
			c.Database.Read = &DatabaseEndpointConfig{Hosts: []string{"replica.example.com"}}
		}, []string{"database.read.hosts"}},
		{"s3.endpoint", func(c *Config) { c.S3.Endpoint = "s3.example.org" }, []string{"s3.endpoint"}},
		{"tls.cert_file", func(c *Config) { c.TLS.CertFile = "/etc/sora/new.pem" }, []string{"tls.cert_file"}},
		{"cluster.peers", func(c *Config) { c.Cluster.Peers = []string{"10.0.0.9:7946"} }, []string{"cluster.peers"}},
		{"spam_training.endpoint", func(c *Config) { c.SpamTraining.Endpoint = "https://spam.example.com" }, []string{"spam_training.endpoint"}},
		{"uploader.batch_size", func(c *Config) { c.Uploader.BatchSize++ }, []string{"uploader.batch_size"}},
		{"local_cache.capacity", func(c *Config) { c.LocalCache.Capacity = "2gb" }, []string{"local_cache.capacity"}},
		{"auth_cache.enabled", func(c *Config) { c.AuthCache.Enabled = !c.AuthCache.Enabled }, []string{"auth_cache.enabled"}},
		{"timeout_scheduler.shard_count", func(c *Config) { c.TimeoutScheduler.ShardCount = 7 }, []string{"timeout_scheduler.shard_count"}},
		{"several, in declaration order", func(c *Config) {
			c.Pools = nil
			c.Relay.SMTPHost = ""
			c.Logging.Level = "debug"
		}, []string{"logging.level", "relay.smtp_host", "pool"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			started, next := startedGlobal(), startedGlobal()
			tt.change(&next)
			if got := started.RestartRequiredChanges(&next, reloadable); !slices.Equal(got, tt.want) {
				t.Errorf("RestartRequiredChanges = %v, want %v", got, tt.want)
			}
		})
	}
}

// The global keys are the leaves of Config by their TOML names, tables dotted, each
// once, without the [[server]] blocks.
func TestGlobalConfigKeys(t *testing.T) {
	keys := GlobalConfigKeys()
	for _, want := range []string{
		"logging.output", "database.write.hosts", "database.read.password", "s3.secret_key",
		"tls.cert_file", "cluster.peers", "relay.smtp_host", "admin_cli.api_key",
		"timeout_scheduler.shard_count", "bcrypt_cost", "pool",
	} {
		if !slices.Contains(keys, want) {
			t.Errorf("GlobalConfigKeys lacks %q", want)
		}
	}
	for _, notKey := range []string{"server", "logging", "database", "database.write", "relay"} {
		if slices.Contains(keys, notKey) {
			t.Errorf("GlobalConfigKeys names %q as a setting", notKey)
		}
	}
	seen := make(map[string]bool, len(keys))
	for _, key := range keys {
		if seen[key] {
			t.Errorf("GlobalConfigKeys names %q twice", key)
		}
		seen[key] = true
	}
}
