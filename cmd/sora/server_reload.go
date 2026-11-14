package main

import (
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

// reloadableServerSettings are, by server type, the settings its ReloadConfig applies,
// as TOML keys dotted inside a table. A reload reports every other setting it finds
// changed as needing a restart, so each list must mirror the names its ReloadConfig
// appends to "reloaded"; TestReloadableServerSettingsMatchEachReloadConfig holds them
// together. A type with no entry has every change reported.
var reloadableServerSettings = map[string][]string{
	"imap": {
		"timeouts.command_timeout", "timeouts.absolute_session_timeout", "timeouts.min_bytes_per_minute",
		"limits.session_memory_limit",
		"master_sasl_username", "master_sasl_password", "master_sasl_allowed_networks",
	},
	"pop3": {
		"timeouts.command_timeout", "timeouts.absolute_session_timeout", "timeouts.min_bytes_per_minute",
		"limits.session_memory_limit",
		"master_sasl_username", "master_sasl_password", "master_sasl_allowed_networks",
	},
	"managesieve": {
		"timeouts.command_timeout", "timeouts.absolute_session_timeout", "timeouts.min_bytes_per_minute",
		"max_script_size",
		"master_sasl_username", "master_sasl_password", "master_sasl_allowed_networks",
	},
	"lmtp": {"max_message_size"},
	"imap_proxy": {
		"limits.max_auth_errors", "auth_idle_timeout",
		"timeouts.command_timeout", "timeouts.absolute_session_timeout", "timeouts.min_bytes_per_minute",
		"master_sasl_username", "master_sasl_password",
	},
	"pop3_proxy": {
		"limits.max_auth_errors", "auth_idle_timeout",
		"timeouts.command_timeout", "timeouts.absolute_session_timeout", "timeouts.min_bytes_per_minute",
		"master_sasl_username", "master_sasl_password", "debug",
	},
	"managesieve_proxy": {
		"limits.max_auth_errors", "auth_idle_timeout",
		"timeouts.command_timeout", "timeouts.absolute_session_timeout", "timeouts.min_bytes_per_minute",
		"master_sasl_username", "master_sasl_password", "debug",
	},
	"lmtp_proxy":     {"timeouts.absolute_session_timeout", "max_message_size"},
	"http_admin_api": {"api_key", "read_only_api_key", "allowed_hosts"},
	"http_user_api":  {"jwt_secret", "allowed_origins", "allowed_hosts"},
	"user_api_proxy": {"jwt_secret"},
}

// reloadServers hands each running server its [[server]] block from newCfg, the config
// a SIGHUP re-read, by name, and reports what the reload leaves for a restart: the
// settings a block changed that its server does not apply (all of them for a server
// that does not reload: metrics, or one start-up skipped, such as an Admin API without
// an api_key; a reload waits for the servers still starting), a block removed from the
// file or set to enabled = false, whose server keeps running, and a block added to it
// or enabled, which is not started. The config the servers started with, deps.config,
// is read and never written.
func (deps *serverDependencies) reloadServers(newCfg *config.Config) {
	newServers := newCfg.GetAllServers()
	newByName := make(map[string]config.ServerConfig, len(newServers))
	for _, s := range newServers {
		newByName[s.Name] = s
	}
	startedServers := deps.config.GetAllServers()
	startedByName := make(map[string]bool, len(startedServers))

	deps.runningServersMux.Lock()
	defer deps.runningServersMux.Unlock()
	for _, started := range startedServers {
		name := started.Name
		startedByName[name] = true
		newServerCfg, ok := newByName[name]
		if !ok {
			logger.Info("Config reload: server removed or set to enabled = false, but it keeps running until a restart", "server", name, "type", started.Type)
			continue
		}
		var reloadable []string
		if srv, running := deps.runningServers[name]; running {
			// Re-validate before applying: keeps the fail-closed startup guards
			// (e.g. master_username with an empty master_password) effective on
			// SIGHUP reload. Invalid new config is skipped; the server keeps
			// running on its previous, already-validated config.
			if err := newServerCfg.Validate(); err != nil {
				logger.Error("Skipping reload: invalid new server config", "server", name, "error", err)
				continue
			}
			if err := srv.ReloadConfig(newServerCfg); err != nil {
				logger.Error("Failed to reload server config", "server", name, "error", err)
			}
			reloadable = reloadableServerSettings[started.Type]
		}
		// Both configurations are enabled; omitted and explicit true are equivalent.
		started.Enabled, newServerCfg.Enabled = nil, nil
		if changed := started.RestartRequiredChanges(newServerCfg, reloadable); len(changed) > 0 {
			logger.Info("Config reload: server settings changed but require restart to take effect", "server", name, "fields", changed)
		}
	}
	for _, s := range newServers {
		if !startedByName[s.Name] {
			if err := s.Validate(); err != nil {
				logger.Error("Config reload: invalid server config; a restart will refuse to start with it", "server", s.Name, "type", s.Type, "error", err)
				continue
			}
			logger.Info("Config reload: server added or enabled but not running; it is not started until restart", "server", s.Name, "type", s.Type)
		}
	}
}
