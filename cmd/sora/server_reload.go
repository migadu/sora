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
	"http_admin_api": {"api_key", "allowed_hosts"},
	"http_user_api":  {"jwt_secret", "allowed_origins", "allowed_hosts"},
	"user_api_proxy": {"jwt_secret"},
}

// reloadServers hands each running server its [[server]] block from newCfg, the config
// a SIGHUP re-read, by name, and reports the settings that block changed but the
// server's ReloadConfig does not apply, as the global report does for [cleanup] and the
// like. A server not in newCfg is left as it is. The config each server started with,
// deps.config, is read and never written.
func (deps *serverDependencies) reloadServers(newCfg *config.Config) {
	deps.runningServersMux.Lock()
	serverCount := len(deps.runningServers)
	deps.runningServersMux.Unlock()

	if serverCount == 0 {
		return
	}

	newServers := newCfg.GetAllServers()
	serversByName := make(map[string]config.ServerConfig, len(newServers))
	for _, s := range newServers {
		serversByName[s.Name] = s
	}
	startedServers := deps.config.GetAllServers()
	startedByName := make(map[string]config.ServerConfig, len(startedServers))
	for _, s := range startedServers {
		startedByName[s.Name] = s
	}

	deps.runningServersMux.Lock()
	defer deps.runningServersMux.Unlock()
	for name, srv := range deps.runningServers {
		newServerCfg, ok := serversByName[name]
		if !ok {
			continue
		}
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
		if started, ok := startedByName[name]; ok {
			changed := started.RestartRequiredChanges(newServerCfg, reloadableServerSettings[started.Type])
			if len(changed) > 0 {
				logger.Info("Config reload: server settings changed but require restart to take effect", "server", name, "fields", changed)
			}
		}
	}
}
