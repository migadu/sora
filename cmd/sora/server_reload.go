package main

import (
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

// reloadServers hands each running server its [[server]] block from newCfg, the config
// a SIGHUP re-read, by name. A server not in newCfg is left as it is.
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
	}
}
