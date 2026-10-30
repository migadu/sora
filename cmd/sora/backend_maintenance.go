package main

import (
	"context"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/server/proxy"
)

// backendMaintenanceInitialLoadTimeout bounds the load at startup, which runs before any
// proxy server accepts a connection.
const backendMaintenanceInitialLoadTimeout = 10 * time.Second

// startBackendMaintenance creates the set of backends in maintenance that every proxy
// server of this process honors, from the backend_maintenance table. Returns nil when no
// proxy server is configured, or when there is no database to read the list from.
func startBackendMaintenance(ctx context.Context, deps *serverDependencies) *proxy.Maintenance {
	if !hasProxyServer(deps.config.GetAllServers()) {
		return nil
	}
	if deps.resilientDB == nil {
		logger.Warn("Backend maintenance is not honored on this node: proxies read the maintenance list from the database, and none is configured")
		return nil
	}
	return runBackendMaintenance(ctx, deps.config.Maintenance, func(ctx context.Context) ([]string, error) {
		rows, err := deps.resilientDB.ListBackendMaintenanceWithRetry(ctx)
		if err != nil {
			return nil, err
		}
		hosts := make([]string, len(rows))
		for i, r := range rows {
			hosts[i] = r.Host
		}
		return hosts, nil
	})
}

func hasProxyServer(servers []config.ServerConfig) bool {
	for _, s := range servers {
		switch s.Type {
		case "imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy", "user_api_proxy":
			return true
		}
	}
	return false
}

// runBackendMaintenance loads the maintenance list once, before returning — a restarted
// proxy must not route to a backend in maintenance while it waits for its first poll —
// and then keeps it current every poll_interval until ctx is done.
func runBackendMaintenance(ctx context.Context, cfg config.MaintenanceConfig, load func(context.Context) ([]string, error)) *proxy.Maintenance {
	interval, err := cfg.GetPollInterval()
	if err != nil {
		logger.Warn("Invalid [backend_maintenance] poll_interval - using 5s", "error", err)
		interval = 5 * time.Second
	}

	m := proxy.NewMaintenance()
	poller := proxy.NewMaintenancePoller(m, load)

	loadCtx, cancel := context.WithTimeout(ctx, backendMaintenanceInitialLoadTimeout)
	err = poller.Refresh(loadCtx)
	cancel()
	if err != nil {
		logger.Error("Backend maintenance: initial load failed - proxies route to every backend until a poll succeeds", "error", err)
	} else if hosts := m.Hosts(); len(hosts) > 0 {
		logger.Info("Backend maintenance: honoring backends in maintenance", "hosts", hosts)
	}

	go poller.Run(ctx, interval)
	return m
}

// attachBackendMaintenance makes a proxy server honor backend maintenance. sessions, when
// non-nil, lists the server's sessions for the drain that closes those on a backend in
// maintenance; proxies whose sessions cannot add uploads, or end quickly, pass nil.
func (deps *serverDependencies) attachBackendMaintenance(ctx context.Context, proxyName string, cm *proxy.ConnectionManager, sessions func() []proxy.DrainTarget) {
	if deps.maintenance == nil || cm == nil {
		return
	}
	cm.SetMaintenance(deps.maintenance)
	if sessions != nil {
		proxy.StartSessionDrainer(ctx, deps.maintenance, deps.config.Maintenance.GetKickRate(), sessions, proxyName)
	}
}
