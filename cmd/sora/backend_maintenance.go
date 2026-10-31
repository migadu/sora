package main

import (
	"context"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
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
// and then keeps it current every poll_interval until ctx is done. If that first load
// fails, the set stays unloaded and the proxies dial no backend until a poll succeeds:
// any backend might be in maintenance. The database was reachable moments before (sora
// does not start without it), so that is normally one poll.
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
		logger.Error("Backend maintenance: initial load failed - proxies refuse every backend connection until a poll succeeds", "error", err)
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

// uploadSessionSource is a server whose sessions can stage uploads: IMAP (authenticated
// sessions), LMTP and the Admin API's mail delivery.
type uploadSessionSource interface {
	UploadSessions() (open, started int64)
}

// startSessionsReport makes this node report its upload sessions under its uploader
// instance id, so that `sora-admin backends ... --wait` calls it safe to stop only once
// none is left: an empty upload queue proves nothing while an IMAP session that can still
// APPEND is open. Only a node with an uploader stages uploads, so only such a node reports.
func startSessionsReport(ctx context.Context, deps *serverDependencies) {
	if deps.uploadWorker == nil || deps.resilientDB == nil {
		return
	}
	go runSessionsReport(ctx, deps.instanceID, db.SessionsReportInterval, deps.uploadSessions, deps.resilientDB.ReportInstanceSessionsWithRetry)
}

// uploadSessions sums the upload sessions of every server running in this process.
func (deps *serverDependencies) uploadSessions() (open, started int64) {
	deps.runningServersMux.Lock()
	defer deps.runningServersMux.Unlock()
	for _, s := range deps.runningServers {
		if source, ok := s.(uploadSessionSource); ok {
			o, st := source.UploadSessions()
			open += o
			started += st
		}
	}
	return open, started
}

// runSessionsReport reports count() every interval until ctx is done, starting at once.
// The count starts with this process, which the report says (Since), so a restart is
// never mistaken for sessions ending.
func runSessionsReport(ctx context.Context, instanceID string, interval time.Duration, count func() (open, started int64), report func(context.Context, db.InstanceSessions) error) {
	since := time.Now()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	failing := false
	for {
		open, started := count()
		reportCtx, cancel := context.WithTimeout(ctx, interval)
		err := report(reportCtx, db.InstanceSessions{InstanceID: instanceID, Open: open, Started: started, Since: since})
		cancel()
		switch {
		case err != nil && ctx.Err() == nil && !failing:
			logger.Warn("Cannot report upload sessions - backend maintenance cannot confirm this node is safe to stop until it can", "instance_id", instanceID, "error", err)
			failing = true
		case err == nil && failing:
			logger.Info("Reporting upload sessions again", "instance_id", instanceID)
			failing = false
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
