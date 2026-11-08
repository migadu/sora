package main

import (
	"context"
	"net"
	"slices"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
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
	return runBackendMaintenance(ctx, deps.config.Maintenance, deps.resilientDB.ListBackendMaintenanceWithRetry)
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
func runBackendMaintenance(ctx context.Context, cfg config.MaintenanceConfig, load func(context.Context) ([]db.BackendMaintenance, error)) *proxy.Maintenance {
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
// maintenance; proxies whose sessions end on their own pass nil (the backend's own report
// keeps --wait waiting for them).
func (deps *serverDependencies) attachBackendMaintenance(ctx context.Context, proxyName string, cm *proxy.ConnectionManager, sessions func() []proxy.DrainTarget) {
	if deps.maintenance == nil || cm == nil {
		return
	}
	cm.SetMaintenance(deps.maintenance)
	if sessions != nil {
		proxy.StartSessionDrainer(ctx, deps.maintenance, deps.config.Maintenance.GetKickRate(), sessions, cm.InMaintenance, proxyName)
	}
}

// drainSessionSource is a server whose sessions the node must let finish before it stops:
// IMAP and POP3 sessions that logged in, LMTP transactions and the Admin API's mail deliveries.
// They can stage uploads, or (POP3) apply their deletions only at QUIT. Each admits them
// through the node's maintenance gate.
type drainSessionSource interface {
	DrainSessions() int64
}

// startSessionsReport makes this node report those sessions under its uploader instance
// id, and refuse new ones while it is in maintenance, so that `sora-admin backends ...
// --wait` calls it safe to stop only once none is left and none can start: an empty upload
// queue proves nothing while an IMAP session that can still APPEND is open. Only a node
// with an uploader is a backend, so only such a node reports.
//
// It sets deps.maintenanceGate, which the servers admit their sessions through, and looks
// up the node's maintenance once before returning: the servers start after it, so a node
// restarted in maintenance lets nothing in.
func startSessionsReport(ctx context.Context, deps *serverDependencies) {
	if deps.uploadWorker == nil || deps.resilientDB == nil {
		return
	}
	refuseAfter, err := deps.config.Maintenance.GetRefuseAfter()
	if err != nil {
		logger.Warn("Invalid [backend_maintenance] refuse_after - using 30s", "error", err)
		refuseAfter = 30 * time.Second
	}

	r := newSessionsReporter(deps.instanceID, func(ctx context.Context) (*time.Time, error) {
		return deps.resilientDB.GetMaintenanceRefusalWithRetry(ctx, deps.instanceID, refuseAfter)
	}, deps.drainSessions, deps.resilientDB.ReportInstanceSessionsWithRetry)
	deps.maintenanceGate = r.gate
	r.tick(ctx, db.SessionsReportInterval)
	go r.run(ctx, db.SessionsReportInterval)
}

// drainSessions sums the drain sessions of every server running in this process.
func (deps *serverDependencies) drainSessions() int64 {
	deps.runningServersMux.Lock()
	defer deps.runningServersMux.Unlock()
	var open int64
	for _, s := range deps.runningServers {
		if source, ok := s.(drainSessionSource); ok {
			open += source.DrainSessions()
		}
	}
	return open
}

// sessionsReporter keeps the node's maintenance gate and its sessions report current.
//
// Each tick looks up whether the node is in maintenance (past refuse_after), sets the gate
// from it, and only then counts the open sessions and reports them, naming the maintenance
// it refuses for: a report of refusing and none open then stays true (see
// server.MaintenanceGate). A process starts out refusing, since a session it let in before
// its first look would not be in the report of the process before it, which may still read
// as current. A failed look keeps what the node last knew, gate and report alike.
//
// Each report also carries the node's own addresses, read afresh every time (one can move
// to another node), for proxies to match it by while it is in maintenance: the name it is
// in maintenance by need not resolve, where they run, to the address they route to it by.
type sessionsReporter struct {
	instanceID string
	gate       *server.MaintenanceGate
	refusal    func(context.Context) (*time.Time, error) // the maintenance to refuse for, nil for none
	count      func() int64
	report     func(context.Context, db.InstanceSessions) error
	addresses  func() ([]string, error) // the node's own addresses (nodeAddresses)

	refusingSince    *time.Time // the maintenance the gate refuses for, as last looked up
	known            bool       // a look has succeeded
	addrs            []string   // the node's addresses, as last read
	lookupFailing    bool
	reportFailing    bool
	addressesFailing bool
}

// newSessionsReporter returns a reporter whose gate refuses new sessions until its first
// look says otherwise.
func newSessionsReporter(instanceID string, refusal func(context.Context) (*time.Time, error), count func() int64, report func(context.Context, db.InstanceSessions) error) *sessionsReporter {
	return &sessionsReporter{
		instanceID: instanceID,
		gate:       server.NewMaintenanceGate(true),
		refusal:    refusal,
		count:      count,
		report:     report,
		addresses:  nodeAddresses,
	}
}

// run ticks every interval until ctx is done.
func (r *sessionsReporter) run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		r.tick(ctx, interval)
	}
}

// tick looks, sets the gate, counts and reports, each step bounded by timeout.
func (r *sessionsReporter) tick(ctx context.Context, timeout time.Duration) {
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	since, err := r.refusal(lookupCtx)
	cancel()
	switch {
	case err != nil:
		if ctx.Err() == nil && !r.lookupFailing {
			logger.Warn("Backend maintenance: cannot look up this node's maintenance - keeping its current state", "instance_id", r.instanceID, "refusing_new_sessions", r.gate.Refusing(), "error", err)
		}
		r.lookupFailing = true
	default:
		if r.lookupFailing {
			logger.Info("Backend maintenance: looking up this node's maintenance again", "instance_id", r.instanceID)
		}
		r.lookupFailing = false
		r.refusingSince = since
		r.setRefusing(since != nil)
		r.known = true
	}
	if r.gate.Refusing() {
		metrics.BackendMaintenanceRefusing.Set(1)
	} else {
		metrics.BackendMaintenanceRefusing.Set(0)
	}

	r.readAddresses()

	open := r.count()
	reportCtx, cancel := context.WithTimeout(ctx, timeout)
	err = r.report(reportCtx, db.InstanceSessions{InstanceID: r.instanceID, Open: open, RefusingSince: r.refusingSince, Addresses: r.addrs})
	cancel()
	switch {
	case err != nil && ctx.Err() == nil && !r.reportFailing:
		logger.Warn("Cannot report sessions - backend maintenance cannot confirm this node is safe to stop until it can", "instance_id", r.instanceID, "error", err)
		r.reportFailing = true
	case err == nil && r.reportFailing:
		logger.Info("Reporting sessions again", "instance_id", r.instanceID)
		r.reportFailing = false
	}
}

// readAddresses reads the node's addresses for the report. Interfaces that cannot be read
// keep the addresses last read: reporting none would let proxies route to the node by an
// address they then no longer match.
func (r *sessionsReporter) readAddresses() {
	addrs, err := r.addresses()
	switch {
	case err != nil && !r.addressesFailing:
		logger.Warn("Cannot read this node's addresses - reporting those last read", "instance_id", r.instanceID, "addresses", r.addrs, "error", err)
		r.addressesFailing = true
	case err == nil:
		if r.addressesFailing {
			logger.Info("Reading this node's addresses again", "instance_id", r.instanceID)
		}
		r.addressesFailing = false
		r.addrs = addrs
	}
}

// setRefusing sets the gate and says so when that changes anything, except for the
// startup default giving way to accepting (the normal start).
func (r *sessionsReporter) setRefusing(refusing bool) {
	if !r.gate.SetRefusing(refusing) {
		return
	}
	switch {
	case refusing:
		logger.Warn("Backend maintenance: this node is in maintenance - refusing new sessions (IMAP and POP3 logins, LMTP transactions, Admin API deliveries)", "instance_id", r.instanceID, "maintenance_since", r.refusingSince)
	case r.known:
		logger.Info("Backend maintenance: this node is out of maintenance - accepting new sessions", "instance_id", r.instanceID)
	}
}

// nodeAddresses returns the addresses proxies elsewhere can reach this node by, read from
// its interfaces.
func nodeAddresses() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	return reachableAddresses(addrs), nil
}

// reachableAddresses returns, sorted and each once, the addresses in addrs that a proxy on
// another node could reach this one by: not loopback, link-local, multicast or unspecified
// addresses, which every node has alike.
func reachableAddresses(addrs []net.Addr) []string {
	var reachable []string
	for _, a := range addrs {
		var ip net.IP
		switch a := a.(type) {
		case *net.IPNet:
			ip = a.IP
		case *net.IPAddr:
			ip = a.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			continue
		}
		reachable = append(reachable, ip.String())
	}
	slices.Sort(reachable)
	return slices.Compact(reachable)
}
