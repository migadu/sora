package proxy

import (
	"context"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

// Maintenance is the set of backend hosts an operator has put in maintenance
// (`sora-admin backends maintenance on`). A proxy gives such a backend no new traffic:
// routing never picks it, an affinity or remote-lookup route to it gives way to normal
// routing, and sessions already on it are closed gradually (see StartSessionDrainer).
// The backend itself keeps running, so the uploads only it can finish (its spool is
// node-local) drain while nothing new arrives. Unlike health, maintenance never recovers
// on its own: it ends when the operator turns it off.
//
// Entries are hosts, not host:port, so one entry covers every protocol pool the host
// serves. Names and addresses match both ways: MaintenancePoller adds each hostname's
// addresses to the set, so a pool resolved to IPs matches an entry made by name, and
// Contains resolves a name it is asked about, so a route by name (a remote-lookup route,
// an alias) matches an entry made by IP. The poller also adds the addresses each host's
// node reports for itself, which match it whatever its name resolves to here.
//
// Until the list is read once (the first Set) the set is not loaded: which backends are
// in maintenance is unknown, Contains reports none, and the connection manager refuses
// to dial any backend (Loaded).
//
// One Maintenance is shared by every proxy server of a process; a nil *Maintenance
// contains nothing.
type Maintenance struct {
	hosts atomic.Pointer[map[string]struct{}] // nil until the first Set

	// names caches the addresses of the hostnames Contains was asked about, refreshed by
	// the poller while anything is in maintenance.
	namesMu    sync.Mutex
	names      map[string][]string
	lookupHost func(ctx context.Context, host string) ([]string, error)

	listenersMu     sync.Mutex
	listeners       []func() // after every Set that leaves the set non-empty (OnUpdate)
	changeListeners []func() // after every Set that changes the set (OnChange)
}

// NewMaintenance returns a maintenance set that is not loaded yet.
func NewMaintenance() *Maintenance {
	return &Maintenance{
		names:      map[string][]string{},
		lookupHost: net.DefaultResolver.LookupHost,
	}
}

// Empty reports whether nothing is in maintenance (or the set was never read).
func (m *Maintenance) Empty() bool {
	if m == nil {
		return true
	}
	set := m.hosts.Load()
	return set == nil || len(*set) == 0
}

// Loaded reports whether the set has been read at least once. Until then no backend may
// be dialed: a proxy that does not know which backends are drained must not send traffic
// to one that is. A nil *Maintenance (maintenance not honored) counts as loaded.
func (m *Maintenance) Loaded() bool {
	return m == nil || m.hosts.Load() != nil
}

// Set replaces the hosts in maintenance and returns the ones that were not in it before.
// While the set is non-empty, every listener runs after each Set — not only when a host
// enters — so a session that reached a backend just before it entered maintenance is
// still found by the next sweep.
func (m *Maintenance) Set(hosts []string) (entered []string) {
	next := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		if h = normalizeMaintenanceHost(h); h != "" {
			next[h] = struct{}{}
		}
	}
	var prev map[string]struct{}
	if p := m.hosts.Swap(&next); p != nil {
		prev = *p
	}
	for h := range next {
		if _, ok := prev[h]; !ok {
			entered = append(entered, h)
		}
	}
	slices.Sort(entered)
	changed := len(entered) > 0 || len(prev) > len(next)-len(entered)

	if len(next) == 0 {
		// Nothing in maintenance: forget the names asked about, so the cache cannot grow
		// across maintenance windows and the next one resolves afresh.
		m.namesMu.Lock()
		clear(m.names)
		m.namesMu.Unlock()
	}

	m.listenersMu.Lock()
	var listeners []func()
	if len(next) > 0 {
		listeners = slices.Clone(m.listeners)
	}
	if changed {
		listeners = append(listeners, m.changeListeners...)
	}
	m.listenersMu.Unlock()
	for _, fn := range listeners {
		fn()
	}
	return entered
}

// Contains reports whether addr — a host or host:port — is a backend in maintenance. A
// hostname is in maintenance if it is listed or any address it resolves to is. Resolving
// costs a lookup the first time a name is asked about, and only while something is in
// maintenance.
func (m *Maintenance) Contains(addr string) bool {
	if m == nil || addr == "" {
		return false
	}
	set := m.hosts.Load()
	if set == nil || len(*set) == 0 {
		return false
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = normalizeMaintenanceHost(host)
	if _, ok := (*set)[host]; ok {
		return true
	}
	if net.ParseIP(host) != nil {
		return false
	}
	for _, ip := range m.addressesOf(host) {
		if _, ok := (*set)[ip]; ok {
			return true
		}
	}
	return false
}

// maxMaintenanceNames bounds the name cache. Names come from the pools and from remote
// lookup, so a few per backend; past the bound a name is resolved on every call instead.
const maxMaintenanceNames = 4096

// addressesOf returns what a hostname resolves to, normalized: from the cache, or looked
// up and cached. A failed lookup is cached as nothing, and retried by the poller.
func (m *Maintenance) addressesOf(name string) []string {
	m.namesMu.Lock()
	addrs, ok := m.names[name]
	m.namesMu.Unlock()
	if ok {
		return addrs
	}

	ctx, cancel := context.WithTimeout(context.Background(), maintenanceLookupTimeout)
	addrs, _ = m.resolve(ctx, name)
	cancel()

	m.namesMu.Lock()
	if _, ok := m.names[name]; !ok && len(m.names) < maxMaintenanceNames {
		m.names[name] = addrs
	}
	m.namesMu.Unlock()
	return addrs
}

// resolve looks name up and returns its addresses normalized.
func (m *Maintenance) resolve(ctx context.Context, name string) ([]string, error) {
	addrs, err := m.lookupHost(ctx, name)
	if err != nil {
		return nil, err
	}
	for i, a := range addrs {
		addrs[i] = normalizeMaintenanceHost(a)
	}
	return addrs, nil
}

// refreshNames re-resolves every cached hostname, keeping the last addresses of one that
// fails to resolve.
func (m *Maintenance) refreshNames(ctx context.Context) {
	m.namesMu.Lock()
	names := make([]string, 0, len(m.names))
	for name := range m.names {
		names = append(names, name)
	}
	m.namesMu.Unlock()

	for _, name := range names {
		lookupCtx, cancel := context.WithTimeout(ctx, maintenanceLookupTimeout)
		addrs, err := m.resolve(lookupCtx, name)
		cancel()
		if err != nil || len(addrs) == 0 {
			continue
		}
		m.namesMu.Lock()
		m.names[name] = addrs
		m.namesMu.Unlock()
	}
}

// Hosts returns the hosts in maintenance, sorted.
func (m *Maintenance) Hosts() []string {
	if m == nil {
		return nil
	}
	set := m.hosts.Load()
	if set == nil {
		return nil
	}
	hosts := make([]string, 0, len(*set))
	for h := range *set {
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)
	return hosts
}

// OnUpdate registers fn to run after every Set that leaves the set non-empty. fn must not
// block: it runs on the poller's goroutine.
func (m *Maintenance) OnUpdate(fn func()) {
	m.listenersMu.Lock()
	defer m.listenersMu.Unlock()
	m.listeners = append(m.listeners, fn)
}

// OnChange registers fn to run after every Set that changes which hosts are in
// maintenance (one entering or leaving it). fn must not block: it runs on the poller's
// goroutine.
func (m *Maintenance) OnChange(fn func()) {
	m.listenersMu.Lock()
	defer m.listenersMu.Unlock()
	m.changeListeners = append(m.changeListeners, fn)
}

// NormalizeMaintenanceHost is the form a host is stored and matched in: lower case, no
// trailing dot, no IPv6 brackets, IP addresses in canonical form.
func NormalizeMaintenanceHost(host string) string {
	return normalizeMaintenanceHost(host)
}

func normalizeMaintenanceHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

// MaintenancePoller keeps a Maintenance in step with the operator's list (the
// backend_maintenance table).
type MaintenancePoller struct {
	m    *Maintenance
	load func(ctx context.Context) ([]db.BackendMaintenance, error)

	// resolved is each hostname's last successful resolution, kept through DNS failures.
	resolved map[string][]string
	// unresolved holds the hostnames whose last resolution failed, so each failure is
	// logged once, not at every poll.
	unresolved map[string]bool
	failing    bool
}

// NewMaintenancePoller returns a poller that installs the hosts load returns into m
// (db.ListBackendMaintenance).
func NewMaintenancePoller(m *Maintenance, load func(ctx context.Context) ([]db.BackendMaintenance, error)) *MaintenancePoller {
	return &MaintenancePoller{
		m:        m,
		load:     load,
		resolved: map[string][]string{},
	}
}

// maintenanceLookupTimeout bounds the resolution of one hostname in maintenance.
const maintenanceLookupTimeout = 2 * time.Second

// Refresh loads the list once and installs it, together with the addresses each hostname
// resolves to and those its node reports for itself. A load failure leaves the set as it
// was (not loaded, if it never was): maintenance must never end because the database was
// briefly unreachable, or a drained backend would silently return to rotation. A hostname
// that fails to resolve keeps the addresses it last resolved to. While anything is in
// maintenance, the hostnames routes were checked by are re-resolved too, before the new
// list is installed.
//
// The node's addresses are what match a host whose name leads nowhere the proxies route
// to: a name that does not resolve here, or resolves to another of the node's addresses
// (a public one, where the pools list private ones).
func (p *MaintenancePoller) Refresh(ctx context.Context) error {
	rows, err := p.load(ctx)
	if err != nil {
		metrics.BackendMaintenancePollFailures.Inc()
		return err
	}
	if len(rows) > 0 {
		p.m.refreshNames(ctx)
	}

	hosts := make([]string, 0, len(rows))
	all := make([]string, 0, len(rows))
	resolved := make(map[string][]string, len(rows))
	unresolved := make(map[string]bool)
	for _, r := range rows {
		h := normalizeMaintenanceHost(r.Host)
		if h == "" {
			continue
		}
		hosts = append(hosts, h)
		all = append(all, h)
		all = append(all, r.Addresses...)
		if net.ParseIP(h) != nil {
			continue
		}
		lookupCtx, cancel := context.WithTimeout(ctx, maintenanceLookupTimeout)
		addrs, err := p.m.resolve(lookupCtx, h)
		cancel()
		if err != nil || len(addrs) == 0 {
			addrs = p.resolved[h]
			unresolved[h] = true
			if !p.unresolved[h] {
				logger.Warn("Backend maintenance: hostname did not resolve - keeping last known addresses", "host", h, "addresses", addrs, "node_addresses", r.Addresses, "error", err)
			}
		} else if p.unresolved[h] {
			logger.Info("Backend maintenance: hostname resolves again", "host", h, "addresses", addrs)
		}
		resolved[h] = addrs
		all = append(all, addrs...)
	}
	p.resolved = resolved
	p.unresolved = unresolved

	metrics.BackendMaintenanceHosts.Set(float64(len(hosts)))
	if entered := p.m.Set(all); len(entered) > 0 {
		logger.Info("Backend maintenance: hosts entered maintenance", "entered", entered, "in_maintenance", hosts)
	}
	return nil
}

// Run calls Refresh every interval until ctx is done. Each refresh is bounded, so a stuck
// query cannot hold the poller far past its tick (the database's own query timeout is
// much longer).
func (p *MaintenancePoller) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	timeout := max(interval, 5*time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		refreshCtx, cancel := context.WithTimeout(ctx, timeout)
		err := p.Refresh(refreshCtx)
		cancel()
		if err != nil {
			if !p.failing && ctx.Err() == nil {
				logger.Warn("Backend maintenance: cannot load the maintenance list - keeping the current one", "in_maintenance", p.m.Hosts(), "loaded", p.m.Loaded(), "error", err)
			}
			p.failing = true
			continue
		}
		if p.failing {
			logger.Info("Backend maintenance: maintenance list loading again")
		}
		p.failing = false
	}
}

// DrainTarget is one proxied session as the maintenance drain sees it.
type DrainTarget struct {
	Backend string // backend address the session is connected to; "" before routing
	Close   func() // ends the session; must tolerate being called on a closing session
}

// StartSessionDrainer closes, at most rate per second, the sessions whose backend is in
// maintenance, so their clients reconnect and are routed elsewhere. Pacing spreads the
// reconnects over the remaining backends instead of landing them all at once. Each close
// re-checks maintenance first, so turning it off stops a drain in progress. inMaintenance
// decides whether a session's backend is in maintenance: the proxy server's
// ConnectionManager.InMaintenance, which also knows the names its pool was resolved from
// (nil means m.Contains). Runs until ctx is done.
func StartSessionDrainer(ctx context.Context, m *Maintenance, rate float64, sessions func() []DrainTarget, inMaintenance func(addr string) bool, proxyName string) {
	if inMaintenance == nil {
		inMaintenance = m.Contains
	}
	if !(rate > 0) || math.IsInf(rate, 0) {
		rate = DefaultMaintenanceKickRate
	}
	interval := time.Duration(float64(time.Second) / rate)

	trigger := make(chan struct{}, 1)
	m.OnUpdate(func() {
		select {
		case trigger <- struct{}{}:
		default: // a sweep is already pending; it will see this update too
		}
	})

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-trigger:
			}
			closed := 0
			for _, t := range sessions() {
				if !inMaintenance(t.Backend) {
					continue
				}
				if closed > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(interval):
					}
					if !inMaintenance(t.Backend) {
						continue
					}
				}
				t.Close()
				closed++
				metrics.BackendMaintenanceSessionsClosed.WithLabelValues(proxyName).Inc()
			}
			if closed > 0 {
				logger.Info("Backend maintenance: closed sessions on backends in maintenance", "proxy", proxyName, "closed", closed, "in_maintenance", m.Hosts())
			}
		}
	}()
}

// DefaultMaintenanceKickRate is how many sessions per second a proxy server closes on a
// backend in maintenance when [backend_maintenance] kick_rate is not set.
const DefaultMaintenanceKickRate = 10
