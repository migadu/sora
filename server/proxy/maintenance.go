package proxy

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/logger"
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
// serves. MaintenancePoller adds each hostname's addresses, so a pool that was resolved
// to IPs still matches an entry made by name.
//
// One Maintenance is shared by every proxy server of a process; a nil *Maintenance
// contains nothing.
type Maintenance struct {
	hosts atomic.Pointer[map[string]struct{}]

	listenersMu sync.Mutex
	listeners   []func()
}

// NewMaintenance returns an empty maintenance set.
func NewMaintenance() *Maintenance {
	m := &Maintenance{}
	empty := map[string]struct{}{}
	m.hosts.Store(&empty)
	return m
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
	prev := *m.hosts.Swap(&next)
	for h := range next {
		if _, ok := prev[h]; !ok {
			entered = append(entered, h)
		}
	}
	slices.Sort(entered)

	if len(next) == 0 {
		return entered
	}
	m.listenersMu.Lock()
	listeners := slices.Clone(m.listeners)
	m.listenersMu.Unlock()
	for _, fn := range listeners {
		fn()
	}
	return entered
}

// Contains reports whether addr — a host or host:port — is a backend in maintenance.
func (m *Maintenance) Contains(addr string) bool {
	if m == nil || addr == "" {
		return false
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	_, ok := (*m.hosts.Load())[normalizeMaintenanceHost(host)]
	return ok
}

// Hosts returns the hosts in maintenance, sorted.
func (m *Maintenance) Hosts() []string {
	if m == nil {
		return nil
	}
	hosts := make([]string, 0, len(*m.hosts.Load()))
	for h := range *m.hosts.Load() {
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
	m          *Maintenance
	load       func(ctx context.Context) ([]string, error)
	lookupHost func(ctx context.Context, host string) ([]string, error)

	// resolved is each hostname's last successful resolution, kept through DNS failures.
	resolved map[string][]string
	failing  bool
}

// NewMaintenancePoller returns a poller that installs the hosts load returns into m.
func NewMaintenancePoller(m *Maintenance, load func(ctx context.Context) ([]string, error)) *MaintenancePoller {
	return &MaintenancePoller{
		m:          m,
		load:       load,
		lookupHost: net.DefaultResolver.LookupHost,
		resolved:   map[string][]string{},
	}
}

// maintenanceLookupTimeout bounds the resolution of one hostname in maintenance.
const maintenanceLookupTimeout = 2 * time.Second

// Refresh loads the list once and installs it, together with the addresses each hostname
// resolves to. A load failure leaves the set as it was: maintenance must never end because
// the database was briefly unreachable, or a drained backend would silently return to
// rotation. A hostname that fails to resolve keeps the addresses it last resolved to.
func (p *MaintenancePoller) Refresh(ctx context.Context) error {
	hosts, err := p.load(ctx)
	if err != nil {
		return err
	}

	all := make([]string, 0, len(hosts))
	resolved := make(map[string][]string, len(hosts))
	for _, h := range hosts {
		h = normalizeMaintenanceHost(h)
		if h == "" {
			continue
		}
		all = append(all, h)
		if net.ParseIP(h) != nil {
			continue
		}
		lookupCtx, cancel := context.WithTimeout(ctx, maintenanceLookupTimeout)
		addrs, err := p.lookupHost(lookupCtx, h)
		cancel()
		if err != nil || len(addrs) == 0 {
			addrs = p.resolved[h]
			logger.Warn("Backend maintenance: hostname did not resolve - keeping last known addresses", "host", h, "addresses", addrs, "error", err)
		}
		resolved[h] = addrs
		all = append(all, addrs...)
	}
	p.resolved = resolved

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
				logger.Warn("Backend maintenance: cannot load the maintenance list - keeping the current one", "in_maintenance", p.m.Hosts(), "error", err)
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
// re-checks maintenance first, so turning it off stops a drain in progress. Runs until ctx
// is done.
func StartSessionDrainer(ctx context.Context, m *Maintenance, rate float64, sessions func() []DrainTarget, proxyName string) {
	if rate <= 0 {
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
				if !m.Contains(t.Backend) {
					continue
				}
				if closed > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(interval):
					}
					if !m.Contains(t.Backend) {
						continue
					}
				}
				t.Close()
				closed++
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
