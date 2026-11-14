package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
)

// AffinityManager defines the interface for cluster-wide affinity management
type AffinityManager interface {
	GetBackend(username, protocol string) (string, bool)
	GetBackendAcrossProtocols(username, protocol string) (backend string, foundProtocol string, found bool)
	SetBackend(username, backend, protocol string)
	UpdateBackend(username, oldBackend, newBackend, protocol string)
	DeleteBackend(username, protocol string)
}

// BackendHealth tracks detailed health information for a backend
type BackendHealth struct {
	FailureCount     int       // Total failure count
	ConsecutiveFails int       // Consecutive failures (resets on success)
	LastFailure      time.Time // Time of last failure
	LastSuccess      time.Time // Time of last successful connection
	IsHealthy        bool      // Current health status
}

// backendPool is one group of backends the manager can route into, with its own hash
// ring and round-robin cursor. Health is not kept here: it is per address in the
// manager's union, so a backend keeps its failure history however it was reached.
type backendPool struct {
	name      string
	named     bool // false for the unnamed pool a flat remote_addrs list becomes
	isDefault bool
	settings  BackendSettings
	// rootCAs verifies the pool's backends (its TLSCAFile); nil = the system roots. Never
	// the proxy server's own remote_tls_ca_file: a pool inherits nothing.
	rootCAs *x509.CertPool
	// configured is the normalized host:port list from config. resolved and ring are
	// what the last DNS resolution made of it: rebuilt by install under cm.healthMu and
	// read under it.
	configured []string
	resolved   []string
	ring       *ConsistentHash
	// nextIndex is the round-robin cursor for this pool.
	nextIndex atomic.Uint32
}

// install rebuilds the pool's members and hash ring from a resolution result (nil = the
// configured addresses themselves, before the first resolution).
func (p *backendPool) install(resolvedHosts map[string][]string) {
	resolved := make([]string, 0, len(p.configured))
	seen := make(map[string]bool, len(p.configured))
	for _, addr := range p.configured {
		entries := resolvedHosts[addr]
		if len(entries) == 0 {
			entries = []string{addr}
		}
		for _, entry := range entries {
			if seen[entry] {
				continue
			}
			seen[entry] = true
			resolved = append(resolved, entry)
		}
	}
	ring := NewConsistentHash(150) // 150 virtual nodes per backend
	for _, addr := range resolved {
		ring.AddBackend(addr)
	}
	p.resolved = resolved
	p.ring = ring
}

// stamp writes the pool's name and backend-leg settings onto a route's info, so the dial
// (dialWithProxy) and the session (ID/XCLIENT/UTF8 forwarding, STARTTLS) read one
// consistent set. Only a named pool stamps: the unnamed pool of a flat list leaves the
// proxy server's own settings in force, as before pools existed.
func (p *backendPool) stamp(info *UserRoutingInfo) {
	if !p.named {
		return
	}
	info.PoolName = p.name
	info.RemoteTLS = p.settings.TLS
	info.RemoteTLSUseStartTLS = p.settings.TLSUseStartTLS
	info.RemoteTLSVerify = p.settings.TLSVerify
	info.RemoteUseProxyProtocol = p.settings.UseProxyProtocol
	info.RemoteUseIDCommand = p.settings.UseIDCommand
	info.RemoteUseXCLIENT = p.settings.UseXCLIENT
	info.RemoteUseUTF8 = p.settings.UseUTF8
}

// ConnectionManager manages connections to multiple remote servers with round-robin and failover
type ConnectionManager struct {
	serverName  string // Server name for logging
	remoteAddrs []string
	// configuredAddrs is the original normalized pool from config (remote_addrs),
	// captured before ResolveAddresses() rewrites remoteAddrs to resolved IPs. Used by
	// AllowRemoteLookupBackend so restrict_to_pool matches hostnames as configured.
	configuredAddrs        []string
	remotePort             int // Default port for backends if not in address
	remoteTLS              bool
	remoteTLSUseStartTLS   bool // Use STARTTLS for backend connections (only relevant if remoteTLS is true)
	remoteTLSVerify        bool
	remoteTLSRootCAs       *x509.CertPool // When non-nil, replaces the system roots for backend certificate verification (private-CA / self-signed backends)
	remoteUseProxyProtocol bool
	connectTimeout         time.Duration

	// pools are the backend groups this manager routes into, each with its own hash ring
	// and round-robin cursor. A manager built from a flat remote_addrs list has exactly
	// one, unnamed, default pool, so every routing decision is pool-scoped whichever way
	// it was built. The slice, the index and defaultPool are fixed at construction; a
	// pool's resolved members and ring are rebuilt under healthMu.
	pools       []*backendPool
	poolsByName map[string]*backendPool
	defaultPool *backendPool // nil when named pools are configured without a default

	// Backend health tracking
	healthMu                 sync.RWMutex
	backendHealth            map[string]*BackendHealth // Pool backends (from remote_addrs config)
	remoteLookupHealth       map[string]*BackendHealth // Dynamic backends from remote_lookup (not in pool)
	enableBackendHealthCheck bool                      // If true, backend health checks are enabled (default: true)
	// resolvedHosts is, per configured address, the pool entries its last successful
	// resolution produced, so a failed re-resolution can keep them. Guarded by healthMu.
	resolvedHosts        map[string][]string
	resolutionGeneration uint64 // guarded by healthMu
	// DNS may alias distinct configured names into the same host:port. Affected
	// named pools and all their addresses are refused until the overlap clears.
	// Both maps are rebuilt with resolvedHosts under healthMu.
	poolErrors    map[string]error
	backendErrors map[string]error

	// resolvedAt is when the pool was last resolved (UnixNano, 0 = never), and resolving
	// is held for the duration of a re-resolution so that concurrent logins cost one DNS
	// lookup between them rather than one each.
	resolvedAt atomic.Int64
	resolving  atomic.Bool

	// resolveRefresh is how long a resolved pool is used before a routing decision
	// re-resolves it; <= 0 pins the pool to the startup resolution. Set via
	// SetResolveRefreshInterval, which callers run once at startup (before serving),
	// after which it is read-only and needs no lock.
	resolveRefresh time.Duration

	// User routing lookup
	routingLookup UserRoutingLookup

	// Affinity manager (optional, for cluster-wide affinity)
	affinityManager AffinityManager

	// restrictRemoteLookupToPool, when true, refuses a remote-lookup-returned backend
	// that is not in the configured pool (SSRF defense). Set via
	// SetRestrictRemoteLookupToPool; default false preserves dynamic routing. Written
	// once at startup (before serving) and then read-only, so it needs no lock.
	restrictRemoteLookupToPool bool

	// maintenance is the process-wide set of backends an operator put in maintenance;
	// routing never picks one. Nil (contains nothing) until SetMaintenance.
	maintenance atomic.Pointer[Maintenance]

	// onMaintenanceChange runs whenever the maintenance set changes (OnMaintenanceChange).
	// Written at startup, before SetMaintenance, then read-only.
	onMaintenanceChange []func()
}

// SetMaintenance attaches the process-wide set of backends in maintenance.
func (cm *ConnectionManager) SetMaintenance(m *Maintenance) {
	if m != nil {
		for _, fn := range cm.onMaintenanceChange {
			m.OnChange(fn)
		}
	}
	cm.maintenance.Store(m)
}

// OnMaintenanceChange registers fn to run whenever the set of backends in maintenance
// changes, once one is attached. Call it before SetMaintenance; fn must not block.
func (cm *ConnectionManager) OnMaintenanceChange(fn func()) {
	cm.onMaintenanceChange = append(cm.onMaintenanceChange, fn)
}

// InMaintenance reports whether addr is a backend an operator put in maintenance. A pool
// entry is also in maintenance when the configured name it was resolved from is: a
// maintenance entry made by name matches the pool's addresses even if its own resolution
// failed, since the pool already knows what the name resolved to.
func (cm *ConnectionManager) InMaintenance(addr string) bool {
	m := cm.maintenance.Load()
	if m.Contains(addr) {
		return true
	}
	if m.Empty() {
		return false
	}
	for _, name := range cm.configuredNamesOf(addr) {
		if m.Contains(name) {
			return true
		}
	}
	return false
}

// configuredNamesOf returns the configured pool addresses (remote_addrs) whose resolution
// produced addr.
func (cm *ConnectionManager) configuredNamesOf(addr string) []string {
	cm.healthMu.RLock()
	defer cm.healthMu.RUnlock()
	return cm.configuredNamesOfLocked(addr)
}

func (cm *ConnectionManager) configuredNamesOfLocked(addr string) []string {
	target := normalizeHostPort(addr, 0)
	var names []string
	for configured, entries := range cm.resolvedHosts {
		for _, entry := range entries {
			if normalizeHostPort(entry, 0) == target && configured != entry {
				names = append(names, configured)
				break
			}
		}
	}
	return names
}

// MaintenanceLoaded reports whether the maintenance list has been read, or is not honored
// at all; until it has, no backend may be dialed (see Maintenance.Loaded).
func (cm *ConnectionManager) MaintenanceLoaded() bool {
	return cm.maintenance.Load().Loaded()
}

var (
	// errBackendInMaintenance is a dial refused because the address actually dialed is
	// in maintenance. It is not a failure of the backend, and never counts against its
	// health.
	errBackendInMaintenance = errors.New("backend is in maintenance")

	// errMaintenanceNotLoaded is a connection refused before the maintenance list was
	// ever read.
	errMaintenanceNotLoaded = errors.New("backend maintenance list not loaded yet")
)

// RefuseMaintenanceDial is a net.Dialer Control for dials to backends. It sees the
// address actually dialed, after name resolution, so a backend in maintenance is never
// connected to whatever name the route used for it, and nothing is dialed before the
// maintenance list was read.
func (cm *ConnectionManager) RefuseMaintenanceDial(_, address string, _ syscall.RawConn) error {
	if err := cm.backendPoolError(address); err != nil {
		return err
	}
	if !cm.MaintenanceLoaded() {
		return errMaintenanceNotLoaded
	}
	if cm.InMaintenance(address) {
		return errBackendInMaintenance
	}
	return nil
}

// SetRestrictRemoteLookupToPool controls whether a backend address returned by the
// remote-lookup API must be a member of the configured pool (remote_addrs). When
// enabled, an out-of-pool address is refused and routing falls back to in-pool
// selection, so a compromised/MITM'd lookup API cannot point the proxy at an
// arbitrary internal host.
func (cm *ConnectionManager) SetRestrictRemoteLookupToPool(v bool) {
	cm.restrictRemoteLookupToPool = v
}

// AllowRemoteLookupBackend reports whether a backend address returned by the remote-lookup
// API may be dialed. With restrict-to-pool off it always allows. With it on, the address
// must match a member of the configured pool — compared by canonical host:port against both
// the originally configured addresses (hostnames) and their resolved forms (IPs) — so a
// compromised or MITM'd lookup API cannot redirect the proxy to an arbitrary host. The
// refusal is logged here so every call site (DetermineRoute and the User API proxy, which
// does not use DetermineRoute) reports it consistently.
func (cm *ConnectionManager) AllowRemoteLookupBackend(addr string) bool {
	if err := cm.backendPoolError(addr); err != nil {
		logger.Error("refusing ambiguous backend pool", "server", cm.serverName, "backend", addr, "error", err)
		return false
	}
	if !cm.restrictRemoteLookupToPool {
		return true
	}
	if addr != "" {
		target := normalizeHostPort(addr, 0)
		cm.healthMu.RLock()
		resolved := cm.remoteAddrs
		cm.healthMu.RUnlock()
		for _, a := range cm.configuredAddrs {
			if normalizeHostPort(a, 0) == target {
				return true
			}
		}
		for _, a := range resolved {
			if normalizeHostPort(a, 0) == target {
				return true
			}
		}
	}
	logger.Error("refusing out-of-pool backend (restrict_to_pool)", "server", cm.serverName, "backend", addr)
	return false
}

// NewConnectionManager creates a new connection manager
func NewConnectionManager(remoteAddrs []string, remotePort int, remoteTLS bool, remoteTLSVerify bool, remoteUseProxyProtocol bool, connectTimeout time.Duration) (*ConnectionManager, error) {
	return NewConnectionManagerWithRouting(remoteAddrs, remotePort, remoteTLS, remoteTLSVerify, remoteUseProxyProtocol, connectTimeout, nil, "")
}

// NewConnectionManagerWithRouting creates a new connection manager with optional user routing
func NewConnectionManagerWithRouting(remoteAddrs []string, remotePort int, remoteTLS bool, remoteTLSVerify bool, remoteUseProxyProtocol bool, connectTimeout time.Duration, routingLookup UserRoutingLookup, serverName string) (*ConnectionManager, error) {
	return NewConnectionManagerWithRoutingAndStartTLS(remoteAddrs, remotePort, remoteTLS, false, remoteTLSVerify, remoteUseProxyProtocol, connectTimeout, routingLookup, serverName)
}

// NewConnectionManagerWithRoutingAndStartTLS creates a new connection manager with optional user routing and StartTLS support
func NewConnectionManagerWithRoutingAndStartTLS(remoteAddrs []string, remotePort int, remoteTLS bool, remoteTLSUseStartTLS bool, remoteTLSVerify bool, remoteUseProxyProtocol bool, connectTimeout time.Duration, routingLookup UserRoutingLookup, serverName string) (*ConnectionManager, error) {
	return NewConnectionManagerWithRoutingAndStartTLSAndHealthCheck(remoteAddrs, remotePort, remoteTLS, remoteTLSUseStartTLS, remoteTLSVerify, remoteUseProxyProtocol, connectTimeout, routingLookup, serverName, false)
}

// NewConnectionManagerWithRoutingAndStartTLSAndHealthCheck creates a new connection manager with all options including health check control.
// The flat remoteAddrs list becomes one unnamed pool that is also the default, which routes
// auth-only lookup answers and locally found users exactly as before pools existed.
func NewConnectionManagerWithRoutingAndStartTLSAndHealthCheck(remoteAddrs []string, remotePort int, remoteTLS bool, remoteTLSUseStartTLS bool, remoteTLSVerify bool, remoteUseProxyProtocol bool, connectTimeout time.Duration, routingLookup UserRoutingLookup, serverName string, disableHealthCheck bool) (*ConnectionManager, error) {
	if len(remoteAddrs) == 0 {
		return nil, fmt.Errorf("no remote addresses provided")
	}
	settings := BackendSettings{
		TLS:              remoteTLS,
		TLSUseStartTLS:   remoteTLSUseStartTLS,
		TLSVerify:        remoteTLSVerify,
		UseProxyProtocol: remoteUseProxyProtocol,
	}
	return newConnectionManager([]PoolSpec{{Backends: remoteAddrs, Default: true, Settings: settings}}, false, remotePort, connectTimeout, routingLookup, serverName, disableHealthCheck)
}

// NewConnectionManagerWithPools creates a connection manager that routes by named pools
// ([[pool]] blocks). Each pool carries its own backend-leg settings and the manager's own
// remote_* settings stay unset, so a dial always uses the settings of the route it serves.
// A backend without a port gets remotePort.
func NewConnectionManagerWithPools(pools []PoolSpec, remotePort int, connectTimeout time.Duration, routingLookup UserRoutingLookup, serverName string, disableHealthCheck bool) (*ConnectionManager, error) {
	if len(pools) == 0 {
		return nil, fmt.Errorf("no backend pools provided")
	}
	return newConnectionManager(pools, true, remotePort, connectTimeout, routingLookup, serverName, disableHealthCheck)
}

func newConnectionManager(specs []PoolSpec, named bool, remotePort int, connectTimeout time.Duration, routingLookup UserRoutingLookup, serverName string, disableHealthCheck bool) (*ConnectionManager, error) {
	cm := &ConnectionManager{
		serverName:               serverName,
		remotePort:               remotePort,
		connectTimeout:           connectTimeout,
		poolsByName:              make(map[string]*backendPool, len(specs)),
		backendHealth:            make(map[string]*BackendHealth),
		remoteLookupHealth:       make(map[string]*BackendHealth), // Dynamic remote lookup backends
		routingLookup:            routingLookup,
		enableBackendHealthCheck: !disableHealthCheck,
		resolveRefresh:           DefaultResolveRefreshInterval,
	}
	if !named {
		// The unnamed pool's settings are the manager's own: they also serve the
		// protocol-layer STARTTLS fallback and the TLS config accessors.
		cm.remoteTLS = specs[0].Settings.TLS
		cm.remoteTLSUseStartTLS = specs[0].Settings.TLSUseStartTLS
		cm.remoteTLSVerify = specs[0].Settings.TLSVerify
		cm.remoteUseProxyProtocol = specs[0].Settings.UseProxyProtocol
	}

	owner := make(map[string]string) // normalized address -> pool name
	for _, spec := range specs {
		if named && spec.Name == "" {
			return nil, fmt.Errorf("backend pool without a name")
		}
		if _, dup := cm.poolsByName[spec.Name]; dup {
			return nil, fmt.Errorf("backend pool %q declared twice", spec.Name)
		}
		if len(spec.Backends) == 0 {
			return nil, fmt.Errorf("backend pool %q has no backends", spec.Name)
		}
		p := &backendPool{name: spec.Name, named: named, isDefault: spec.Default, settings: spec.Settings}
		if spec.Settings.TLSCAFile != "" {
			roots, err := loadCAFile(spec.Settings.TLSCAFile)
			if err != nil {
				return nil, fmt.Errorf("backend pool %q: remote_tls_ca_file: %w", spec.Name, err)
			}
			p.rootCAs = roots
		}
		for _, addr := range spec.Backends {
			// Normalize remote addresses to include default port if missing
			normalized := normalizeHostPort(addr, remotePort)
			if other, taken := owner[normalized]; taken {
				if other == spec.Name {
					continue // listed twice in the same pool
				}
				return nil, fmt.Errorf("backend %s is in pool %q and in pool %q", normalized, other, spec.Name)
			}
			owner[normalized] = spec.Name
			p.configured = append(p.configured, normalized)
			cm.configuredAddrs = append(cm.configuredAddrs, normalized)
			// Initially mark all servers as healthy
			cm.backendHealth[normalized] = &BackendHealth{
				IsHealthy:   true,
				LastSuccess: time.Now(),
			}
		}
		// Until the first resolution the configured addresses are the members.
		p.install(nil)
		if spec.Default {
			if cm.defaultPool != nil {
				return nil, fmt.Errorf("backend pools %q and %q are both default", cm.defaultPool.name, spec.Name)
			}
			cm.defaultPool = p
		}
		cm.pools = append(cm.pools, p)
		cm.poolsByName[spec.Name] = p
	}
	cm.remoteAddrs = slices.Clone(cm.configuredAddrs)

	logger.Debug("Connection manager: Initialized backend pools", "prefix", cm.logPrefix(), "pools", len(cm.pools), "named", named, "backends", len(cm.configuredAddrs))

	return cm, nil
}

// HasNamedPools reports whether this manager routes by named pools ([[pool]] blocks)
// rather than one flat remote_addrs list.
func (cm *ConnectionManager) HasNamedPools() bool {
	return len(cm.pools) > 0 && cm.pools[0].named
}

// PoolNames lists the named pools in configuration order (empty for a flat list).
func (cm *ConnectionManager) PoolNames() []string {
	if !cm.HasNamedPools() {
		return nil
	}
	names := make([]string, 0, len(cm.pools))
	for _, p := range cm.pools {
		names = append(names, p.name)
	}
	return names
}

// PoolInfo describes the pool a route is confined to.
type PoolInfo struct {
	Name     string
	Named    bool // false for the unnamed pool of a flat remote_addrs list
	Default  bool
	Settings BackendSettings
}

// ResolvePool reports the pool a route naming name ("" = the default pool) is confined to,
// or the error DetermineRoute would return for it: ErrUnknownPool, or ErrNoDefaultPool when
// nothing is named and no pool is the default. A flat-list manager always answers with its
// one pool.
func (cm *ConnectionManager) ResolvePool(name string) (PoolInfo, error) {
	p, err := cm.poolByName(name)
	if err != nil {
		return PoolInfo{}, err
	}
	return PoolInfo{Name: p.name, Named: p.named, Default: p.isDefault, Settings: p.settings}, nil
}

// PoolHasBackend reports whether backend is a current member of the pool a route naming
// name is confined to; false for an unknown pool.
func (cm *ConnectionManager) PoolHasBackend(name, backend string) bool {
	p, err := cm.poolByName(name)
	if err != nil {
		return false
	}
	return cm.poolHasBackend(p, backend)
}

// poolByName returns the pool a route naming name is confined to. A flat-list manager has
// one pool and every route lands in it; a named-pool manager refuses an unknown name, and
// an empty name when no pool is the default.
func (cm *ConnectionManager) poolByName(name string) (*backendPool, error) {
	if !cm.HasNamedPools() {
		return cm.defaultPool, nil
	}
	if name == "" {
		if cm.defaultPool == nil {
			return nil, ErrNoDefaultPool
		}
		name = cm.defaultPool.name
	}
	p, ok := cm.poolsByName[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPool, name)
	}
	cm.healthMu.RLock()
	err := cm.poolErrors[name]
	cm.healthMu.RUnlock()
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (cm *ConnectionManager) backendPoolError(addr string) error {
	cm.healthMu.RLock()
	defer cm.healthMu.RUnlock()
	return cm.backendErrors[normalizeHostPort(addr, cm.remotePort)]
}

// poolForRoute is poolByName for the pool a route's info names.
func (cm *ConnectionManager) poolForRoute(info *UserRoutingInfo) (*backendPool, error) {
	name := ""
	if info != nil {
		name = info.PoolName
	}
	return cm.poolByName(name)
}

func (cm *ConnectionManager) poolHasBackend(p *backendPool, backend string) bool {
	cm.healthMu.RLock()
	defer cm.healthMu.RUnlock()
	return slices.Contains(p.resolved, backend)
}

// PoolOfBackend names the named pool addr is a member of, as configured or as resolved;
// "" when it is in none, or this manager routes a flat remote_addrs list. It is how a user
// pinned to a backend in maintenance is routed among that backend's own siblings: a lookup
// pin carries no pool, and the pool the pinned host belongs to is the only one its account
// is known to live in.
func (cm *ConnectionManager) PoolOfBackend(addr string) string {
	cm.healthMu.RLock()
	defer cm.healthMu.RUnlock()
	return cm.poolOfBackendLocked(addr)
}

func (cm *ConnectionManager) poolOfBackendLocked(addr string) string {
	if !cm.HasNamedPools() || addr == "" {
		return ""
	}
	target := normalizeHostPort(addr, cm.remotePort)
	if cm.backendErrors[target] != nil {
		return ""
	}
	for _, p := range cm.pools {
		for _, a := range p.configured {
			if normalizeHostPort(a, cm.remotePort) == target {
				return p.name
			}
		}
		for _, a := range p.resolved {
			if normalizeHostPort(a, cm.remotePort) == target {
				return p.name
			}
		}
	}
	return ""
}

// poolBackendByHost is FindPoolBackendByHost confined to one pool.
func (cm *ConnectionManager) poolBackendByHost(p *backendPool, host string) (string, bool) {
	cm.healthMu.RLock()
	defer cm.healthMu.RUnlock()
	for _, addr := range p.resolved {
		h, _, err := net.SplitHostPort(addr)
		if err == nil && h == host {
			return addr, true
		}
	}
	return "", false
}

// logPrefix returns a consistent log prefix for this connection manager
func (cm *ConnectionManager) logPrefix() string {
	if cm.serverName != "" {
		return fmt.Sprintf("ConnectionManager: %s:", cm.serverName)
	}
	return "ConnectionManager:"
}

// SetAffinityManager sets the affinity manager for cluster-wide affinity
func (cm *ConnectionManager) SetAffinityManager(am AffinityManager) {
	cm.affinityManager = am
}

// GetAffinityManager returns the affinity manager (may be nil)
func (cm *ConnectionManager) GetAffinityManager() AffinityManager {
	return cm.affinityManager
}

// FindPoolBackendByHost returns the pool backend address matching the given hostname.
// This enables cross-protocol affinity: when IMAP affinity points to "backend1:143",
// the POP3 proxy can resolve it to "backend1:110" from its own pool.
// Returns the full host:port address from the pool and true if found, or empty and false otherwise.
func (cm *ConnectionManager) FindPoolBackendByHost(host string) (string, bool) {
	cm.healthMu.RLock()
	defer cm.healthMu.RUnlock()
	for _, addr := range cm.remoteAddrs {
		h, _, err := net.SplitHostPort(addr)
		if err == nil && h == host {
			return addr, true
		}
	}
	return "", false
}

// HasBackend checks if a backend is currently configured in the connection manager pool.
// This ensures that we do not attempt to route to backends that have been removed
// from the configuration but are still present in the affinity cache.
func (cm *ConnectionManager) HasBackend(backend string) bool {
	cm.healthMu.RLock()
	defer cm.healthMu.RUnlock()
	for _, addr := range cm.remoteAddrs {
		if addr == backend {
			return true
		}
	}
	return false
}

// GetBackendByConsistentHash returns a backend for a username using consistent hashing
// over the default pool (the whole list of a flat-list manager). Automatically excludes
// unhealthy backends and tries the next one in the ring. Returns empty string if all
// backends are unhealthy, or if no pool is the default.
func (cm *ConnectionManager) GetBackendByConsistentHash(username string) string {
	return cm.GetBackendByConsistentHashInPool("", username)
}

// GetBackendByConsistentHashInPool is GetBackendByConsistentHash confined to the pool a
// route naming pool ("" = default) is confined to; "" when that pool is unknown.
func (cm *ConnectionManager) GetBackendByConsistentHashInPool(pool, username string) string {
	p, err := cm.poolByName(pool)
	if err != nil {
		logger.Debug("ConnectionManager: Consistent hash has no pool", "username", username, "pool", pool, "error", err)
		return ""
	}
	return cm.hashInPool(p, username)
}

func (cm *ConnectionManager) hashInPool(p *backendPool, username string) string {
	cm.refreshResolvedAddrsIfStale()

	// Snapshot the ring and the pool size: a re-resolution replaces both, and the
	// health checks below take the write lock, so this cannot hold the read lock.
	cm.healthMu.RLock()
	ring := p.ring
	poolSize := len(p.resolved)
	cm.healthMu.RUnlock()

	if ring == nil {
		return ""
	}

	// Try to get a healthy backend from the consistent hash ring
	exclude := make(map[string]bool)

	// Try up to len(remoteAddrs) times (all backends)
	for i := 0; i < poolSize; i++ {
		backend := ring.GetBackendWithExclusions(username, exclude)
		if backend == "" {
			// No more backends available
			logger.Debug("ConnectionManager: Consistent hash returned no backend", "username", username, "iteration", i)
			return ""
		}

		// A backend in maintenance is skipped before its health is read, so it is
		// never dialed and its record stays clean for when it returns.
		if cm.InMaintenance(backend) {
			exclude[backend] = true
			continue
		}

		// Check if this backend is healthy
		isHealthy := cm.IsBackendHealthy(backend)
		logger.Debug("ConnectionManager: Consistent hash health check", "username", username, "backend", backend, "healthy", isHealthy, "iteration", i)

		if isHealthy {
			return backend
		}

		// Backend unhealthy, exclude it and try next
		exclude[backend] = true
	}

	// All backends unhealthy - log diagnostics
	logger.Warn("ConnectionManager: All consistent hash backends unhealthy", "username", username, "pool", p.name, "pool_size", poolSize)
	cm.healthMu.RLock()
	for _, addr := range p.resolved {
		if health, ok := cm.backendHealth[addr]; ok {
			logger.Debug("ConnectionManager: Backend health status", "backend", addr, "healthy", health.IsHealthy, "consecutive_fails", health.ConsecutiveFails, "last_failure", health.LastFailure)
		}
	}
	cm.healthMu.RUnlock()

	return ""
}

// backendRecoveryInterval is how long a backend stays quarantined after being marked
// unhealthy before health checks let traffic try it again.
const backendRecoveryInterval = 1 * time.Minute

// healthWithAutoRecovery reads the health entry for a backend and applies the
// auto-recovery transition, all inside one critical section on the write lock: the
// BackendHealth fields are mutated by the Record* methods under that same lock, and
// ResolveAddresses replaces the maps wholesale, so the entry that gets recovered has to be
// the one currently in the map.
func (cm *ConnectionManager) healthWithAutoRecovery(backend string, remoteLookup, missingIsHealthy bool) (healthy, recovered bool) {
	cm.healthMu.Lock()
	defer cm.healthMu.Unlock()

	entries := cm.backendHealth
	if remoteLookup {
		entries = cm.remoteLookupHealth
	}

	health, exists := entries[backend]
	if !exists {
		return missingIsHealthy, false
	}

	if !health.IsHealthy && time.Since(health.LastFailure) > backendRecoveryInterval {
		health.IsHealthy = true
		health.ConsecutiveFails = 0
		recovered = true
	}

	return health.IsHealthy, recovered
}

// IsBackendHealthy checks if a backend is healthy based on detailed health tracking
// Returns true if healthy, false if marked unhealthy
// Auto-recovers backends after 1 minute of being marked unhealthy
func (cm *ConnectionManager) IsBackendHealthy(backend string) bool {
	// If health checks are disabled, always return true (all backends healthy)
	if !cm.enableBackendHealthCheck {
		return true
	}

	healthy, recovered := cm.healthWithAutoRecovery(backend, false /* remoteLookup */, false /* not in our list, assume unhealthy */)
	if recovered {
		logger.Info("ConnectionManager: Auto-recovered backend after 1 minute", "backend", backend)
	}

	return healthy
}

// IsBackendHealthyForAffinity checks if a backend is healthy WITHOUT auto-recovery.
// This ensures users who failed over to a different backend stay there,
// even if their original affinity backend recovers.
// Auto-recovery still applies for consistent-hash routing (allows new users to use recovered backends).
func (cm *ConnectionManager) IsBackendHealthyForAffinity(backend string) bool {
	// If health checks are disabled, always return true (all backends healthy)
	if !cm.enableBackendHealthCheck {
		return true
	}

	cm.healthMu.RLock()
	defer cm.healthMu.RUnlock()

	health, exists := cm.backendHealth[backend]
	if !exists {
		// No health record = healthy (never attempted connection yet)
		return true
	}

	// For affinity checks, do NOT apply auto-recovery
	// Return the actual health status WITHOUT checking the 1-minute grace period
	// Even if the backend was marked unhealthy >1 minute ago, we still consider it unhealthy
	// for affinity purposes (sticky failover)
	return health.IsHealthy
}

// IsRemoteLookupBackendHealthy checks if a remote lookup backend (not in pool) is healthy
// Returns true if healthy or unknown, false if marked unhealthy
// Auto-recovers backends after 1 minute of being marked unhealthy
func (cm *ConnectionManager) IsRemoteLookupBackendHealthy(backend string) bool {
	// If health checks are disabled, always return true
	if !cm.enableBackendHealthCheck {
		return true
	}

	healthy, recovered := cm.healthWithAutoRecovery(backend, true /* remoteLookup */, true /* unknown backend, assume healthy to allow a first attempt */)
	if recovered {
		logger.Info("ConnectionManager: Remote lookup backend auto-recovered after 1 minute", "backend", backend)
	}

	return healthy
}

// BackendHealthInfo represents the health status of a single backend for external reporting
type BackendHealthInfo struct {
	Address            string    `json:"address"`
	Pool               string    `json:"pool,omitempty"` // Named pool the backend belongs to ("" for a flat remote_addrs list)
	IsHealthy          bool      `json:"is_healthy"`
	FailureCount       int       `json:"failure_count"`
	ConsecutiveFails   int       `json:"consecutive_fails"`
	LastFailure        time.Time `json:"last_failure,omitempty"`
	LastSuccess        time.Time `json:"last_success,omitempty"`
	HealthCheckEnabled bool      `json:"health_check_enabled"`
	IsRemoteLookup     bool      `json:"is_remote_lookup"` // True if backend from remote_lookup (not in pool)
	InMaintenance      bool      `json:"in_maintenance"`   // True if an operator put the backend in maintenance
}

// HasHealthyPoolBackends checks if at least one pool backend (from remote_addrs config) is
// available: healthy (or due to auto-recover, or health checks are disabled) and not in
// maintenance. This is used to determine if the proxy can route messages to backends.
//
// With named pools only the default pool counts: the LMTP proxy asks before bouncing a
// recipient its own database does not know, and only a local user, who lives in the
// default pool, could be known to those backends instead. Without a default pool there is
// no such backend, and the answer is false (a temporary failure, never a bounce).
func (cm *ConnectionManager) HasHealthyPoolBackends() bool {
	cm.healthMu.RLock()
	var members map[string]bool // nil = every backend counts
	if cm.HasNamedPools() {
		members = map[string]bool{}
		if cm.defaultPool != nil {
			for _, addr := range cm.defaultPool.resolved {
				members[addr] = true
			}
		}
	}
	healthy := make([]string, 0, len(cm.backendHealth))
	for addr, health := range cm.backendHealth {
		if members != nil && !members[addr] {
			continue
		}
		// Healthy, or due for auto-recovery (1 minute since last failure)
		if !cm.enableBackendHealthCheck || health.IsHealthy || time.Since(health.LastFailure) > backendRecoveryInterval {
			healthy = append(healthy, addr)
		}
	}
	cm.healthMu.RUnlock()

	// Outside healthMu: maintenance may resolve a hostname.
	for _, addr := range healthy {
		if !cm.InMaintenance(addr) {
			return true
		}
	}
	return false
}

// GetBackendHealthStatuses returns health information for all backends (pool + remote lookup)
func (cm *ConnectionManager) GetBackendHealthStatuses() []BackendHealthInfo {
	statuses := cm.backendHealthStatuses()
	// Outside healthMu: maintenance may resolve a hostname.
	for i := range statuses {
		statuses[i].InMaintenance = cm.InMaintenance(statuses[i].Address)
	}
	return statuses
}

func (cm *ConnectionManager) backendHealthStatuses() []BackendHealthInfo {
	cm.healthMu.RLock()
	defer cm.healthMu.RUnlock()

	healthCheckEnabled := cm.enableBackendHealthCheck
	statuses := make([]BackendHealthInfo, 0, len(cm.backendHealth)+len(cm.remoteLookupHealth))

	report := func(addr, pool string, health *BackendHealth) {
		info := BackendHealthInfo{
			Address:            addr,
			Pool:               pool,
			IsHealthy:          health.IsHealthy,
			FailureCount:       health.FailureCount,
			ConsecutiveFails:   health.ConsecutiveFails,
			LastFailure:        health.LastFailure,
			LastSuccess:        health.LastSuccess,
			HealthCheckEnabled: healthCheckEnabled,
			IsRemoteLookup:     false, // Pool backend
		}

		// If health checks are disabled, all backends are considered healthy
		if !healthCheckEnabled {
			info.IsHealthy = true
		}

		statuses = append(statuses, info)
	}

	// Pool backends, each under the pool it belongs to
	seen := make(map[string]bool, len(cm.backendHealth))
	for _, p := range cm.pools {
		for _, addr := range p.resolved {
			seen[addr] = true
			health, ok := cm.backendHealth[addr]
			if !ok {
				health = &BackendHealth{IsHealthy: true}
			}
			report(addr, p.name, health)
		}
	}
	// A health entry no pool lists any more (a member a re-resolution dropped)
	for addr, health := range cm.backendHealth {
		if !seen[addr] {
			report(addr, "", health)
		}
	}

	// Add remote lookup backends (dynamic, not in pool)
	for addr, health := range cm.remoteLookupHealth {
		info := BackendHealthInfo{
			Address:            addr,
			IsHealthy:          health.IsHealthy,
			FailureCount:       health.FailureCount,
			ConsecutiveFails:   health.ConsecutiveFails,
			LastFailure:        health.LastFailure,
			LastSuccess:        health.LastSuccess,
			HealthCheckEnabled: healthCheckEnabled,
			IsRemoteLookup:     true, // Remote lookup backend
		}

		// If health checks are disabled, all backends are considered healthy
		if !healthCheckEnabled {
			info.IsHealthy = true
		}

		statuses = append(statuses, info)
	}

	return statuses
}

// RecordConnectionSuccess records a successful connection to a backend
func (cm *ConnectionManager) RecordConnectionSuccess(backend string) {
	cm.healthMu.Lock()
	defer cm.healthMu.Unlock()

	health, exists := cm.backendHealth[backend]
	if !exists {
		// Create health entry for new backend
		health = &BackendHealth{
			IsHealthy:   true,
			LastSuccess: time.Now(),
		}
		cm.backendHealth[backend] = health
		return
	}

	wasUnhealthy := !health.IsHealthy
	health.LastSuccess = time.Now()
	health.ConsecutiveFails = 0 // Reset consecutive failures on success
	health.IsHealthy = true

	if wasUnhealthy {
		logger.Info("ConnectionManager: Backend recovered (consecutive failures reset)", "backend", backend)
	}
}

// RecordConnectionFailure records a connection failure and marks backend unhealthy after 3 consecutive failures
// Returns true if backend was just marked unhealthy (transition from healthy to unhealthy)
func (cm *ConnectionManager) RecordConnectionFailure(backend string) bool {
	// If health checks are disabled, do nothing
	if !cm.enableBackendHealthCheck {
		return false
	}

	cm.healthMu.Lock()
	defer cm.healthMu.Unlock()

	health, exists := cm.backendHealth[backend]
	if !exists {
		// Create health entry for new backend - start healthy, mark unhealthy after 3 failures
		health = &BackendHealth{
			IsHealthy:        true,
			LastFailure:      time.Now(),
			FailureCount:     1,
			ConsecutiveFails: 1,
		}
		cm.backendHealth[backend] = health
		logger.Debug("ConnectionManager: Recording first failure for backend", "backend", backend, "server", cm.serverName)
		return false
	}

	wasHealthy := health.IsHealthy
	health.FailureCount++
	health.ConsecutiveFails++
	health.LastFailure = time.Now()

	logger.Debug("ConnectionManager: Recording connection failure", "backend", backend, "consecutive_fails", health.ConsecutiveFails, "was_healthy", wasHealthy, "server", cm.serverName)

	// Mark unhealthy after 3 consecutive failures
	if health.ConsecutiveFails >= 3 {
		health.IsHealthy = false
		if wasHealthy {
			logger.Warn("ConnectionManager: Backend marked unhealthy after consecutive failures", "backend", backend, "count", health.ConsecutiveFails, "server", cm.serverName)
			return true // Just became unhealthy
		}
	}

	return false
}

// RecordRemoteLookupSuccess records a successful connection to a remote lookup backend (not in pool)
func (cm *ConnectionManager) RecordRemoteLookupSuccess(backend string) {
	cm.healthMu.Lock()
	defer cm.healthMu.Unlock()

	health, exists := cm.remoteLookupHealth[backend]
	if !exists {
		// Create health entry for new remote lookup backend
		health = &BackendHealth{
			IsHealthy:   true,
			LastSuccess: time.Now(),
		}
		cm.remoteLookupHealth[backend] = health
		return
	}

	wasUnhealthy := !health.IsHealthy
	health.LastSuccess = time.Now()
	health.ConsecutiveFails = 0 // Reset consecutive failures on success
	health.IsHealthy = true

	if wasUnhealthy {
		logger.Info("ConnectionManager: Remote lookup backend recovered", "backend", backend)
	}
}

// RecordRemoteLookupFailure records a connection failure to a remote lookup backend (not in pool)
// Marks backend unhealthy after 3 consecutive failures (same as pool backends)
// Returns true if backend was just marked unhealthy (transition from healthy to unhealthy)
func (cm *ConnectionManager) RecordRemoteLookupFailure(backend string) bool {
	// If health checks are disabled, do nothing
	if !cm.enableBackendHealthCheck {
		return false
	}

	cm.healthMu.Lock()
	defer cm.healthMu.Unlock()

	health, exists := cm.remoteLookupHealth[backend]
	if !exists {
		// Create health entry for new remote lookup backend - start healthy, mark unhealthy after 3 failures
		health = &BackendHealth{
			IsHealthy:        true,
			LastFailure:      time.Now(),
			FailureCount:     1,
			ConsecutiveFails: 1,
		}
		cm.remoteLookupHealth[backend] = health
		logger.Debug("ConnectionManager: Recording first failure for remote lookup backend", "backend", backend, "server", cm.serverName)
		return false
	}

	wasHealthy := health.IsHealthy
	health.FailureCount++
	health.ConsecutiveFails++
	health.LastFailure = time.Now()

	logger.Debug("ConnectionManager: Recording remote lookup failure", "backend", backend, "consecutive_fails", health.ConsecutiveFails, "was_healthy", wasHealthy, "server", cm.serverName)

	// Mark unhealthy after 3 consecutive failures (same as pool backends)
	if health.ConsecutiveFails >= 3 {
		health.IsHealthy = false
		if wasHealthy {
			logger.Warn("ConnectionManager: Remote lookup backend marked unhealthy", "backend", backend, "count", health.ConsecutiveFails, "server", cm.serverName)
			return true // Just became unhealthy
		}
	}

	return false
}

// AuthenticateAndRouteWithClientIP performs authentication and routing with client IP and additional options
// clientIP: the real client's IP (the PROXY header source when there is one), the
// remotelookup URL's $ip placeholder
// routeOnly: if true, skip password validation and only return routing info (for master username auth)
func (cm *ConnectionManager) AuthenticateAndRouteWithClientIP(ctx context.Context, email, password, clientIP string, routeOnly bool) (*UserRoutingInfo, AuthResult, error) {
	if cm.routingLookup == nil {
		return nil, AuthUserNotFound, fmt.Errorf("no routing lookup configured")
	}
	return cm.routingLookup.LookupUserRouteWithClientIP(ctx, email, password, clientIP, routeOnly)
}

// GetRoutingLookup returns the routing lookup client (may be nil)
func (cm *ConnectionManager) GetRoutingLookup() UserRoutingLookup {
	return cm.routingLookup
}

// GetRemoteLookupTimeout returns the timeout for remotelookup HTTP requests including connection establishment
// This automatically calculates a context timeout that allows enough time for:
// - DNS resolution + TCP dial (dial_timeout)
// - TLS handshake (tls_handshake_timeout)
// - HTTP request/response (configured timeout)
//
// The context timeout is set to the maximum of:
// 1. Configured HTTP timeout (for reused connections)
// 2. dial_timeout + tls_handshake_timeout + HTTP timeout (for new connections)
//
// This ensures:
// - First request to new host: Has time for full connection setup
// - Subsequent requests: Reuse connection, complete within HTTP timeout
// - Context never cancels before HTTP client timeouts complete
func (cm *ConnectionManager) GetRemoteLookupTimeout() time.Duration {
	if cm.routingLookup == nil {
		return 10 * time.Second // Default if no remotelookup configured
	}

	// Type assert to HTTPRemoteLookupClient to access timeout and transport settings
	if httpClient, ok := cm.routingLookup.(*HTTPRemoteLookupClient); ok {
		baseTimeout := httpClient.GetTimeout()
		dialTimeout, tlsTimeout := httpClient.GetTransportTimeouts()

		// Context timeout must allow for worst case: new connection requiring dial + TLS + HTTP
		// We add a small buffer (10%) to account for network overhead
		totalTimeout := dialTimeout + tlsTimeout + baseTimeout
		contextTimeout := totalTimeout + (totalTimeout / 10) // +10% buffer

		// Use whichever is larger: configured HTTP timeout or calculated total
		// This maintains backward compatibility if someone manually set a high timeout
		if contextTimeout > baseTimeout {
			return contextTimeout
		}
		return baseTimeout
	}

	return 10 * time.Second // Fallback default
}

// SetRemoteTLSRootCAs replaces the system roots used to verify backend
// certificates when remote_tls_verify is enabled. Use it for backends whose
// certificates are issued by a private CA (or are self-signed): put the CA
// (or the certificate itself) in the pool instead of disabling verification.
// Must be called before the manager starts dialing backends.
func (cm *ConnectionManager) SetRemoteTLSRootCAs(pool *x509.CertPool) {
	cm.remoteTLSRootCAs = pool
}

// loadCAFile reads a PEM file of CA certificates; an unreadable file, or one without a
// usable certificate, is an error (never a silent fallback to the system roots).
func loadCAFile(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s contains no usable certificates", path)
	}
	return roots, nil
}

// BackendClientTLS is the client TLS config for a connection to the backend at addr, the
// address actually dialed, on the implicit-TLS dial and for a STARTTLS upgrade alike:
//   - the hardening of backendTLSConfig, verifying certificates when verify is set;
//   - the roots: a member of a named pool is verified against its pool's remote_tls_ca_file
//     (the system roots without one): a certificate belongs to the host, however routing
//     reached it. Any other backend uses the server's remote_tls_ca_file (POP3) or the
//     system roots;
//   - the name: a pool or remote_addrs entry configured by hostname is dialed at an address
//     the name resolved to, but the certificate is issued for the name. ServerName (SNI) is
//     that name, and a certificate valid for the name or for the address dialed is accepted,
//     so a backend whose certificate names only its address keeps working as before.
func (cm *ConnectionManager) BackendClientTLS(verify bool, addr string) *tls.Config {
	route, err := cm.BindBackendRoute("", addr)
	if err != nil {
		return cm.refusedBackendTLS(err)
	}
	return route.TLSConfig(verify)
}

// configuredHostnamesOfLocked returns the hostnames (not IP literals) whose resolution
// produced addr. The caller holds healthMu so roots and names use one DNS snapshot.
func (cm *ConnectionManager) configuredHostnamesOfLocked(addr string) []string {
	var hosts []string
	for _, configured := range cm.configuredNamesOfLocked(addr) {
		h, _, err := net.SplitHostPort(configured)
		if err != nil {
			h = configured
		}
		if h != "" && net.ParseIP(strings.Trim(h, "[]")) == nil {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// verifyBackendCertificate verifies a backend's certificate chain against roots (nil = the
// system roots) and accepts it if it is valid for any of names.
func verifyBackendCertificate(roots *x509.CertPool, names []string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("backend presented no certificate")
		}
		opts := x509.VerifyOptions{Roots: roots, Intermediates: x509.NewCertPool()}
		for _, c := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		leaf := cs.PeerCertificates[0]
		if _, err := leaf.Verify(opts); err != nil {
			return err
		}
		var err error
		for _, name := range names {
			if err = leaf.VerifyHostname(name); err == nil {
				return nil
			}
		}
		return err
	}
}

// backendTLSConfig builds the client TLS config for the proxy->backend leg.
// Shared by the implicit-TLS dial paths and the STARTTLS upgrade path so the
// hardening choices (no client certs, no renegotiation, TLS 1.2 floor, custom
// roots) stay in one place. verify is a parameter because remote-lookup
// routing can override remote_tls_verify per connection.
func (cm *ConnectionManager) backendTLSConfig(verify bool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: !verify,
		// nil means system roots; ignored entirely when verification is off.
		RootCAs: cm.remoteTLSRootCAs,
		// Explicitly set empty certificates to prevent automatic client certificate presentation
		Certificates: []tls.Certificate{},
		// Disable client certificate authentication
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return nil, nil
		},
		// Disable renegotiation (not supported in TLS 1.3, causes errors)
		Renegotiation: tls.RenegotiateNever,
		// Floor the proxy->backend leg at TLS 1.2 (avoid downgrade to 1.0/1.1).
		MinVersion: tls.VersionTLS12,
	}
}

// GetTLSConfig returns the TLS configuration for remote connections
// Used for StartTLS negotiation at the protocol layer
// addr is the backend address actually connected to (see BackendClientTLS).
func (cm *ConnectionManager) GetTLSConfig(addr string) *tls.Config {
	if !cm.remoteTLS {
		return nil
	}
	return cm.BackendClientTLS(cm.remoteTLSVerify, addr)
}

// IsRemoteStartTLS returns whether remote connections should use StartTLS
func (cm *ConnectionManager) IsRemoteStartTLS() bool {
	return cm.remoteTLS && cm.remoteTLSUseStartTLS
}

// backendTLSSettings are the remote_tls, remote_tls_use_starttls and remote_tls_verify a
// connection to addr uses: the route's for the backend the lookup named or a member of the
// pool routing confined it to, else the manager's own. ConnectWithProxy dials by them and
// BackendStartTLSConfig asks them again, so the two cannot disagree.
func (cm *ConnectionManager) backendTLSSettings(routingInfo *UserRoutingInfo, addr string) (remoteTLS, useStartTLS, verify bool) {
	if routingInfo.UsesRouteSettings(addr) {
		return routingInfo.RemoteTLS, routingInfo.RemoteTLSUseStartTLS, routingInfo.RemoteTLSVerify
	}
	return cm.remoteTLS, cm.remoteTLSUseStartTLS, cm.remoteTLSVerify
}

// BackendStartTLSConfig returns the config the protocol layer upgrades a connection
// ConnectWithProxy returned for addr with, by its protocol's STARTTLS, right after the
// greeting: nil when that connection needs none (implicit TLS, which the dial did, or a
// plaintext leg). ConnectWithProxy dials plaintext whenever it returns a config, so a
// proxy that skips the upgrade then runs the leg in plaintext.
func (cm *ConnectionManager) BackendStartTLSConfig(routingInfo *UserRoutingInfo, addr string, connected ...net.Conn) *tls.Config {
	remoteTLS, useStartTLS, verify := cm.backendTLSSettings(routingInfo, addr)
	if !remoteTLS || !useStartTLS {
		return nil
	}
	if len(connected) > 0 && connected[0] != nil {
		return cm.BackendClientTLSForConn(verify, addr, connected[0])
	}
	route, err := cm.bindForDial(routingInfo, addr)
	if err != nil {
		return cm.refusedBackendTLS(err)
	}
	return route.TLSConfig(verify)
}

// ConnectWithProxy attempts to connect to a remote server and sends PROXY protocol header
func (cm *ConnectionManager) ConnectWithProxy(ctx context.Context, preferredAddr, clientIP string, clientPort int, serverIP string, serverPort int, routingInfo *UserRoutingInfo) (net.Conn, string, error) {
	if !cm.MaintenanceLoaded() {
		// Fail closed: a backend may be in maintenance, and which is not known yet. The
		// list is retried every poll; routing has not been touched (no affinity dropped).
		logger.Error("Backend maintenance list not loaded yet - refusing connection", "server", cm.serverName)
		return nil, "", errMaintenanceNotLoaded
	}
	cm.refreshResolvedAddrsIfStale()

	if preferredAddr != "" {
		if err := cm.backendPoolError(preferredAddr); err != nil {
			return nil, "", err
		}
		conn, addr, err, fallback := cm.tryPreferredAddress(ctx, preferredAddr, clientIP, clientPort, serverIP, serverPort, routingInfo)
		if !fallback {
			// If no fallback is needed, we either succeeded or had a hard failure.
			return conn, addr, err
		}
		// If fallback is true, the connection failed but we should proceed to round-robin.
		// The error from tryPreferredAddress is logged but not returned to the client yet.
		if cm.HasNamedPools() && routingInfo != nil && routingInfo.ServerAddress != "" && routingInfo.ServerAddress == preferredAddr {
			// A lookup pin whose backend cannot be dialed has no pool to fall back into:
			// the pin names none, and the default pool need not hold the account (the
			// session would close a backend other than the pin anyway). DetermineRoute
			// already routes a pin in maintenance among its siblings; this is the race
			// where it entered maintenance after that, or a pin seen as a plain preference.
			logger.Warn("ConnectionManager: Pinned backend unavailable - not falling back into a pool", "backend", preferredAddr, "server", cm.serverName)
			return nil, "", fmt.Errorf("remote-lookup backend %s is unavailable", preferredAddr)
		}
	}

	// Round-robin stays inside the route's pool: a user whose pool has no backend left is
	// refused, never handed to another pool's backend. The member list is snapshotted
	// under the lock because a re-resolution replaces it.
	pool, err := cm.poolForRoute(routingInfo)
	if err != nil {
		return nil, "", err
	}
	cm.healthMu.RLock()
	currentRemoteAddrs := pool.resolved
	cm.healthMu.RUnlock()

	// Try all servers in round-robin order
	startIndex := pool.nextIndex.Add(1) - 1
	inMaintenance := 0
	for i := 0; i < len(currentRemoteAddrs); i++ {
		idx := (startIndex + uint32(i)) % uint32(len(currentRemoteAddrs))
		addr := currentRemoteAddrs[idx]

		if cm.InMaintenance(addr) {
			inMaintenance++
			continue
		}

		// Skip unhealthy backends
		if !cm.IsBackendHealthy(addr) {
			continue
		}

		conn, err := cm.dialWithProxy(ctx, addr, clientIP, clientPort, serverIP, serverPort, routingInfo)
		if err == nil {
			// Record success in health tracking
			cm.RecordConnectionSuccess(addr)
			return conn, addr, nil
		}
		if errors.Is(err, ErrBackendOutsidePool) {
			continue
		}
		if errors.Is(err, errBackendInMaintenance) {
			inMaintenance++ // resolved to an address in maintenance
			continue
		}
		if errors.Is(err, ErrAmbiguousBackendPool) {
			return nil, "", err
		}

		// Record failure in health tracking only if the caller's context is still live.
		// ctx.Err() is the only usable discriminator: a dial that exhausted its own
		// connect_timeout — the black-holed backend case — also reports as
		// context.DeadlineExceeded, so the error identity cannot tell a dead backend
		// apart from a caller-side timeout or cancellation (slow remote_lookup consuming
		// the deadline, client disconnect, global timeout).
		if ctx.Err() == nil {
			cm.RecordConnectionFailure(addr)
		}
		logger.Warn("Failed to connect to backend (round-robin)", "addr", addr, "error", err, "ctx_err", ctx.Err(), "server", cm.serverName)
	}

	if inMaintenance > 0 && inMaintenance == len(currentRemoteAddrs) {
		// Fail closed: maintenance means no new traffic, even when nothing else is left.
		logger.Error("Every backend in the pool is in maintenance - refusing connection", "server", cm.serverName, "backends", currentRemoteAddrs)
		return nil, "", fmt.Errorf("all remote servers are in maintenance")
	}
	return nil, "", fmt.Errorf("all remote servers are unavailable")
}

// tryPreferredAddress attempts to connect to a preferred address (from affinity or remotelookup).
// It returns the connection, address, and an error if it fails.
// The 'shouldFallback' boolean indicates if the caller should attempt round-robin.
func (cm *ConnectionManager) tryPreferredAddress(ctx context.Context, preferredAddr, clientIP string, clientPort int, serverIP string, serverPort int, routingInfo *UserRoutingInfo) (conn net.Conn, addr string, err error, shouldFallback bool) {
	// A backend in maintenance is never dialed. DetermineRoute already routes around it;
	// this covers a preferred address that reached here some other way.
	if cm.InMaintenance(preferredAddr) {
		logger.Debug("ConnectionManager: Preferred backend is in maintenance. Falling back to round-robin.", "backend", preferredAddr, "server", cm.serverName)
		return nil, "", nil, true
	}

	// Determine if this is a remote lookup route with explicit server designation
	// Auth-only mode (AuthOnlyMode=true) means remote API authenticated but didn't specify backend,
	// so we should treat it like a normal DB user (allow fallback to round-robin/affinity/consistent-hash)
	isRemoteLookupRoute := routingInfo != nil && routingInfo.IsRemoteLookupAccount &&
		routingInfo.ServerAddress == preferredAddr && !routingInfo.AuthOnlyMode

	cm.healthMu.RLock()
	isInList := false
	for _, a := range cm.remoteAddrs {
		if a == preferredAddr {
			isInList = true
			break
		}
	}
	cm.healthMu.RUnlock()

	// For remote lookup backends NOT in pool, check their health separately
	if !isInList && isRemoteLookupRoute {
		if !cm.IsRemoteLookupBackendHealthy(preferredAddr) {
			logger.Warn("ConnectionManager: Remote lookup backend (not in pool) is marked unhealthy. Failing request.", "backend", preferredAddr, "server", cm.serverName)
			err = fmt.Errorf("remotelookup-designated backend %s is marked unhealthy", preferredAddr)
			return nil, "", err, false // No fallback - fail immediately
		}
	}

	// If the server is in our list and marked unhealthy, decide whether to fail hard or fall back.
	if isInList && !cm.IsBackendHealthy(preferredAddr) {
		if isRemoteLookupRoute {
			// RemoteLookup routes are definitive; if the server is unhealthy, we fail hard.
			logger.Debug("ConnectionManager: RemoteLookup-designated server is marked as unhealthy. NOT falling back to round-robin.", "server", preferredAddr)
			err = fmt.Errorf("remotelookup-designated server %s is marked as unhealthy", preferredAddr)
			return nil, "", err, false // No fallback
		}
		// For affinity, if the server is unhealthy, we just fall back to round-robin.
		logger.Debug("ConnectionManager: Preferred (affinity) server is marked as unhealthy. Falling back to round-robin.", "server", preferredAddr)
		return nil, "", nil, true // Fallback
	}

	// Attempt to dial the preferred address.
	conn, err = cm.dialWithProxy(ctx, preferredAddr, clientIP, clientPort, serverIP, serverPort, routingInfo)
	if errors.Is(err, ErrAmbiguousBackendPool) {
		return nil, "", err, false
	}
	if errors.Is(err, ErrBackendOutsidePool) {
		return nil, "", err, true
	}
	if errors.Is(err, errBackendInMaintenance) {
		// The name resolved to an address in maintenance: as above, not a failure.
		logger.Debug("ConnectionManager: Preferred backend resolves to an address in maintenance. Falling back to round-robin.", "backend", preferredAddr, "server", cm.serverName)
		return nil, "", nil, true
	}
	if err == nil {
		// Success! Record success in health tracking
		if isInList {
			cm.RecordConnectionSuccess(preferredAddr)
		} else if isRemoteLookupRoute {
			// Track remote lookup backend (not in pool)
			cm.RecordRemoteLookupSuccess(preferredAddr)
		}
		return conn, preferredAddr, nil, false // No fallback
	}

	// Connection failed. Mark it as unhealthy if it's in our managed list.
	if isInList {
		// Only record failure if the caller's context is still live. Same discriminator as
		// the round-robin path: a dial that exhausted its own connect_timeout reports as
		// context.DeadlineExceeded even though ctx never expired, so only ctx.Err() tells a
		// dead backend apart from a caller-side timeout or cancellation.
		if ctx.Err() == nil {
			cm.RecordConnectionFailure(preferredAddr)
		}
		logger.Warn("Failed to connect to preferred backend", "addr", preferredAddr, "error", err, "is_remotelookup", isRemoteLookupRoute, "ctx_err", ctx.Err(), "server", cm.serverName)
	} else if isRemoteLookupRoute {
		// Track remote lookup backend failure (not in pool), same discriminator as above.
		if ctx.Err() == nil {
			cm.RecordRemoteLookupFailure(preferredAddr)
		}
		logger.Warn("Failed to connect to remote lookup backend (not in pool)", "addr", preferredAddr, "error", err, "ctx_err", ctx.Err(), "server", cm.serverName)
	}

	if isRemoteLookupRoute {
		// For remotelookup routes, do NOT fall back to round-robin.
		logger.Warn("ConnectionManager: Failed to connect to remotelookup-designated server. NOT falling back to round-robin.", "server", preferredAddr, "error", err)
		err = fmt.Errorf("failed to connect to remotelookup-designated server %s: %w", preferredAddr, err)
		return nil, "", err, false // No fallback
	}

	// For affinity-based connections, log the failure and indicate that we should fall back.
	logger.Warn("ConnectionManager: Failed to connect to preferred address. Falling back to round-robin.", "addr", preferredAddr, "error", err, "server", cm.serverName)
	return nil, "", err, true // Fallback
}

// ResolveAddresses resolves the configured backend names to IP addresses and installs
// the result as the pool. Callers run this once at startup; the pool is re-resolved from
// then on by refreshResolvedAddrsIfStale.
func (cm *ConnectionManager) ResolveAddresses() error {
	logger.Info("ConnectionManager: Starting address resolution", "server", cm.serverName, "configured_backends", len(cm.configuredAddrs))
	cm.resolveAddresses()
	cm.healthMu.RLock()
	defer cm.healthMu.RUnlock()
	var errs []error
	for _, p := range cm.pools {
		if err := cm.poolErrors[p.name]; err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// DefaultResolveRefreshInterval is how long a resolved pool is used before the next
// routing decision re-resolves it, unless SetResolveRefreshInterval overrides it.
// net.LookupIP does not report the TTL of the records it answered from, so this stands
// in for it.
const DefaultResolveRefreshInterval = 5 * time.Minute

// SetResolveRefreshInterval overrides how long a resolved backend pool is used before a
// routing decision re-resolves it. An interval of 0 (or less) pins the pool to the
// addresses resolved at startup, which is the behavior to fall back to if periodic
// re-resolution ever misbehaves in a deployment. Must be called before the manager
// starts routing.
func (cm *ConnectionManager) SetResolveRefreshInterval(d time.Duration) {
	cm.resolveRefresh = d
}

// refreshResolvedAddrsIfStale re-resolves the pool in the background once the current
// answer has aged past the resolve refresh interval, so a backend that changes address
// is picked up without a restart. The caller routes on the addresses already in hand: a
// DNS lookup must not sit in the path of a login. A manager whose pool was never resolved
// (nothing called ResolveAddresses) is left alone — its pool is the configured one, which
// the per-dial resolveAddress still resolves.
//
// A pool entry that disappears takes the affinity pointing at it with it: DetermineRoute
// drops an affinity whose backend is no longer in the pool and routes the user afresh.
// Established sessions are untouched; they hold a connection, not an address.
func (cm *ConnectionManager) refreshResolvedAddrsIfStale() {
	if cm.resolveRefresh <= 0 {
		return
	}
	last := cm.resolvedAt.Load()
	if last == 0 || time.Since(time.Unix(0, last)) < cm.resolveRefresh {
		return
	}
	if !cm.resolving.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer cm.resolving.Store(false)
		cm.resolveAddresses()
	}()
}

// resolveAddresses resolves configuredAddrs — never the pool a previous resolution
// produced, which holds IP literals a lookup hands back unchanged — and installs the
// result.
func (cm *ConnectionManager) resolveAddresses() {
	cm.healthMu.RLock()
	previous := cm.resolvedHosts
	cm.healthMu.RUnlock()

	resolvedAddrs := make([]string, 0, len(cm.configuredAddrs))
	resolvedHosts := make(map[string][]string, len(cm.configuredAddrs))
	seen := make(map[string]bool, len(cm.configuredAddrs))

	for _, addr := range cm.configuredAddrs {
		entries := resolvePoolEntries(addr, previous[addr])
		if entries == nil {
			// The name did not resolve. Keep the answer that last worked rather than
			// dropping the backend out of the pool over a transient SERVFAIL.
			entries = previous[addr]
			if entries == nil {
				entries = []string{addr}
			}
			logger.Warn("ConnectionManager: Backend name did not resolve - keeping last known addresses", "server", cm.serverName, "backend", addr, "addresses", entries)
		}

		resolvedHosts[addr] = entries
		for _, entry := range entries {
			if seen[entry] {
				continue
			}
			seen[entry] = true
			resolvedAddrs = append(resolvedAddrs, entry)
		}
	}

	cm.installResolvedAddrs(resolvedAddrs, resolvedHosts)
}

// installResolvedAddrs makes a resolution result the pool, rebuilding the health map and
// the hash ring around it. Health is carried over per address, so a backend that survives
// a re-resolution keeps the failures recorded against it.
func (cm *ConnectionManager) installResolvedAddrs(resolvedAddrs []string, resolvedHosts map[string][]string) {
	cm.healthMu.Lock()
	defer cm.healthMu.Unlock()
	defer cm.resolvedAt.Store(time.Now().UnixNano())

	cm.resolvedHosts = resolvedHosts
	cm.installPoolsLocked(resolvedHosts)
	cm.resolutionGeneration++

	if slices.Equal(cm.remoteAddrs, resolvedAddrs) {
		logger.Debug("ConnectionManager: Address resolution unchanged", "server", cm.serverName, "backends", len(resolvedAddrs))
		// Membership and ownership checks were rebuilt even though the union stayed
		// unchanged: addresses can have moved between pools, or begun to overlap.
		return
	}

	newBackendHealth := make(map[string]*BackendHealth, len(resolvedAddrs))
	for _, addr := range resolvedAddrs {
		if health, ok := cm.backendHealth[addr]; ok {
			newBackendHealth[addr] = health
			continue
		}
		newBackendHealth[addr] = &BackendHealth{
			IsHealthy:   true,
			LastSuccess: time.Now(),
		}
	}

	logger.Info("ConnectionManager: Backend pool resolved", "server", cm.serverName, "previous", cm.remoteAddrs, "resolved", resolvedAddrs)

	cm.remoteAddrs = resolvedAddrs
	cm.backendHealth = newBackendHealth
}

// installPoolsLocked publishes membership and its ownership checks together. Retaining
// both colliding pools as usable would let PoolOfBackend pick the first pool's CA and
// configuredHostnamesOf accept the other pool's names. Refuse the affected pools,
// including their configured aliases and cached pins; unrelated pools remain available.
func (cm *ConnectionManager) installPoolsLocked(resolvedHosts map[string][]string) {
	cm.poolErrors = make(map[string]error)
	cm.backendErrors = make(map[string]error)
	owners := make(map[string]string)
	for _, p := range cm.pools {
		p.install(resolvedHosts)
		if !p.named {
			continue
		}
		for _, addr := range p.resolved {
			if owner, exists := owners[addr]; exists && owner != p.name {
				err := fmt.Errorf("%w: %s is in %q and %q", ErrAmbiguousBackendPool, addr, owner, p.name)
				cm.poolErrors[owner], cm.poolErrors[p.name] = err, err
				logger.Error("ConnectionManager: refusing overlapping backend pools", "server", cm.serverName, "error", err)
			} else {
				owners[addr] = p.name
			}
		}
	}
	for _, p := range cm.pools {
		if err := cm.poolErrors[p.name]; err != nil {
			for _, addr := range p.configured {
				cm.backendErrors[addr] = err
			}
			for _, addr := range p.resolved {
				cm.backendErrors[addr] = err
			}
		}
	}
}

// resolvePoolEntries resolves one configured backend address into the pool entries it
// contributes, or nil if the name does not resolve.
//
// Every address of one family is kept: several A records under one name are that many
// distinct machines, and each has to be its own pool member. Only one family is kept,
// though — the A and AAAA records of one name are two routes to the SAME machine, and
// admitting both would give it two health entries and twice its share of the hash ring.
//
// Which family, on a first resolution, is the one net.LookupIP ranks first: RFC 6724
// ordering against this host's own source addresses, i.e. the address a dial of the name
// would pick, so the pool entry is reachable from here. That ordering depends on host
// state, so it is decided ONCE per name and then pinned: previous holds the entries the
// last resolution produced, and as long as the name still answers with that family, the
// family is kept. Without the pin a change in this host's connectivity would flip every
// dual-stack name to the other family at once, replacing the whole pool and rehashing
// every user off their backend.
//
// The pin is per host, so two proxies with different connectivity can still settle on
// different families for the same dual-stack name and build different hash rings. That
// is logged below; prefer single-family names for backends behind a clustered proxy.
// pinnedFamilyIsIPv4 reports the family a previous resolution settled on for a name.
// Entries are host:port or bare IPs; anything unparseable means there is nothing to pin.
func pinnedFamilyIsIPv4(previous []string) (isIPv4 bool, ok bool) {
	for _, entry := range previous {
		host := entry
		if h, _, err := net.SplitHostPort(entry); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip != nil {
			return ip.To4() != nil, true
		}
	}
	return false, false
}

func anyOfFamily(ips []net.IP, isIPv4 bool) bool {
	for _, ip := range ips {
		if (ip.To4() != nil) == isIPv4 {
			return true
		}
	}
	return false
}

func hasBothFamilies(ips []net.IP) bool {
	return anyOfFamily(ips, true) && anyOfFamily(ips, false)
}

func familyName(isIPv4 bool) string {
	if isIPv4 {
		return "ipv4"
	}
	return "ipv6"
}

func resolvePoolEntries(addr string, previous []string) []string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil
	}
	return resolvePoolEntriesFrom(addr, previous, ips)
}

// resolvePoolEntriesFrom is the pure half of resolvePoolEntries: the family choice and
// the entry list, given an already-resolved address set.
func resolvePoolEntriesFrom(addr string, previous []string, ips []net.IP) []string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		// If no port specified, assume it's just a host
		port = ""
	}

	preferIPv4 := ips[0].To4() != nil
	if pinned, ok := pinnedFamilyIsIPv4(previous); ok && anyOfFamily(ips, pinned) {
		preferIPv4 = pinned
	} else if hasBothFamilies(ips) {
		logger.Warn("ConnectionManager: Backend name is dual-stack - keeping one address family",
			"backend", addr, "family", familyName(preferIPv4),
			"detail", "the family is chosen per proxy host, so proxies with different connectivity can route this backend differently")
	}

	var entries []string
	for _, ip := range ips {
		if (ip.To4() != nil) != preferIPv4 {
			continue
		}
		if port == "" {
			entries = append(entries, ip.String())
			continue
		}
		entries = append(entries, net.JoinHostPort(ip.String(), port))
	}

	// A server that rotates a name's records answers in a different order every time;
	// sorting keeps a re-resolution that found nothing new from reading as a pool change.
	slices.Sort(entries)

	return entries
}

func (cm *ConnectionManager) dial(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: cm.connectTimeout,
		Control: cm.RefuseMaintenanceDial,
	}

	// Resolve the address to ensure proper IPv6 formatting
	resolvedAddr := cm.resolveAddress(addr)
	if resolvedAddr != addr {
		logger.Debug("ConnectionManager: Resolved address", "addr", addr, "resolved", resolvedAddr)
	}

	logger.Debug("Attempting to connect to backend", "addr", resolvedAddr)

	var conn net.Conn
	var err error
	// Only use implicit TLS if remoteTLS is enabled AND StartTLS is not being used
	// When StartTLS is enabled, the protocol layer will handle the TLS upgrade
	if cm.remoteTLS && !cm.remoteTLSUseStartTLS {
		// Verified by the backend's configured name (or its address), not by the formatted
		// dial target alone; see BackendClientTLS.
		tlsConfig := cm.BackendClientTLS(cm.remoteTLSVerify, addr)
		conn, err = tls.DialWithDialer(dialer, "tcp", resolvedAddr, tlsConfig)
	} else {
		// Plain connection (either no TLS, or TLS will be negotiated via StartTLS)
		conn, err = dialer.DialContext(ctx, "tcp", resolvedAddr)
	}

	if err != nil {
		logger.Debug("ConnectionManager: Failed to connect", "addr", resolvedAddr, "error", err)
		return nil, err
	}

	// Log the actual local and remote addresses of the established connection
	logger.Debug("Connected to backend", "resolved_addr", resolvedAddr, "local", server.GetAddrString(conn.LocalAddr()), "remote", server.GetAddrString(conn.RemoteAddr()))

	return conn, nil
}

// resolveAddress resolves a single address to ensure proper IPv6 formatting
func (cm *ConnectionManager) resolveAddress(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// If no port specified, just return as-is (shouldn't happen in our case)
		return addr
	}

	// Try to resolve the host to IP
	ips, err := net.LookupIP(host)
	if err != nil {
		// If resolution fails, return the original address
		return addr
	}

	// Use the first resolved IP and rejoin with the port
	if len(ips) > 0 {
		return net.JoinHostPort(ips[0].String(), port)
	}

	return addr
}

func (cm *ConnectionManager) dialWithProxy(ctx context.Context, addr, clientIP string, clientPort int, serverIP string, serverPort int, routingInfo *UserRoutingInfo) (net.Conn, error) {
	route, err := cm.bindForDial(routingInfo, addr)
	if err != nil {
		return nil, err
	}
	// For PROXY protocol, we need to establish plain TCP connection first
	dialer := &net.Dialer{
		Timeout: cm.connectTimeout,
		Control: route.Control,
	}

	// Resolve the address to ensure proper IPv6 formatting
	resolvedAddr := cm.resolveAddress(addr)
	if resolvedAddr != addr {
		logger.Debug("ConnectionManager: Resolved address", "addr", addr, "resolved", resolvedAddr)
	}

	logger.Debug("Attempting to connect to backend", "addr", resolvedAddr)

	// Always establish plain TCP connection first
	conn, err := dialer.DialContext(ctx, "tcp", resolvedAddr)
	if err != nil {
		logger.Warn("ConnectionManager: TCP dial failed", "addr", resolvedAddr, "original_addr", addr, "error", err, "server", cm.serverName)
		return nil, err
	}

	logger.Debug("Connected to backend", "resolved_addr", resolvedAddr, "local", server.GetAddrString(conn.LocalAddr()), "remote", server.GetAddrString(conn.RemoteAddr()))

	// Determine effective settings for this connection.
	// Default to the connection manager's global settings.
	useProxyProtocol := cm.remoteUseProxyProtocol
	remoteTLS, remoteTLSUseStartTLS, remoteTLSVerify := cm.backendTLSSettings(routingInfo, addr)

	// A route carries its own backend-leg settings for the backend the remote lookup named,
	// and for every member of the named pool routing confined it to (which stamped that
	// pool's settings on it). Otherwise the proxy server's own settings apply.
	if routingInfo.UsesRouteSettings(addr) {
		useProxyProtocol = routingInfo.RemoteUseProxyProtocol
		logger.Debug("Using remotelookup settings", "addr", addr, "remoteTLS", remoteTLS, "remoteTLSUseStartTLS", remoteTLSUseStartTLS, "remoteTLSVerify", remoteTLSVerify, "useProxyProtocol", useProxyProtocol)
	} else {
		logger.Debug("Using global settings", "addr", addr, "remoteTLS", remoteTLS, "remoteTLSUseStartTLS", remoteTLSUseStartTLS, "remoteTLSVerify", remoteTLSVerify, "useProxyProtocol", useProxyProtocol)
	}

	// If we have client IP information and PROXY protocol is enabled, send PROXY protocol header
	if useProxyProtocol && clientIP != "" && clientPort > 0 && serverIP != "" && serverPort > 0 {
		logger.Debug("ConnectionManager: Sending PROXY v2 header", "client_ip", clientIP, "client_port", clientPort, "server_ip", serverIP, "server_port", serverPort)

		// Extract JA4 fingerprint and session ID from routingInfo if available
		var ja4Fingerprint, proxySessionID string
		if routingInfo != nil {
			// Extract JA4 fingerprint from client connection
			if routingInfo.ClientConn != nil {
				// With SoraConn, no unwrapping needed - direct access
				if ja4Conn, ok := routingInfo.ClientConn.(interface{ GetJA4Fingerprint() (string, error) }); ok {
					fingerprint, err := ja4Conn.GetJA4Fingerprint()
					if err == nil && fingerprint != "" {
						ja4Fingerprint = fingerprint
						logger.Debug("ConnectionManager: Extracted JA4 fingerprint for PROXY v2 TLV", "ja4", fingerprint)
					}
				}
			}
			// Extract proxy session ID for end-to-end tracing
			if routingInfo.ProxySessionID != "" {
				proxySessionID = routingInfo.ProxySessionID
				logger.Debug("ConnectionManager: Including proxy session ID in PROXY v2 TLV", "session_id", proxySessionID)
			}
		}

		err = cm.writeProxyV2HeaderWithTLVs(conn, clientIP, clientPort, serverIP, serverPort, ja4Fingerprint, proxySessionID)
		if err != nil {
			conn.Close()
			logger.Debug("ConnectionManager: Failed to send PROXY protocol header", "addr", addr, "error", err)
			return nil, fmt.Errorf("failed to send PROXY protocol header: %w", err)
		}
	} else if useProxyProtocol {
		logger.Debug("ConnectionManager: PROXY protocol enabled but not sent (missing client/server info)", "client_ip", clientIP, "client_port", clientPort, "server_ip", serverIP, "server_port", serverPort)
	}

	// Now establish TLS if required (only for implicit TLS, not StartTLS)
	// When StartTLS is enabled, the protocol layer will handle TLS upgrade
	if remoteTLS && !remoteTLSUseStartTLS {
		tlsConfig := route.TLSConfig(remoteTLSVerify, conn)
		logger.Debug("Starting TLS handshake", "addr", addr, "InsecureSkipVerify", !remoteTLSVerify, "server_name", tlsConfig.ServerName)
		tlsConn := tls.Client(conn, tlsConfig)

		// Set a deadline for the TLS handshake
		if err := conn.SetDeadline(time.Now().Add(cm.connectTimeout)); err != nil {
			conn.Close()
			logger.Debug("ConnectionManager: Failed to set TLS handshake deadline", "addr", addr, "error", err)
			return nil, fmt.Errorf("failed to set TLS deadline: %w", err)
		}

		err = tlsConn.Handshake()
		if err != nil {
			conn.Close()
			logger.Debug("ConnectionManager: TLS handshake failed", "addr", addr, "error", err)
			logger.Debug("ConnectionManager: TLS handshake was using InsecureSkipVerify=%t, no client certificates", !remoteTLSVerify)
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}

		// Clear the deadline after successful handshake
		if err := conn.SetDeadline(time.Time{}); err != nil {
			logger.Debug("ConnectionManager: Warning: failed to clear TLS deadline", "addr", addr, "error", err)
		}

		return tlsConn, nil
	}

	if remoteTLS && remoteTLSUseStartTLS {
		return &backendRouteConn{Conn: conn, route: route}, nil
	}
	return conn, nil
}

// writeProxyV2HeaderWithTLVs writes a PROXY protocol v2 header with optional TLV extensions
func (cm *ConnectionManager) writeProxyV2HeaderWithTLVs(conn net.Conn, clientIP string, clientPort int, serverIP string, serverPort int, ja4Fingerprint, proxySessionID string) error {
	// Build TLVs map if we have a JA4 fingerprint or session ID
	var tlvs map[byte][]byte
	if ja4Fingerprint != "" || proxySessionID != "" {
		tlvs = make(map[byte][]byte)
		if ja4Fingerprint != "" {
			tlvs[0xE0] = []byte(ja4Fingerprint) // TLVTypeJA4Fingerprint
			logger.Debug("PROXY: Including JA4 fingerprint in PROXY v2 TLV", "ja4", ja4Fingerprint)
		}
		if proxySessionID != "" {
			tlvs[0xE1] = []byte(proxySessionID) // TLVTypeProxySessionID
			logger.Debug("PROXY: Including proxy session ID in PROXY v2 TLV", "session_id", proxySessionID)
		}
	}

	// PROXY v2 signature
	header := make([]byte, 16)
	copy(header[0:12], []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A})

	// Version and Command (byte 12): version=2, command=PROXY
	header[12] = 0x21 // version=2 (bits 7-4), command=1/PROXY (bits 3-0)

	// Parse IPs to determine address family
	clientIPNet := net.ParseIP(clientIP)
	serverIPNet := net.ParseIP(serverIP)

	if clientIPNet == nil || serverIPNet == nil {
		return fmt.Errorf("invalid IP addresses: client=%s, server=%s", clientIP, serverIP)
	}

	var addressData []byte
	var addressFamily byte
	var transportProtocol byte = 0x1 // TCP

	// Determine if IPv4 or IPv6
	clientIPv4 := clientIPNet.To4()
	serverIPv4 := serverIPNet.To4()

	if clientIPv4 != nil && serverIPv4 != nil {
		// IPv4
		addressFamily = 0x1 // AF_INET
		addressData = make([]byte, 12)
		copy(addressData[0:4], clientIPv4)
		copy(addressData[4:8], serverIPv4)
		// Client port (big endian)
		addressData[8] = byte(clientPort >> 8)
		addressData[9] = byte(clientPort & 0xFF)
		// Server port (big endian)
		addressData[10] = byte(serverPort >> 8)
		addressData[11] = byte(serverPort & 0xFF)
	} else {
		// IPv6
		addressFamily = 0x2 // AF_INET6
		clientIPv6 := clientIPNet.To16()
		serverIPv6 := serverIPNet.To16()
		addressData = make([]byte, 36)
		copy(addressData[0:16], clientIPv6)
		copy(addressData[16:32], serverIPv6)
		// Client port (big endian)
		addressData[32] = byte(clientPort >> 8)
		addressData[33] = byte(clientPort & 0xFF)
		// Server port (big endian)
		addressData[34] = byte(serverPort >> 8)
		addressData[35] = byte(serverPort & 0xFF)
	}

	// Encode TLVs if present
	var tlvData []byte
	if len(tlvs) > 0 {
		for tlvType, tlvValue := range tlvs {
			tlvLen := len(tlvValue)
			// TLV format: Type (1 byte) + Length (2 bytes, big endian) + Value
			tlvData = append(tlvData, tlvType)
			tlvData = append(tlvData, byte(tlvLen>>8))
			tlvData = append(tlvData, byte(tlvLen&0xFF))
			tlvData = append(tlvData, tlvValue...)
		}
	}

	// Address family and protocol (byte 13)
	header[13] = (addressFamily << 4) | transportProtocol

	// Length (bytes 14-15, big endian) - includes address data + TLV data
	dataLen := len(addressData) + len(tlvData)
	header[14] = byte(dataLen >> 8)
	header[15] = byte(dataLen & 0xFF)

	// Combine header, address data, and TLV data
	proxyHeader := append(header, addressData...)
	proxyHeader = append(proxyHeader, tlvData...)

	// Send the header
	_, err := conn.Write(proxyHeader)
	if err != nil {
		return fmt.Errorf("failed to write PROXY v2 header: %w", err)
	}

	if ja4Fingerprint != "" {
		logger.Debug("PROXY: Sent PROXY v2 header with JA4 TLV to backend", "backend", server.GetAddrString(conn.RemoteAddr()), "client_ip", clientIP, "client_port", clientPort, "server_ip", serverIP, "server_port", serverPort, "ja4", ja4Fingerprint)
	} else {
		logger.Debug("PROXY: Sent PROXY v2 header to backend", "backend", server.GetAddrString(conn.RemoteAddr()), "client_ip", clientIP, "client_port", clientPort, "server_ip", serverIP, "server_port", serverPort)
	}

	return nil
}

// ConnectToSpecificWithContext attempts to connect to a specific server address with proper context propagation
func (cm *ConnectionManager) ConnectToSpecificWithContext(ctx context.Context, addr string) (net.Conn, error) {
	// Check if the address is in our list
	if !cm.HasBackend(addr) {
		return nil, fmt.Errorf("address %s not in remote addresses list", addr)
	}

	return cm.dial(ctx, addr)
}

// IsRemoteTLS returns whether remote connections use TLS
func (cm *ConnectionManager) IsRemoteTLS() bool {
	return cm.remoteTLS
}

// IsRemoteTLSVerifyEnabled returns whether TLS verification is enabled
func (cm *ConnectionManager) IsRemoteTLSVerifyEnabled() bool {
	return cm.remoteTLSVerify
}

// GetConnectTimeout returns the configured connection timeout
func (cm *ConnectionManager) GetConnectTimeout() time.Duration {
	return cm.connectTimeout
}

const (
	// maxConnectAttempts caps how many dials one ConnectWithProxy call is given budget
	// for, so a broadly dead pool cannot stretch a single login to len(pool) x connect_timeout.
	maxConnectAttempts = 3

	// defaultConnectBudgetPerDial bounds a manager configured without a connect timeout,
	// where net.Dialer imposes no per-dial limit of its own.
	defaultConnectBudgetPerDial = 30 * time.Second
)

// ConnectBudget returns the overall deadline a caller should put around one
// ConnectWithProxy call. connect_timeout is a per-dial budget (net.Dialer.Timeout) and
// ConnectWithProxy dials the preferred backend and then falls back through the pool, so a
// deadline of one connect_timeout lets a black-holed backend spend the whole budget and
// leaves every fallback dial to fail instantly on an already-expired context.
func (cm *ConnectionManager) ConnectBudget() time.Duration {
	perDial := cm.connectTimeout
	if perDial <= 0 {
		perDial = defaultConnectBudgetPerDial
	}

	cm.healthMu.RLock()
	attempts := len(cm.remoteAddrs) + 1 // preferred dial plus one round-robin dial per backend
	cm.healthMu.RUnlock()

	if attempts > maxConnectAttempts {
		attempts = maxConnectAttempts
	}

	return perDial * time.Duration(attempts)
}

// HasRouting returns true if a user routing lookup is configured.
func (cm *ConnectionManager) HasRouting() bool {
	return cm.routingLookup != nil
}

// LookupUserRoute performs a user routing lookup if configured.
// Note: This is routing-only lookup, so password is empty. clientIP is the real
// client's IP, the remotelookup URL's $ip placeholder.
func (cm *ConnectionManager) LookupUserRoute(ctx context.Context, email, clientIP string) (*UserRoutingInfo, error) {
	if !cm.HasRouting() || email == "" {
		return nil, nil
	}
	// Use routeOnly=true for LMTP routing lookups (no authentication, only routing info needed)
	info, authResult, err := cm.routingLookup.LookupUserRouteWithClientIP(ctx, email, "", clientIP, true)
	if err != nil {
		return nil, err
	}
	if authResult == AuthUserNotFound {
		return nil, nil
	}
	return info, nil
}

// RouteParams holds all parameters needed to determine a backend route.
type RouteParams struct {
	Ctx                   context.Context
	Username              string
	ClientIP              string // Real client IP (PROXY header source when present), the lookup's $ip
	Protocol              string // "imap", "pop3", "managesieve", "lmtp"
	IsRemoteLookupAccount bool
	RoutingInfo           *UserRoutingInfo
	ConnManager           *ConnectionManager
	EnableAffinity        bool
	ProxyName             string // "IMAP Proxy", "POP3 Proxy", etc. for logging
}

// RouteResult holds the outcome of a routing decision.
type RouteResult struct {
	PreferredAddr       string
	RoutingMethod       string
	IsRemoteLookupRoute bool
	Pool                string           // Named pool the route is confined to ("" for a flat list or an explicit server)
	RoutingInfo         *UserRoutingInfo // Can be updated by the lookup
}

// DetermineRoute centralizes the logic for choosing a backend server.
// The precedence is: RemoteLookup server > Affinity > Consistent Hash > Round-robin.
//
// Everything below the explicit-server step is confined to ONE pool: the one the lookup
// answer named, or the default pool when it named none. A route that names a pool this
// proxy lacks, or names none where no pool is the default, is returned as an error that
// the caller MUST turn into a connection failure: the user is never spilled into another
// pool's backends, where the account does not exist.
func DetermineRoute(params RouteParams) (RouteResult, error) {
	result := RouteResult{
		RoutingMethod: "consistent_hash", // Default: consistent hashing
		RoutingInfo:   params.RoutingInfo,
	}
	cm := params.ConnManager

	// 1. Try routing lookup first, only if not already available from auth
	if result.RoutingInfo == nil && cm.HasRouting() {
		// Use remotelookup timeout for routing lookup (accounts for dial + TLS + HTTP)
		lookupTimeout := cm.GetRemoteLookupTimeout()
		routingCtx, routingCancel := context.WithTimeout(params.Ctx, lookupTimeout)
		var lookupErr error
		result.RoutingInfo, lookupErr = cm.LookupUserRoute(routingCtx, params.Username, params.ClientIP)
		routingCancel()
		if lookupErr != nil && cm.HasNamedPools() {
			// No answer is no pool: routing on would put the user in the default pool,
			// where the account need not live, and drop their affinity in the real one.
			logger.Warn("Routing lookup failed - refusing to route without a pool", "proxy", params.ProxyName, "user", params.Username, "error", lookupErr)
			return result, fmt.Errorf("%w: %w", ErrRouteLookupFailed, lookupErr)
		}
		if lookupErr != nil {
			logger.Debug("Routing lookup failed, falling back to affinity", "proxy", params.ProxyName, "user", params.Username, "error", lookupErr)
		}
	}

	if result.RoutingInfo != nil && result.RoutingInfo.ServerAddress != "" && params.ConnManager.InMaintenance(result.RoutingInfo.ServerAddress) {
		// The remote-lookup-specified backend is in maintenance: route this user as in
		// auth-only mode (affinity, consistent hash, round-robin). The routing info is
		// copied, not edited — it may be a lookup-cache entry other sessions share, and the
		// pin must come back when maintenance ends.
		logger.Info("Remote lookup backend in maintenance - routing normally", "proxy", params.ProxyName, "user", params.Username, "backend", result.RoutingInfo.ServerAddress)
		// With named pools the user stays among the pinned backend's own siblings.
		// An unowned pin has no safe detour, even when a default pool is configured.
		routed := *result.RoutingInfo
		routed.ServerAddress = ""
		routed.AuthOnlyMode = true
		routed.PoolName = cm.PoolOfBackend(result.RoutingInfo.ServerAddress)
		if cm.HasNamedPools() && routed.PoolName == "" {
			return result, fmt.Errorf("%w: pinned backend in maintenance has no pool", ErrRouteLookupFailed)
		}
		result.RoutingInfo = &routed
	}

	if result.RoutingInfo != nil && result.RoutingInfo.ServerAddress != "" {
		// restrict_to_pool (SSRF defense): only honor the remote-lookup-specified backend
		// if it is in the configured pool. Otherwise fall through to in-pool routing below,
		// so the proxy never dials an attacker-chosen host. AllowRemoteLookupBackend logs
		// the refusal and is a no-op (always true) when the feature is disabled.
		if cm.AllowRemoteLookupBackend(result.RoutingInfo.ServerAddress) {
			// Use server address from routing info (remotelookup specified backend)
			result.PreferredAddr = result.RoutingInfo.ServerAddress
			logger.Debug("Using routing lookup", "proxy", params.ProxyName, "user", params.Username, "server", result.PreferredAddr)
			result.RoutingMethod = "remotelookup"
			result.IsRemoteLookupRoute = true
			binding, err := cm.BindBackendRoute("", result.PreferredAddr)
			if err != nil {
				return result, err
			}
			boundInfo := *result.RoutingInfo
			boundInfo.backendRoute = binding
			result.RoutingInfo = &boundInfo
			return result, nil
		}
		// Blocked out-of-pool address (logged in AllowRemoteLookupBackend): drop it so
		// the affinity and consistent-hash steps below still run and the user is routed
		// to a valid in-pool backend instead of being stranded on a single rejected route.
		if cm.HasNamedPools() {
			return result, fmt.Errorf("%w: pinned backend is outside the configured pools", ErrRouteLookupFailed)
		}
		result.RoutingInfo.ServerAddress = ""
	}

	// 2. The pool the rest of the decision is confined to.
	pool, err := cm.routePool(params, &result)
	if err != nil {
		return result, err
	}

	// 3. Cluster-wide affinity, honored only inside the pool.
	// Note: For auth-only remotelookup (IsRemoteLookupAccount=true but ServerAddress=""),
	// we still use affinity/consistent-hash (remotelookup only handled auth, not routing)
	if params.EnableAffinity {
		affinityMgr := cm.GetAffinityManager()
		if affinityMgr != nil && params.Protocol != "" {
			result.PreferredAddr, result.RoutingMethod = resolveAffinityRoute(params, pool, affinityMgr)
		}
	}

	// 4. If no affinity, try consistent hashing (deterministic, no race condition)
	if result.PreferredAddr == "" && params.Username != "" {
		if backend := cm.hashInPool(pool, params.Username); backend != "" {
			result.PreferredAddr = backend
			result.RoutingMethod = "consistent_hash"
			logger.Info("Using consistent hash", "proxy", params.ProxyName, "user", params.Username, "pool", pool.name, "backend", result.PreferredAddr)
		} else {
			// All backends unhealthy in consistent hash, fall back to round-robin
			result.RoutingMethod = "roundrobin"
			logger.Info("All consistent hash backends unhealthy - falling back to round-robin", "proxy", params.ProxyName, "user", params.Username, "pool", pool.name)
		}
	}

	return result, nil
}

// routePool resolves the pool a route is confined to and stamps a named pool's name and
// settings on the routing info, so the dial and the session use that pool's backend-leg
// configuration. A flat-list manager ignores a pool name in the answer with a warning:
// that is what a proxy without pools did before pools existed, and it lets binaries and
// configs roll out independently.
func (cm *ConnectionManager) routePool(params RouteParams, result *RouteResult) (*backendPool, error) {
	info := result.RoutingInfo
	if !cm.HasNamedPools() {
		if info != nil && info.PoolName != "" {
			logger.Warn("Lookup answer names a pool but this proxy has no [[pool]] blocks - using remote_addrs", "proxy", params.ProxyName, "user", params.Username, "pool", info.PoolName)
			info.PoolName = ""
		}
		return cm.defaultPool, nil
	}

	name := ""
	if info != nil {
		name = info.PoolName
	}
	pool, err := cm.poolByName(name)
	if err != nil {
		metrics.ProxyPoolRoute.WithLabelValues(params.Protocol, PoolRouteLabel(name, err), poolRouteOutcome(err)).Inc()
		logger.Error("No backend pool for route - refusing to route elsewhere", "proxy", params.ProxyName, "user", params.Username, "pool", name, "error", err)
		return nil, err
	}
	if info == nil {
		info = &UserRoutingInfo{}
		result.RoutingInfo = info
	}
	pool.stamp(info)
	result.Pool = pool.name
	metrics.ProxyPoolRoute.WithLabelValues(params.Protocol, pool.name, "routed").Inc()
	return pool, nil
}

// crossProtocolLister is implemented by the cluster affinity manager: every live affinity of
// a user's other protocols, in the order GetBackendAcrossProtocols consults them.
type crossProtocolLister interface {
	CrossProtocolBackends(username, protocol string) (backends, protocols []string)
}

// crossProtocolInPool picks, among the user's affinities of other protocols, the first whose
// host is a member of pool, resolved to this proxy's address for it. first is the one
// GetBackendAcrossProtocols returned; the others are only known through crossProtocolLister.
// An entry outside the pool is passed over, not deleted: it is that protocol's to correct when
// it routes the user, and what looks outside the pool here may be the same host as another
// node resolved it (the other address family), whose deletion would be cluster-wide.
func crossProtocolInPool(params RouteParams, pool *backendPool, affinityMgr AffinityManager, firstAddr, firstProtocol string) (affAddr, protocol, target string, ok bool) {
	backends, protocols := []string{firstAddr}, []string{firstProtocol}
	if l, isLister := affinityMgr.(crossProtocolLister); isLister {
		backends, protocols = l.CrossProtocolBackends(params.Username, params.Protocol)
	}
	for i, addr := range backends {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return addr, protocols[i], addr, true // checked against the pool by the caller
		}
		if local, found := params.ConnManager.poolBackendByHost(pool, host); found {
			return addr, protocols[i], local, true
		}
		logger.Debug("Cross-protocol affinity host not in pool, passing over it",
			"proxy", params.ProxyName, "user", params.Username, "pool", pool.name,
			"affinity_addr", addr, "from_protocol", protocols[i])
	}
	return "", "", "", false
}

// resolveAffinityRoute attempts to find a healthy backend via affinity, including cross-protocol,
// inside the given pool. A same-protocol affinity outside the pool is deleted and the user is
// routed afresh: that is how a user moved between pools by the lookup API lands in the new one.
// A cross-protocol one outside the pool is passed over for the next (crossProtocolInPool), so a
// stale entry of one protocol cannot mask the user's good entry of another. If same-protocol
// affinity is stale (unhealthy), it deletes it and retries once to check cross-protocol
// affinities from other protocols that may have already failed over.
func resolveAffinityRoute(params RouteParams, pool *backendPool, affinityMgr AffinityManager) (preferredAddr, routingMethod string) {
	cm := params.ConnManager

	// Try affinity lookup (may retry once after deleting stale same-protocol affinity)
	for attempt := 0; attempt < 2; attempt++ {
		lastAddr, foundProtocol, found := affinityMgr.GetBackendAcrossProtocols(params.Username, params.Protocol)
		if !found {
			return "", ""
		}

		targetAddr := lastAddr

		// Cross-protocol: the first of the user's other protocols' affinities inside the
		// pool, resolved to this proxy's address for that host
		if foundProtocol != params.Protocol {
			var ok bool
			lastAddr, foundProtocol, targetAddr, ok = crossProtocolInPool(params, pool, affinityMgr, lastAddr, foundProtocol)
			if !ok {
				return "", ""
			}
		}

		// Check if the backend is still a member of the user's pool and not in maintenance.
		// It might have been removed from the config since the affinity was cached, or the
		// lookup may have moved the user to another pool. A backend in maintenance is
		// treated the same: the user is routed afresh, and the new affinity keeps them there
		// after maintenance ends (no stampede back).
		if !cm.poolHasBackend(pool, targetAddr) || cm.InMaintenance(targetAddr) {
			logger.Info("Cluster affinity backend not in the user's pool or in maintenance - deleting affinity", "proxy", params.ProxyName, "backend", lastAddr, "pool", pool.name, "user", params.Username, "protocol", foundProtocol)
			affinityMgr.DeleteBackend(params.Username, foundProtocol)

			if foundProtocol == params.Protocol {
				logger.Debug("Retrying affinity lookup after deleting out-of-pool same-protocol affinity",
					"proxy", params.ProxyName, "user", params.Username, "protocol", params.Protocol)
				continue
			}
			break
		}

		// Check if resolved backend is healthy (without auto-recovery for sticky failover)
		if cm.IsBackendHealthyForAffinity(targetAddr) {
			if foundProtocol == params.Protocol {
				logger.Info("Using cluster affinity", "proxy", params.ProxyName, "user", params.Username, "backend", targetAddr)
				return targetAddr, "affinity"
			}
			logger.Info("Using cross-protocol affinity for cache locality", "proxy", params.ProxyName, "user", params.Username, "backend", targetAddr, "from_protocol", foundProtocol, "to_protocol", params.Protocol)
			return targetAddr, "affinity_cross_protocol"
		}

		// Backend is unhealthy — delete the stale affinity
		logger.Info("Cluster affinity backend unhealthy - deleting affinity", "proxy", params.ProxyName, "backend", lastAddr, "user", params.Username, "protocol", foundProtocol)
		affinityMgr.DeleteBackend(params.Username, foundProtocol)

		// If we just deleted same-protocol affinity, retry to check cross-protocol
		// This enables: LMTP stale → delete → retry → find IMAP's updated affinity
		if foundProtocol == params.Protocol {
			logger.Debug("Retrying affinity lookup after deleting stale same-protocol affinity",
				"proxy", params.ProxyName, "user", params.Username, "protocol", params.Protocol)
			continue
		}

		// Deleted a cross-protocol affinity — don't retry (avoid cascading deletions)
		break
	}

	return "", ""
}

// UpdateAffinityAfterConnection updates affinity after a successful connection
// This should be called by proxies after establishing a backend connection
//
// With consistent hashing, affinity is primarily used to track failover:
// - If consistent hash placed user on backend A, no affinity is set (deterministic)
// - If backend A fails and user moves to backend B, affinity tracks the failover
// - Affinity ensures user stays on backend B even after A recovers (session continuity)
func UpdateAffinityAfterConnection(params RouteParams, connectedBackend string, wasAffinityRoute bool) {
	// Skip affinity updates only for remotelookup users with explicit backend routing
	// Auth-only remotelookup (ServerAddress="") should use affinity like regular users
	if params.IsRemoteLookupAccount && params.RoutingInfo != nil && params.RoutingInfo.ServerAddress != "" {
		// RemoteLookup explicitly specified backend - don't use affinity (remotelookup controls routing)
		return
	}

	cm := params.ConnManager
	affinityMgr := cm.GetAffinityManager()
	if affinityMgr == nil || params.Protocol == "" {
		return
	}

	// Get the consistent hash placement for this user, inside the pool it was routed in
	pool, err := cm.poolForRoute(params.RoutingInfo)
	if err != nil {
		return
	}
	consistentHashBackend := cm.hashInPool(pool, params.Username)

	// Check current affinity
	currentBackend, hasAffinity := affinityMgr.GetBackend(params.Username, params.Protocol)

	if !hasAffinity {
		// Always set affinity after a successful connection.
		// Even when the connected backend matches the consistent hash backend,
		// the affinity entry is needed for cross-protocol cache locality:
		// other protocol proxies (LMTP, POP3, etc.) discover this user's backend
		// via GetBackendAcrossProtocols and route to the same machine.
		affinityMgr.SetBackend(params.Username, connectedBackend, params.Protocol)
		if connectedBackend != consistentHashBackend {
			logger.Info("Set failover affinity", "proxy", params.ProxyName, "user", params.Username,
				"backend", connectedBackend, "consistent_hash", consistentHashBackend)
		} else {
			logger.Debug("Set affinity for cross-protocol discovery", "proxy", params.ProxyName, "user", params.Username, "backend", connectedBackend)
		}
	} else if currentBackend != connectedBackend {
		// Affinity exists but we connected to a different backend — update it
		affinityMgr.UpdateBackend(params.Username, currentBackend, connectedBackend, params.Protocol)
		if wasAffinityRoute {
			logger.Info("Updated affinity after failover", "proxy", params.ProxyName, "user", params.Username, "old", currentBackend, "new", connectedBackend)
		} else {
			logger.Info("Updated affinity to match connected backend", "proxy", params.ProxyName, "user", params.Username, "old", currentBackend, "new", connectedBackend)
		}
	}
	// else: connected backend matches existing affinity — nothing to do
}
