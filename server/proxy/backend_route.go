package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"slices"
	"syscall"
)

// BackendRoute binds a connection to the pool and DNS snapshot that authorized
// it. A later refresh cannot turn that route into a route to another pool.
// Its fields are immutable after construction.
type BackendRoute struct {
	manager  *ConnectionManager
	pool     *backendPool
	addr     string
	allowed  map[string]bool
	names    []string
	roots    *x509.CertPool
	snapshot uint64
}

// BindBackendRoute binds addr to the named pool. With an empty poolName, an
// explicit pin uses its known owning pool; an unowned pin remains unrestricted.
// Callers selecting a default pool must pass that pool's name explicitly.
func (cm *ConnectionManager) BindBackendRoute(poolName, addr string) (*BackendRoute, error) {
	cm.healthMu.RLock()
	defer cm.healthMu.RUnlock()
	r := &BackendRoute{manager: cm, addr: addr, snapshot: cm.resolutionGeneration, roots: cm.remoteTLSRootCAs}
	target := normalizeHostPort(addr, cm.remotePort)
	if err := cm.backendErrors[target]; err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	r.names = append(cm.configuredHostnamesOfLocked(addr), host)
	if !cm.HasNamedPools() {
		return r, nil
	}
	if poolName != "" {
		var ok bool
		r.pool, ok = cm.poolsByName[poolName]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownPool, poolName)
		}
	} else {
		target := normalizeHostPort(addr, cm.remotePort)
		for _, p := range cm.pools {
			if slices.Contains(p.configured, target) || slices.Contains(p.resolved, target) {
				r.pool = p
				break
			}
		}
	}
	if r.pool == nil {
		return r, nil
	}
	if err := cm.poolErrors[r.pool.name]; err != nil {
		return nil, err
	}
	r.roots = r.pool.rootCAs
	if !slices.Contains(r.pool.configured, target) && !slices.Contains(r.pool.resolved, target) {
		return nil, fmt.Errorf("%w: %s is not in pool %q", ErrBackendOutsidePool, addr, r.pool.name)
	}
	r.allowed = make(map[string]bool, len(r.pool.resolved))
	for _, member := range r.pool.resolved {
		r.allowed[normalizeHostPort(member, cm.remotePort)] = true
	}
	return r, nil
}

// PoolName identifies the named pool whose routing and trust apply to this leg.
func (r *BackendRoute) PoolName() string {
	if r.pool == nil {
		return ""
	}
	return r.pool.name
}

// SnapshotID changes whenever backend DNS ownership is republished. HTTP callers
// must include it and PoolName in their transport cache key: idle connection reuse
// does not pass through a socket dial guard.
func (r *BackendRoute) SnapshotID() uint64 { return r.snapshot }

// Validate refuses a route retained across a newly published DNS snapshot.
// HTTP callers use it before reuse, which bypasses the socket dial guard.
func (r *BackendRoute) Validate() error {
	if !r.manager.MaintenanceLoaded() {
		return errMaintenanceNotLoaded
	}
	if r.manager.InMaintenance(r.addr) {
		return errBackendInMaintenance
	}
	r.manager.healthMu.RLock()
	defer r.manager.healthMu.RUnlock()
	if r.snapshot != r.manager.resolutionGeneration {
		return fmt.Errorf("%w: backend DNS snapshot changed", ErrBackendOutsidePool)
	}
	if err := r.manager.backendErrors[normalizeHostPort(r.addr, r.manager.remotePort)]; err != nil {
		return err
	}
	if r.pool != nil {
		return r.manager.poolErrors[r.pool.name]
	}
	return nil
}

// Control checks the address of the socket actually being opened, after DNS
// resolution. Both the captured authorization and current ownership must agree.
func (r *BackendRoute) Control(_ string, address string, _ syscall.RawConn) error {
	return r.ValidateDestination(address)
}

// ValidateDestination rechecks the connected peer and pool under one DNS snapshot.
func (r *BackendRoute) ValidateDestination(address string) error {
	cm := r.manager
	if !cm.MaintenanceLoaded() {
		return errMaintenanceNotLoaded
	}
	if cm.InMaintenance(address) {
		return errBackendInMaintenance
	}
	return r.ValidatePoolDestination(address)
}

// ValidatePoolDestination rechecks only DNS ownership and pool collisions. A held
// transaction may finish on a backend entering maintenance, but must never reuse
// its connection after the destination changes pools.
func (r *BackendRoute) ValidatePoolDestination(address string) error {
	cm := r.manager
	target := normalizeHostPort(address, cm.remotePort)
	cm.healthMu.RLock()
	defer cm.healthMu.RUnlock()
	if err := cm.backendErrors[target]; err != nil {
		return err
	}
	if r.pool == nil {
		return nil
	}
	if err := cm.poolErrors[r.pool.name]; err != nil {
		return err
	}
	if !r.allowed[target] || !slices.Contains(r.pool.resolved, target) {
		return fmt.Errorf("%w: %s is not authorized by pool %q", ErrBackendOutsidePool, address, r.pool.name)
	}
	return nil
}

// TLSConfig keeps the roots and names that authorized the route. Passing the
// connected socket also validates its actual destination after the handshake.
func (r *BackendRoute) TLSConfig(verify bool, connected ...net.Conn) *tls.Config {
	cfg := r.manager.backendTLSConfig(verify)
	cfg.RootCAs = r.roots
	cfg.ServerName = r.names[0]
	cfg.InsecureSkipVerify = true // verification below also checks pool ownership
	checkCertificate := verifyBackendCertificate(r.roots, r.names)
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		var err error
		if len(connected) > 0 && connected[0] != nil {
			err = r.ValidateDestination(connected[0].RemoteAddr().String())
		} else {
			err = r.Validate()
		}
		if err != nil {
			return err
		}
		if verify {
			return checkCertificate(cs)
		}
		return nil
	}
	return cfg
}

func (cm *ConnectionManager) refusedBackendTLS(err error) *tls.Config {
	cfg := cm.backendTLSConfig(false)
	cfg.VerifyConnection = func(tls.ConnectionState) error { return err }
	return cfg
}

// BackendClientTLSForConn uses the binding retained by a STARTTLS socket.
func (cm *ConnectionManager) BackendClientTLSForConn(verify bool, addr string, conn net.Conn) *tls.Config {
	if bound, ok := conn.(*backendRouteConn); ok {
		return bound.route.TLSConfig(verify, conn)
	}
	route, err := cm.BindBackendRoute("", addr)
	if err != nil {
		return cm.refusedBackendTLS(err)
	}
	return route.TLSConfig(verify, conn)
}

// GetTLSConfigForConn preserves the manager's verification setting for STARTTLS.
func (cm *ConnectionManager) GetTLSConfigForConn(addr string, conn net.Conn) *tls.Config {
	if !cm.remoteTLS {
		return nil
	}
	return cm.BackendClientTLSForConn(cm.remoteTLSVerify, addr, conn)
}

// DialContext dials only a destination authorized by this route's binding.
func (r *BackendRoute) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: r.manager.connectTimeout, Control: r.Control}
	return dialer.DialContext(ctx, network, address)
}

// RecordDialOutcome feeds the outcome of a connection to this route's backend (TCP,
// PROXY header and TLS handshake; err nil on success) to the health that routing reads,
// for a caller that dials through its own transport instead of ConnectWithProxy (the
// User API proxy). It counts a pool member's dials as ConnectWithProxy does: a dial the
// proxy refused itself (maintenance, pool ownership) says nothing about the backend, and
// a failure counts only while the caller's context is live, as a dial its caller
// abandoned cannot be told from one the backend timed out. A backend outside the pools
// (a lookup pin) is not recorded: ConnectWithProxy keeps such pins in a record of their
// own (IsRemoteLookupBackendHealthy) to refuse them early, but the User API proxy dials a
// pin whatever its health, so nothing would read it.
func (r *BackendRoute) RecordDialOutcome(ctx context.Context, err error) {
	cm := r.manager
	if !cm.HasBackend(r.addr) {
		return
	}
	switch {
	case err == nil:
		cm.RecordConnectionSuccess(r.addr)
	case errors.Is(err, errBackendInMaintenance), errors.Is(err, errMaintenanceNotLoaded),
		errors.Is(err, ErrBackendOutsidePool), errors.Is(err, ErrAmbiguousBackendPool):
	case ctx.Err() == nil:
		cm.RecordConnectionFailure(r.addr)
	}
}

// BindRoutedBackend captures the same authorization a routed dial will use. Callers
// retaining a connection across requests must retain this binding as well: routing
// info can be replaced by the next request and DNS can change a destination's owner.
func (cm *ConnectionManager) BindRoutedBackend(info *UserRoutingInfo, addr string) (*BackendRoute, error) {
	return cm.bindForDial(info, addr)
}

func (cm *ConnectionManager) bindForDial(info *UserRoutingInfo, addr string) (*BackendRoute, error) {
	if info != nil && info.backendRoute != nil && info.backendRoute.addr == addr {
		return info.backendRoute, nil
	}
	if info.PoolRouted() {
		return cm.BindBackendRoute(info.PoolName, addr)
	}
	if cm.HasNamedPools() && !info.LookupRouted(addr) {
		pool, err := cm.poolForRoute(info)
		if err != nil {
			return nil, err
		}
		return cm.BindBackendRoute(pool.name, addr)
	}
	return cm.BindBackendRoute("", addr)
}

// backendRouteConn retains the authorization that opened a plaintext connection,
// so a subsequent STARTTLS upgrade can use that same pool and trust identity.
type backendRouteConn struct {
	net.Conn
	route *BackendRoute
}

func (c *backendRouteConn) Unwrap() net.Conn { return c.Conn }

func (c *backendRouteConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return fmt.Errorf("backend transport does not support half-close")
}
