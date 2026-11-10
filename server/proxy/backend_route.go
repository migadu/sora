package proxy

import (
	"context"
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
	snapshot uint64
}

// BindBackendRoute binds addr to the named pool. With an empty poolName, an
// explicit pin uses its known owning pool; an unowned pin remains unrestricted.
// Callers selecting a default pool must pass that pool's name explicitly.
func (cm *ConnectionManager) BindBackendRoute(poolName, addr string) (*BackendRoute, error) {
	cm.healthMu.RLock()
	defer cm.healthMu.RUnlock()
	r := &BackendRoute{manager: cm, addr: addr, snapshot: cm.resolutionGeneration}
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
	target := normalizeHostPort(addr, cm.remotePort)
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
	r.manager.healthMu.RLock()
	defer r.manager.healthMu.RUnlock()
	if r.snapshot != r.manager.resolutionGeneration {
		return fmt.Errorf("%w: backend DNS snapshot changed", ErrBackendOutsidePool)
	}
	return nil
}

// Control checks the address of the socket actually being opened, after DNS
// resolution. Both the captured authorization and current ownership must agree.
func (r *BackendRoute) Control(network, address string, raw syscall.RawConn) error {
	if err := r.manager.RefuseMaintenanceDial(network, address, raw); err != nil {
		return err
	}
	return r.ValidateDestination(address)
}

// ValidateDestination checks the connected peer too, after a TLS handshake.
func (r *BackendRoute) ValidateDestination(address string) error {
	if r.pool == nil {
		return nil
	}
	target := normalizeHostPort(address, r.manager.remotePort)
	r.manager.healthMu.RLock()
	defer r.manager.healthMu.RUnlock()
	if !r.allowed[target] || !slices.Contains(r.pool.resolved, target) {
		return fmt.Errorf("%w: %s is not authorized by pool %q", ErrBackendOutsidePool, address, r.pool.name)
	}
	return nil
}

// DialContext dials only a destination authorized by this route's binding.
func (r *BackendRoute) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: r.manager.connectTimeout, Control: r.Control}
	return dialer.DialContext(ctx, network, address)
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
