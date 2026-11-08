package config

import (
	"fmt"
	"net"
	"strings"
)

// PoolConfig is one named group of backend hosts, declared once per node as a `[[pool]]`
// block and shared by every proxy server in the file. The remote-lookup API names a pool
// in its answer ("pool": "sora1") and the proxy picks a member with the same
// affinity → consistent-hash → round-robin logic it applies to a flat remote_addrs list,
// confined to that pool. A one-member pool therefore behaves like an explicit server.
//
// Every block repeats the full backend-leg settings for its hosts; nothing is inherited
// from the [[server]] that dials them. A backend written without a port gets the dialing
// proxy's remote_port, which is what lets one block serve the IMAP, POP3, ManageSieve,
// LMTP and User API proxies alike.
type PoolConfig struct {
	Name     string   `toml:"name"`
	Backends []string `toml:"backends"`

	// Default marks the pool an answer WITHOUT a pool name is routed into: an auth-only
	// lookup answer, or a user found locally through lookup_local_users. At most one pool
	// may be the default. Without one such an answer is refused, so a lookup API that names
	// a pool for every user runs without any fallback at all.
	Default bool `toml:"default"`

	RemoteTLS              bool  `toml:"remote_tls"`
	RemoteTLSUseStartTLS   bool  `toml:"remote_tls_use_starttls"` // LMTP/ManageSieve only
	RemoteTLSVerify        *bool `toml:"remote_tls_verify"`       // default true
	RemoteUseProxyProtocol bool  `toml:"remote_use_proxy_protocol"`
	RemoteUseIDCommand     bool  `toml:"remote_use_id_command"` // IMAP only
	RemoteUseXCLIENT       bool  `toml:"remote_use_xclient"`    // POP3/LMTP only
	RemoteUseUTF8          bool  `toml:"remote_use_utf8"`       // POP3 only; sora backends only
}

// GetRemoteTLSVerify returns whether backend certificates are verified (default true).
func (p *PoolConfig) GetRemoteTLSVerify() bool {
	return p.RemoteTLSVerify == nil || *p.RemoteTLSVerify
}

// HasPools reports whether the file declares named backend pools.
func (c *Config) HasPools() bool {
	return len(c.Pools) > 0
}

// DefaultPool returns the pool marked default = true, or nil when there is none.
func (c *Config) DefaultPool() *PoolConfig {
	for i := range c.Pools {
		if c.Pools[i].Default {
			return &c.Pools[i]
		}
	}
	return nil
}

// ValidatePools checks the [[pool]] blocks and how the proxy servers relate to them:
//   - every pool has a name without whitespace, unique among pools, and at least one backend;
//   - a backend host belongs to exactly one pool (health and affinity are per address);
//   - at most one pool is the default;
//   - a proxy server lists remote_addrs OR the file declares pools, never both;
//   - a proxy that falls back to local users (lookup_local_users) has a default pool to
//     route them into, since such a user comes with no pool name.
func (c *Config) ValidatePools() error {
	if !c.HasPools() {
		return nil
	}

	names := make(map[string]bool, len(c.Pools))
	hosts := make(map[string]string)
	defaults := 0
	for i := range c.Pools {
		p := &c.Pools[i]
		if p.Name == "" {
			return fmt.Errorf("[[pool]] #%d: name is required", i+1)
		}
		if strings.ContainsAny(p.Name, " \t\r\n") {
			return fmt.Errorf("[[pool]] %q: name must not contain whitespace", p.Name)
		}
		if names[p.Name] {
			return fmt.Errorf("[[pool]] %q: declared more than once", p.Name)
		}
		names[p.Name] = true
		if len(p.Backends) == 0 {
			return fmt.Errorf("[[pool]] %q: backends is required (at least one host)", p.Name)
		}
		for _, b := range p.Backends {
			key := poolBackendKey(b)
			if key == "" {
				return fmt.Errorf("[[pool]] %q: empty backend address", p.Name)
			}
			if other, dup := hosts[key]; dup {
				return fmt.Errorf("[[pool]] %q: backend %q already belongs to pool %q", p.Name, b, other)
			}
			hosts[key] = p.Name
		}
		if p.Default {
			defaults++
			if defaults > 1 {
				return fmt.Errorf("[[pool]] %q: only one pool may be default = true", p.Name)
			}
		}
	}

	for _, s := range c.DynamicServers {
		if !strings.HasSuffix(s.Type, "_proxy") {
			continue
		}
		if len(s.RemoteAddrs) > 0 {
			return fmt.Errorf("server %q: remote_addrs cannot be combined with [[pool]] blocks; list its backends in a pool instead", s.Name)
		}
		if s.RemoteLookup != nil && s.RemoteLookup.ShouldLookupLocalUsers() && defaults == 0 {
			return fmt.Errorf("server %q: lookup_local_users = true needs a pool with default = true to route local users into", s.Name)
		}
	}
	return nil
}

// poolBackendKey identifies a backend for the one-pool-per-host check: lowercase, and
// host:port when a port is given (a bare IPv6 literal is one host, not host:port).
func poolBackendKey(addr string) string {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if addr == "" {
		return ""
	}
	if host, port, err := net.SplitHostPort(addr); err == nil {
		return net.JoinHostPort(host, port)
	}
	return addr
}
