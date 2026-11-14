package config

import (
	"fmt"
	"net"
	"strconv"
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
	RemoteTLSUseStartTLS   bool  `toml:"remote_tls_use_starttls"` // LMTP/ManageSieve; IMAP/POP3/User API use implicit TLS
	RemoteTLSVerify        *bool `toml:"remote_tls_verify"`       // default true
	RemoteUseProxyProtocol bool  `toml:"remote_use_proxy_protocol"`
	RemoteUseIDCommand     bool  `toml:"remote_use_id_command"` // IMAP only
	RemoteUseXCLIENT       bool  `toml:"remote_use_xclient"`    // POP3/LMTP only
	RemoteUseUTF8          bool  `toml:"remote_use_utf8"`       // POP3 only; sora backends only
	// RemoteTLSCAFile is a PEM file of CA certificates this pool's backends are verified
	// against (private-CA or self-signed backends), on every proxy; empty = system roots.
	RemoteTLSCAFile string `toml:"remote_tls_ca_file"`
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
//   - a backend belongs to exactly one pool and appears once, whatever letter case or IP
//     spelling it is written with. A backend without a port stands for its host on every
//     proxy's remote_port, so it clashes with any other entry for that host; entries with
//     explicit, different ports may share a host (one pool per protocol on one machine);
//   - remote_tls_use_starttls only comes with remote_tls;
//   - at most one pool is the default;
//   - a proxy server lists remote_addrs OR the file declares pools, never both;
//   - a proxy server has a remote_port when a pool backend is written without a port;
//   - a proxy that routes users without a pool name has a default pool to route them
//     into: one that falls back to local users (lookup_local_users), and one without a
//     remote lookup at all, whose every user comes with no pool name.
func (c *Config) ValidatePools() error {
	if !c.HasPools() {
		return nil
	}

	names := make(map[string]bool, len(c.Pools))
	bareHosts := make(map[string]string)   // host -> pool, for backends written without a port
	portedHosts := make(map[string]string) // host -> first pool listing it with a port
	ported := make(map[string]string)      // host:port -> pool
	var portless []string                  // backends written without a port: each proxy's remote_port completes them
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
			host, port := poolBackendHost(b)
			if host == "" {
				return fmt.Errorf("[[pool]] %q: empty backend address", p.Name)
			}
			other, clash := bareHosts[host]
			if !clash {
				if port == "" {
					other, clash = portedHosts[host]
				} else {
					other, clash = ported[net.JoinHostPort(host, port)]
				}
			}
			if clash {
				if other == p.Name {
					return fmt.Errorf("[[pool]] %q: backend %q is listed more than once", p.Name, b)
				}
				return fmt.Errorf("[[pool]] %q: backend %q already belongs to pool %q", p.Name, b, other)
			}
			if port == "" {
				bareHosts[host] = p.Name
				portless = append(portless, b)
			} else {
				ported[net.JoinHostPort(host, port)] = p.Name
				if _, seen := portedHosts[host]; !seen {
					portedHosts[host] = p.Name
				}
			}
		}
		if p.RemoteTLSUseStartTLS && !p.RemoteTLS {
			return fmt.Errorf("[[pool]] %q: remote_tls_use_starttls = true needs remote_tls = true", p.Name)
		}
		if p.RemoteTLSCAFile != "" && !p.RemoteTLS {
			return fmt.Errorf("[[pool]] %q: remote_tls_ca_file needs remote_tls = true", p.Name)
		}
		if p.Default {
			defaults++
			if defaults > 1 {
				return fmt.Errorf("[[pool]] %q: only one pool may be default = true", p.Name)
			}
		}
	}

	// Match the startup path: stanzas with enabled = false are retained in the file,
	// but do not constrain the backend pools used by the servers that will run.
	for _, s := range c.GetAllServers() {
		if !strings.HasSuffix(s.Type, "_proxy") {
			continue
		}
		if len(s.RemoteAddrs) > 0 {
			return fmt.Errorf("server %q: remote_addrs cannot be combined with [[pool]] blocks; list its backends in a pool instead", s.Name)
		}
		if len(portless) > 0 {
			if port, err := s.GetRemotePort(); err == nil && port == 0 {
				return fmt.Errorf("server %q: remote_port is required, since pool backend %q has no port", s.Name, portless[0])
			}
		}
		if defaults == 0 {
			if s.RemoteLookup == nil || !s.RemoteLookup.Enabled {
				return fmt.Errorf("server %q: without remote_lookup every user comes with no pool name, which needs a pool with default = true", s.Name)
			}
			if s.RemoteLookup.ShouldLookupLocalUsers() {
				return fmt.Errorf("server %q: lookup_local_users = true needs a pool with default = true to route local users into", s.Name)
			}
		}
	}
	return nil
}

// poolBackendHost splits a pool backend address for the one-pool-per-backend check: the
// host lowercase, an IP in canonical form, without brackets; and the port, "" when none
// was given. A bare IPv6 literal is one host, not host:port.
func poolBackendHost(addr string) (host, port string) {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if addr == "" {
		return "", ""
	}
	host = addr
	if h, p, err := net.SplitHostPort(addr); err == nil {
		host, port = h, p
		if n, err := strconv.Atoi(p); err == nil {
			port = strconv.Itoa(n) // "0143" is port 143
		}
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	return host, port
}
