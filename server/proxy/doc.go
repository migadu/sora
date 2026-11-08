// Package proxy provides connection management and load balancing for proxy servers.
//
// This package implements the core proxy infrastructure used by protocol-specific
// proxy packages (imapproxy, lmtpproxy, pop3proxy, managesieveproxy).
//
// Features:
//   - Multiple backend server support
//   - Consistent hashing for session affinity
//   - Round-robin load balancing
//   - Health-based backend selection
//   - Automatic failover to healthy backends
//   - Connection pooling and reuse
//   - Transparent protocol proxying
//
// # Architecture
//
//	Client → Proxy → ConnectionManager → Backend Server
//
// The ConnectionManager selects an appropriate backend based on:
//   - Backend health status
//   - Affinity method (consistent hash or round robin)
//   - User identity for session persistence
//
// # Named Pools
//
// A manager built with NewConnectionManagerWithPools routes by named backend pools
// ([[pool]] blocks): the remote-lookup answer names a pool, and affinity, consistent
// hashing and round-robin are all confined to that pool's members. A flat remote_addrs
// list is one unnamed default pool, so both kinds of manager take the same routing
// path. A route that names a pool the manager lacks, or names none where no pool is
// the default, is an error (ErrUnknownPool, ErrNoDefaultPool) the proxy turns into a
// temporary failure; it is never spilled into another pool's backends. A lookup pin to
// a backend in maintenance is routed among that backend's own pool (PoolOfBackend), or
// refused when it is in none. A rejected lookup pin likewise never guesses a named
// default pool.
//
// # Affinity Methods
//
// Consistent Hashing:
//   - Routes same user to same backend
//   - Preserves IMAP session state
//   - Better cache hit rates on backends
//
// Round Robin:
//   - Distributes load evenly
//   - No session affinity
//   - Better for stateless protocols
//
// # Usage
//
//	cm := proxy.NewConnectionManager(
//		[]string{"backend1:143", "backend2:143", "backend3:143"},
//		"consistent_hash",  // or "round_robin"
//		30*time.Second,     // connection timeout
//	)
//
//	// Connect to appropriate backend
//	conn, backend, err := cm.ConnectWithProxy(ctx, username, clientIP, clientPort, serverIP, serverPort, nil)
//	if err != nil {
//		// Handle error (all backends unhealthy?)
//	}
//	defer conn.Close()
//
//	// Proxy traffic bidirectionally
//	proxy.Relay(clientConn, conn)
//
// # Health Monitoring
//
// Backends are monitored continuously:
//   - Connection failures mark backend unhealthy
//   - Automatic recovery attempts
//   - Failed backends excluded from selection
//
// # Integration
//
// Used by:
//   - server/imapproxy: IMAP proxy server
//   - server/lmtpproxy: LMTP proxy server
//   - server/pop3proxy: POP3 proxy server
//   - server/managesieveproxy: ManageSieve proxy server
package proxy
