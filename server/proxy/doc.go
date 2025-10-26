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
