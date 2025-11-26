package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/server"
)

// AffinityManager defines the interface for cluster-wide affinity management
type AffinityManager interface {
	GetBackend(username, protocol string) (string, bool)
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

// ConnectionManager manages connections to multiple remote servers with round-robin and failover
type ConnectionManager struct {
	serverName             string // Server name for logging
	remoteAddrs            []string
	remotePort             int // Default port for backends if not in address
	remoteTLS              bool
	remoteTLSUseStartTLS   bool // Use STARTTLS for backend connections (only relevant if remoteTLS is true)
	remoteTLSVerify        bool
	remoteUseProxyProtocol bool
	connectTimeout         time.Duration

	// Round-robin index (fallback when consistent hash not used)
	nextIndex atomic.Uint32

	// Consistent hashing for deterministic backend selection
	consistentHash *ConsistentHash

	// Backend health tracking
	healthMu      sync.RWMutex
	backendHealth map[string]*BackendHealth

	// User routing lookup
	routingLookup UserRoutingLookup

	// Affinity manager (optional, for cluster-wide affinity)
	affinityManager AffinityManager
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
	if len(remoteAddrs) == 0 {
		return nil, fmt.Errorf("no remote addresses provided")
	}

	// Normalize remote addresses to include default port if missing
	normalizedAddrs := make([]string, len(remoteAddrs))
	for i, addr := range remoteAddrs {
		normalizedAddrs[i] = normalizeHostPort(addr, remotePort)
	}

	backendHealth := make(map[string]*BackendHealth)

	// Initially mark all servers as healthy
	for _, addr := range normalizedAddrs {
		backendHealth[addr] = &BackendHealth{
			IsHealthy:   true,
			LastSuccess: time.Now(),
		}
	}

	// Initialize consistent hash ring with all backends
	consistentHash := NewConsistentHash(150) // 150 virtual nodes per backend
	for _, addr := range normalizedAddrs {
		consistentHash.AddBackend(addr)
	}

	cm := &ConnectionManager{
		serverName:             serverName,
		remoteAddrs:            normalizedAddrs,
		remotePort:             remotePort,
		remoteTLS:              remoteTLS,
		remoteTLSUseStartTLS:   remoteTLSUseStartTLS,
		remoteTLSVerify:        remoteTLSVerify,
		remoteUseProxyProtocol: remoteUseProxyProtocol,
		connectTimeout:         connectTimeout,
		consistentHash:         consistentHash,
		backendHealth:          backendHealth,
		routingLookup:          routingLookup,
	}

	logger.Debug("Connection manager: Initialized consistent hash ring", "prefix", cm.logPrefix(), "backends", len(normalizedAddrs))

	return cm, nil
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

// GetBackendByConsistentHash returns a backend for a username using consistent hashing
// Automatically excludes unhealthy backends and tries the next one in the ring
// Returns empty string if all backends are unhealthy
func (cm *ConnectionManager) GetBackendByConsistentHash(username string) string {
	if cm.consistentHash == nil {
		return ""
	}

	// Try to get a healthy backend from the consistent hash ring
	exclude := make(map[string]bool)

	// Try up to len(remoteAddrs) times (all backends)
	for i := 0; i < len(cm.remoteAddrs); i++ {
		backend := cm.consistentHash.GetBackendWithExclusions(username, exclude)
		if backend == "" {
			// No more backends available
			return ""
		}

		// Check if this backend is healthy
		if cm.IsBackendHealthy(backend) {
			return backend
		}

		// Backend unhealthy, exclude it and try next
		exclude[backend] = true
	}

	// All backends unhealthy
	return ""
}

// IsBackendHealthy checks if a backend is healthy based on detailed health tracking
// Returns true if healthy, false if marked unhealthy
// Auto-recovers backends after 1 minute of being marked unhealthy
func (cm *ConnectionManager) IsBackendHealthy(backend string) bool {
	cm.healthMu.RLock()
	health, exists := cm.backendHealth[backend]
	cm.healthMu.RUnlock()

	if !exists {
		// Backend not in our list, assume unhealthy
		return false
	}

	// Check if backend should auto-recover (1 minute since last failure)
	if !health.IsHealthy && time.Since(health.LastFailure) > 1*time.Minute {
		cm.healthMu.Lock()
		health.IsHealthy = true
		health.ConsecutiveFails = 0 // Reset consecutive failures
		cm.healthMu.Unlock()
		logger.Info("ConnectionManager: Auto-recovered backend after 1 minute", "backend", backend)
		return true
	}

	return health.IsHealthy
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
	cm.healthMu.Lock()
	defer cm.healthMu.Unlock()

	health, exists := cm.backendHealth[backend]
	if !exists {
		// Create health entry for new backend
		health = &BackendHealth{
			IsHealthy:        false,
			LastFailure:      time.Now(),
			FailureCount:     1,
			ConsecutiveFails: 1,
		}
		cm.backendHealth[backend] = health
		logger.Warn("ConnectionManager: Backend marked unhealthy after first failure", "backend", backend)
		return true
	}

	wasHealthy := health.IsHealthy
	health.FailureCount++
	health.ConsecutiveFails++
	health.LastFailure = time.Now()

	// Mark unhealthy after 3 consecutive failures
	if health.ConsecutiveFails >= 3 {
		health.IsHealthy = false
		if wasHealthy {
			logger.Warn("ConnectionManager: Backend marked unhealthy after consecutive failures", "backend", backend, "count", health.ConsecutiveFails)
			return true // Just became unhealthy
		}
	}

	return false
}

// AuthenticateAndRoute delegates to the routing lookup if available
func (cm *ConnectionManager) AuthenticateAndRoute(ctx context.Context, email, password string) (*UserRoutingInfo, AuthResult, error) {
	return cm.AuthenticateAndRouteWithOptions(ctx, email, password, false)
}

// AuthenticateAndRouteWithOptions performs authentication and routing with additional options
// routeOnly: if true, skip password validation and only return routing info (for master username auth)
func (cm *ConnectionManager) AuthenticateAndRouteWithOptions(ctx context.Context, email, password string, routeOnly bool) (*UserRoutingInfo, AuthResult, error) {
	return cm.AuthenticateAndRouteWithClientIP(ctx, email, password, "", routeOnly)
}

// AuthenticateAndRouteWithClientIP performs authentication and routing with client IP and additional options
// clientIP: client IP address to include in remotelookup URL (supports $ip placeholder)
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

// GetTLSConfig returns the TLS configuration for remote connections
// Used for StartTLS negotiation at the protocol layer
func (cm *ConnectionManager) GetTLSConfig() *tls.Config {
	if !cm.remoteTLS {
		return nil
	}
	return &tls.Config{
		InsecureSkipVerify: !cm.remoteTLSVerify,
		// Explicitly set empty certificates to prevent automatic client certificate presentation
		Certificates: []tls.Certificate{},
		// Disable client certificate authentication
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return nil, nil
		},
		// Disable renegotiation (not supported in TLS 1.3, causes errors)
		Renegotiation: tls.RenegotiateNever,
	}
}

// IsRemoteStartTLS returns whether remote connections should use StartTLS
func (cm *ConnectionManager) IsRemoteStartTLS() bool {
	return cm.remoteTLS && cm.remoteTLSUseStartTLS
}

// ConnectWithProxy attempts to connect to a remote server and sends PROXY protocol header
func (cm *ConnectionManager) ConnectWithProxy(ctx context.Context, preferredAddr, clientIP string, clientPort int, serverIP string, serverPort int, routingInfo *UserRoutingInfo) (net.Conn, string, error) {
	if preferredAddr != "" {
		conn, addr, err, fallback := cm.tryPreferredAddress(ctx, preferredAddr, clientIP, clientPort, serverIP, serverPort, routingInfo)
		if !fallback {
			// If no fallback is needed, we either succeeded or had a hard failure.
			return conn, addr, err
		}
		// If fallback is true, the connection failed but we should proceed to round-robin.
		// The error from tryPreferredAddress is logged but not returned to the client yet.
	}

	// Try all servers in round-robin order
	startIndex := cm.nextIndex.Add(1) - 1
	for i := 0; i < len(cm.remoteAddrs); i++ {
		idx := (startIndex + uint32(i)) % uint32(len(cm.remoteAddrs))
		addr := cm.remoteAddrs[idx]

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

		// Record failure in health tracking
		cm.RecordConnectionFailure(addr)
		logger.Debug("Failed to connect to backend", "addr", addr, "error", err)
	}

	return nil, "", fmt.Errorf("all remote servers are unavailable")
}

// tryPreferredAddress attempts to connect to a preferred address (from affinity or remotelookup).
// It returns the connection, address, and an error if it fails.
// The 'shouldFallback' boolean indicates if the caller should attempt round-robin.
func (cm *ConnectionManager) tryPreferredAddress(ctx context.Context, preferredAddr, clientIP string, clientPort int, serverIP string, serverPort int, routingInfo *UserRoutingInfo) (conn net.Conn, addr string, err error, shouldFallback bool) {
	isRemoteLookupRoute := routingInfo != nil && routingInfo.IsRemoteLookupAccount && routingInfo.ServerAddress == preferredAddr

	isInList := false
	for _, a := range cm.remoteAddrs {
		if a == preferredAddr {
			isInList = true
			break
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
	if err == nil {
		// Success! Record success in health tracking
		if isInList {
			cm.RecordConnectionSuccess(preferredAddr)
		}
		return conn, preferredAddr, nil, false // No fallback
	}

	// Connection failed. Mark it as unhealthy if it's in our managed list.
	if isInList {
		cm.RecordConnectionFailure(preferredAddr)
	}

	if isRemoteLookupRoute {
		// For remotelookup routes, do NOT fall back to round-robin.
		logger.Debug("ConnectionManager: Failed to connect to remotelookup-designated server. NOT falling back to round-robin.", "server", preferredAddr, "error", err)
		err = fmt.Errorf("failed to connect to remotelookup-designated server %s: %w", preferredAddr, err)
		return nil, "", err, false // No fallback
	}

	// For affinity-based connections, log the failure and indicate that we should fall back.
	logger.Debug("ConnectionManager: Failed to connect to preferred address. Falling back to round-robin.", "addr", preferredAddr, "error", err)
	return nil, "", err, true // Fallback
}

// ResolveAddresses resolves hostnames to IP addresses, expanding the address list
func (cm *ConnectionManager) ResolveAddresses() error {
	var resolvedAddrs []string
	newBackendHealth := make(map[string]*BackendHealth)

	for _, addr := range cm.remoteAddrs {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			// If no port specified, assume it's just a host
			host = addr
			port = ""
		}

		// Try to resolve the host
		ips, err := net.LookupIP(host)
		if err != nil {
			// If resolution fails, keep the original address
			resolvedAddrs = append(resolvedAddrs, addr)
			cm.healthMu.RLock()
			if health, ok := cm.backendHealth[addr]; ok {
				newBackendHealth[addr] = health
			}
			cm.healthMu.RUnlock()
			continue
		}

		// Add all resolved IPs
		for _, ip := range ips {
			var resolvedAddr string
			if port != "" {
				resolvedAddr = net.JoinHostPort(ip.String(), port)
			} else {
				resolvedAddr = ip.String()
			}
			resolvedAddrs = append(resolvedAddrs, resolvedAddr)

			// Preserve health status if we had it
			cm.healthMu.RLock()
			if health, ok := cm.backendHealth[resolvedAddr]; ok {
				newBackendHealth[resolvedAddr] = health
			} else {
				newBackendHealth[resolvedAddr] = &BackendHealth{
					IsHealthy:   true,
					LastSuccess: time.Now(),
				}
			}
			cm.healthMu.RUnlock()
		}
	}

	cm.healthMu.Lock()
	cm.remoteAddrs = resolvedAddrs
	cm.backendHealth = newBackendHealth
	cm.healthMu.Unlock()

	return nil
}

func (cm *ConnectionManager) dial(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: cm.connectTimeout,
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
		tlsConfig := &tls.Config{
			InsecureSkipVerify: !cm.remoteTLSVerify,
			// Explicitly set empty certificates to prevent automatic client certificate presentation
			Certificates: []tls.Certificate{},
			// Disable client certificate authentication
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return nil, nil
			},
			// Disable renegotiation (not supported in TLS 1.3, causes errors)
			Renegotiation: tls.RenegotiateNever,
		}
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
	// For PROXY protocol, we need to establish plain TCP connection first
	dialer := &net.Dialer{
		Timeout: cm.connectTimeout,
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
		logger.Debug("ConnectionManager: Failed to connect", "addr", resolvedAddr, "error", err)
		return nil, err
	}

	logger.Debug("Connected to backend", "resolved_addr", resolvedAddr, "local", server.GetAddrString(conn.LocalAddr()), "remote", server.GetAddrString(conn.RemoteAddr()))

	// Determine effective settings for this connection.
	// Default to the connection manager's global settings.
	useProxyProtocol := cm.remoteUseProxyProtocol
	remoteTLS := cm.remoteTLS
	remoteTLSUseStartTLS := cm.remoteTLSUseStartTLS
	remoteTLSVerify := cm.remoteTLSVerify

	// If routingInfo is provided and this connection is for that specific server,
	// override the TLS settings with the ones from the remotelookup config.
	if routingInfo != nil && routingInfo.ServerAddress == addr {
		useProxyProtocol = routingInfo.RemoteUseProxyProtocol
		remoteTLS = routingInfo.RemoteTLS
		remoteTLSUseStartTLS = routingInfo.RemoteTLSUseStartTLS
		remoteTLSVerify = routingInfo.RemoteTLSVerify
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
		tlsConfig := &tls.Config{
			InsecureSkipVerify: !remoteTLSVerify,
			// Explicitly set empty certificates to prevent automatic client certificate presentation
			Certificates: []tls.Certificate{},
			// Disable client certificate authentication
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return nil, nil
			},
			// Disable renegotiation (not supported in TLS 1.3, causes errors)
			Renegotiation: tls.RenegotiateNever,
		}
		logger.Debug("Starting TLS handshake", "addr", addr, "InsecureSkipVerify", !remoteTLSVerify)
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
	found := false
	for _, remoteAddr := range cm.remoteAddrs {
		if remoteAddr == addr {
			found = true
			break
		}
	}

	if !found {
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

// HasRouting returns true if a user routing lookup is configured.
func (cm *ConnectionManager) HasRouting() bool {
	return cm.routingLookup != nil
}

// LookupUserRoute performs a user routing lookup if configured.
// Note: This is routing-only lookup, so password is empty.
func (cm *ConnectionManager) LookupUserRoute(ctx context.Context, email string) (*UserRoutingInfo, error) {
	if !cm.HasRouting() || email == "" {
		return nil, nil
	}
	// Use routeOnly=true for LMTP routing lookups (no authentication, only routing info needed)
	info, authResult, err := cm.routingLookup.LookupUserRouteWithOptions(ctx, email, "", true)
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
	RoutingInfo         *UserRoutingInfo // Can be updated by the lookup
}

// DetermineRoute centralizes the logic for choosing a backend server.
// The precedence is: RemoteLookup > Affinity > Consistent Hash > Round-robin.
func DetermineRoute(params RouteParams) (RouteResult, error) {
	result := RouteResult{
		RoutingMethod: "consistent_hash", // Default: consistent hashing
		RoutingInfo:   params.RoutingInfo,
	}

	// 1. Try routing lookup first, only if not already available from auth
	if result.RoutingInfo == nil && params.ConnManager.HasRouting() {
		// Use remotelookup timeout for routing lookup (accounts for dial + TLS + HTTP)
		lookupTimeout := params.ConnManager.GetRemoteLookupTimeout()
		routingCtx, routingCancel := context.WithTimeout(params.Ctx, lookupTimeout)
		var lookupErr error
		result.RoutingInfo, lookupErr = params.ConnManager.LookupUserRoute(routingCtx, params.Username)
		routingCancel()
		if lookupErr != nil {
			logger.Debug("Routing lookup failed, falling back to affinity", "proxy", params.ProxyName, "user", params.Username, "error", lookupErr)
		}
	}

	if result.RoutingInfo != nil && result.RoutingInfo.ServerAddress != "" {
		// Use server address from routing info (remotelookup specified backend)
		result.PreferredAddr = result.RoutingInfo.ServerAddress
		logger.Debug("Using routing lookup", "proxy", params.ProxyName, "user", params.Username, "server", result.PreferredAddr)
		result.RoutingMethod = "remotelookup"
		result.IsRemoteLookupRoute = true
	}

	// 2. If no routing info from remotelookup, try cluster-wide affinity
	// Note: For auth-only remotelookup (IsRemoteLookupAccount=true but ServerAddress=""),
	// we still use affinity/consistent-hash (remotelookup only handled auth, not routing)
	if result.PreferredAddr == "" && params.EnableAffinity {
		// Only skip affinity if remotelookup explicitly provided a backend server
		// Auth-only mode: has routing info but no server address - should use affinity
		skipAffinity := params.IsRemoteLookupAccount && result.RoutingInfo != nil && result.RoutingInfo.ServerAddress != ""
		if !skipAffinity {
			affinityMgr := params.ConnManager.GetAffinityManager()
			if affinityMgr != nil && params.Protocol != "" {
				// Use gossip-based cluster affinity
				if lastAddr, found := affinityMgr.GetBackend(params.Username, params.Protocol); found {
					// Check if backend is healthy
					if params.ConnManager.IsBackendHealthy(lastAddr) {
						result.PreferredAddr = lastAddr
						result.RoutingMethod = "affinity"
						logger.Info("Using cluster affinity", "proxy", params.ProxyName, "user", params.Username, "backend", result.PreferredAddr)
					} else {
						logger.Info("Cluster affinity backend unhealthy - deleting affinity", "proxy", params.ProxyName, "backend", lastAddr, "user", params.Username)
						// Delete unhealthy affinity
						affinityMgr.DeleteBackend(params.Username, params.Protocol)
					}
				}
			}
		}
	}

	// 3. If no affinity, try consistent hashing (deterministic, no race condition)
	if result.PreferredAddr == "" && params.Username != "" {
		if backend := params.ConnManager.GetBackendByConsistentHash(params.Username); backend != "" {
			result.PreferredAddr = backend
			result.RoutingMethod = "consistent_hash"
			logger.Info("Using consistent hash", "proxy", params.ProxyName, "user", params.Username, "backend", result.PreferredAddr)
		} else {
			// All backends unhealthy in consistent hash, fall back to round-robin
			result.RoutingMethod = "roundrobin"
			logger.Info("All consistent hash backends unhealthy - falling back to round-robin", "proxy", params.ProxyName, "user", params.Username)
		}
	}

	return result, nil
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

	affinityMgr := params.ConnManager.GetAffinityManager()
	if affinityMgr == nil || params.Protocol == "" {
		return
	}

	// Get the consistent hash placement for this user
	consistentHashBackend := params.ConnManager.GetBackendByConsistentHash(params.Username)

	// Check current affinity
	currentBackend, hasAffinity := affinityMgr.GetBackend(params.Username, params.Protocol)

	if !hasAffinity {
		// No affinity exists yet
		if connectedBackend != consistentHashBackend {
			// User connected to different backend than consistent hash suggests
			// This means failover occurred - set affinity to track this
			affinityMgr.SetBackend(params.Username, connectedBackend, params.Protocol)
			logger.Info("Set failover affinity", "proxy", params.ProxyName, "user", params.Username,
				"backend", connectedBackend, "consistent_hash", consistentHashBackend)
		} else {
			// User on consistent hash backend - no affinity needed (deterministic)
			logger.Debug("Connection manager: User on consistent hash backend - no affinity needed", "proxy", params.ProxyName, "user", params.Username, "backend", connectedBackend)
		}
	} else if currentBackend != connectedBackend {
		// Affinity exists but we connected to a different backend
		if wasAffinityRoute {
			// We tried to use affinity but ended up on different backend (another failover)
			affinityMgr.UpdateBackend(params.Username, currentBackend, connectedBackend, params.Protocol)
			logger.Info("Updated affinity after failover", "proxy", params.ProxyName, "user", params.Username, "old", currentBackend, "new", connectedBackend)
		} else {
			// We used consistent hash but affinity exists pointing elsewhere
			// Check if we're back on consistent hash backend - if so, clear affinity
			if connectedBackend == consistentHashBackend {
				// User is back on consistent hash backend, clear affinity
				affinityMgr.DeleteBackend(params.Username, params.Protocol)
				logger.Info("Cleared affinity - reconnected to consistent hash backend", "proxy", params.ProxyName, "user", params.Username, "backend", connectedBackend)
			} else {
				// Connected to different backend via consistent hash, keep existing affinity
				// This can happen if consistent hash changed (backend added/removed)
				logger.Info("Affinity exists - keeping affinity", "proxy", params.ProxyName, "user", params.Username, "affinity", currentBackend, "connected", connectedBackend)
			}
		}
	} else {
		// Connected backend matches affinity - check if we can clear affinity
		if connectedBackend == consistentHashBackend {
			// User is back on consistent hash backend, clear affinity
			affinityMgr.DeleteBackend(params.Username, params.Protocol)
			logger.Info("Cleared affinity - back on consistent hash backend", "proxy", params.ProxyName, "user", params.Username, "backend", connectedBackend)
		}
		// Otherwise keep affinity (still in failover state)
	}
}
