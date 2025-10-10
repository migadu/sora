package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/pkg/resilient"
)

// ConnectionManager manages connections to multiple remote servers with round-robin and failover
type ConnectionManager struct {
	remoteAddrs            []string
	remotePort             int // Default port for backends if not in address
	remoteTLS              bool
	remoteTLSUseStartTLS   bool // Use STARTTLS for backend connections (only relevant if remoteTLS is true)
	remoteTLSVerify        bool
	remoteUseProxyProtocol bool
	connectTimeout         time.Duration

	// Round-robin index
	nextIndex atomic.Uint32

	// Track healthy servers
	healthyMu     sync.RWMutex
	healthyStatus map[string]bool
	lastCheck     map[string]time.Time

	// User routing lookup
	routingLookup UserRoutingLookup
}

// NewConnectionManager creates a new connection manager
func NewConnectionManager(remoteAddrs []string, remotePort int, remoteTLS bool, remoteTLSVerify bool, remoteUseProxyProtocol bool, connectTimeout time.Duration) (*ConnectionManager, error) {
	return NewConnectionManagerWithRouting(remoteAddrs, remotePort, remoteTLS, remoteTLSVerify, remoteUseProxyProtocol, connectTimeout, nil)
}

// NewConnectionManagerWithRouting creates a new connection manager with optional user routing
func NewConnectionManagerWithRouting(remoteAddrs []string, remotePort int, remoteTLS bool, remoteTLSVerify bool, remoteUseProxyProtocol bool, connectTimeout time.Duration, routingLookup UserRoutingLookup) (*ConnectionManager, error) {
	return NewConnectionManagerWithRoutingAndStartTLS(remoteAddrs, remotePort, remoteTLS, false, remoteTLSVerify, remoteUseProxyProtocol, connectTimeout, routingLookup)
}

// NewConnectionManagerWithRoutingAndStartTLS creates a new connection manager with optional user routing and StartTLS support
func NewConnectionManagerWithRoutingAndStartTLS(remoteAddrs []string, remotePort int, remoteTLS bool, remoteTLSUseStartTLS bool, remoteTLSVerify bool, remoteUseProxyProtocol bool, connectTimeout time.Duration, routingLookup UserRoutingLookup) (*ConnectionManager, error) {
	if len(remoteAddrs) == 0 {
		return nil, fmt.Errorf("no remote addresses provided")
	}

	// Normalize remote addresses to include default port if missing
	normalizedAddrs := make([]string, len(remoteAddrs))
	for i, addr := range remoteAddrs {
		normalizedAddrs[i] = normalizeHostPort(addr, remotePort)
	}

	healthyStatus := make(map[string]bool)
	lastCheck := make(map[string]time.Time)

	// Initially mark all servers as healthy
	for _, addr := range normalizedAddrs {
		healthyStatus[addr] = true
		lastCheck[addr] = time.Now()
	}

	return &ConnectionManager{
		remoteAddrs:            normalizedAddrs,
		remotePort:             remotePort,
		remoteTLS:              remoteTLS,
		remoteTLSUseStartTLS:   remoteTLSUseStartTLS,
		remoteTLSVerify:        remoteTLSVerify,
		remoteUseProxyProtocol: remoteUseProxyProtocol,
		connectTimeout:         connectTimeout,
		healthyStatus:          healthyStatus,
		lastCheck:              lastCheck,
		routingLookup:          routingLookup,
	}, nil
}

// AuthenticateAndRoute delegates to the routing lookup if available
func (cm *ConnectionManager) AuthenticateAndRoute(ctx context.Context, email, password string) (*UserRoutingInfo, AuthResult, error) {
	if cm.routingLookup == nil {
		return nil, AuthUserNotFound, fmt.Errorf("no routing lookup configured")
	}
	return cm.routingLookup.AuthenticateAndRoute(ctx, email, password)
}

// GetRoutingLookup returns the routing lookup client (may be nil)
func (cm *ConnectionManager) GetRoutingLookup() UserRoutingLookup {
	return cm.routingLookup
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
	}
}

// IsRemoteStartTLS returns whether remote connections should use StartTLS
func (cm *ConnectionManager) IsRemoteStartTLS() bool {
	return cm.remoteTLS && cm.remoteTLSUseStartTLS
}

// Connect attempts to connect to a remote server with round-robin and failover
// Deprecated: Use ConnectWithContext instead to properly propagate context cancellation
func (cm *ConnectionManager) Connect(preferredAddr string) (net.Conn, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cm.connectTimeout)
	defer cancel()
	return cm.ConnectWithProxy(ctx, preferredAddr, "", 0, "", 0, nil)
}

// ConnectWithContext attempts to connect to a remote server with proper context propagation
func (cm *ConnectionManager) ConnectWithContext(ctx context.Context, preferredAddr string) (net.Conn, string, error) {
	return cm.ConnectWithProxy(ctx, preferredAddr, "", 0, "", 0, nil)
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

		if !cm.isHealthy(addr) {
			// Check if we should retry this server
			if cm.shouldRetry(addr) {
				cm.markHealthy(addr)
			} else {
				continue
			}
		}

		conn, err := cm.dialWithProxy(ctx, addr, clientIP, clientPort, serverIP, serverPort, routingInfo)
		if err == nil {
			return conn, addr, nil
		}

		// Mark as unhealthy if connection failed
		cm.markUnhealthy(addr)
		log.Printf("[ConnectionManager] Failed to connect to %s: %v", addr, err)
	}

	return nil, "", fmt.Errorf("all remote servers are unavailable")
}

// tryPreferredAddress attempts to connect to a preferred address (from affinity or prelookup).
// It returns the connection, address, and an error if it fails.
// The 'shouldFallback' boolean indicates if the caller should attempt round-robin.
func (cm *ConnectionManager) tryPreferredAddress(ctx context.Context, preferredAddr, clientIP string, clientPort int, serverIP string, serverPort int, routingInfo *UserRoutingInfo) (conn net.Conn, addr string, err error, shouldFallback bool) {
	isPrelookupRoute := routingInfo != nil && routingInfo.IsPrelookupAccount && routingInfo.ServerAddress == preferredAddr

	isInList := false
	for _, a := range cm.remoteAddrs {
		if a == preferredAddr {
			isInList = true
			break
		}
	}

	// If the server is in our list and marked unhealthy, decide whether to fail hard or fall back.
	if isInList && !cm.isHealthy(preferredAddr) {
		if isPrelookupRoute {
			// Prelookup routes are definitive; if the server is unhealthy, we fail hard.
			log.Printf("[ConnectionManager] Prelookup-designated server %s is marked as unhealthy. NOT falling back to round-robin.", preferredAddr)
			err = fmt.Errorf("prelookup-designated server %s is marked as unhealthy", preferredAddr)
			return nil, "", err, false // No fallback
		}
		// For affinity, if the server is unhealthy, we just fall back to round-robin.
		log.Printf("[ConnectionManager] Preferred (affinity) server %s is marked as unhealthy. Falling back to round-robin.", preferredAddr)
		return nil, "", nil, true // Fallback
	}

	// Attempt to dial the preferred address.
	conn, err = cm.dialWithProxy(ctx, preferredAddr, clientIP, clientPort, serverIP, serverPort, routingInfo)
	if err == nil {
		// Success!
		return conn, preferredAddr, nil, false // No fallback
	}

	// Connection failed. Mark it as unhealthy if it's in our managed list.
	if isInList {
		cm.markUnhealthy(preferredAddr)
	}

	if isPrelookupRoute {
		// For prelookup routes, do NOT fall back to round-robin.
		log.Printf("[ConnectionManager] Failed to connect to prelookup-designated server %s: %v. NOT falling back to round-robin.", preferredAddr, err)
		err = fmt.Errorf("failed to connect to prelookup-designated server %s: %w", preferredAddr, err)
		return nil, "", err, false // No fallback
	}

	// For affinity-based connections, log the failure and indicate that we should fall back.
	log.Printf("[ConnectionManager] Failed to connect to preferred address %s: %v. Falling back to round-robin.", preferredAddr, err)
	return nil, "", err, true // Fallback
}

// ResolveAddresses resolves hostnames to IP addresses, expanding the address list
func (cm *ConnectionManager) ResolveAddresses() error {
	var resolvedAddrs []string
	newHealthyStatus := make(map[string]bool)
	newLastCheck := make(map[string]time.Time)

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
			newHealthyStatus[addr] = cm.healthyStatus[addr]
			newLastCheck[addr] = cm.lastCheck[addr]
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
			if status, ok := cm.healthyStatus[resolvedAddr]; ok {
				newHealthyStatus[resolvedAddr] = status
				newLastCheck[resolvedAddr] = cm.lastCheck[resolvedAddr]
			} else {
				newHealthyStatus[resolvedAddr] = true
				newLastCheck[resolvedAddr] = time.Now()
			}
		}
	}

	cm.healthyMu.Lock()
	cm.remoteAddrs = resolvedAddrs
	cm.healthyStatus = newHealthyStatus
	cm.lastCheck = newLastCheck
	cm.healthyMu.Unlock()

	return nil
}

func (cm *ConnectionManager) dial(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: cm.connectTimeout,
	}

	// Resolve the address to ensure proper IPv6 formatting
	resolvedAddr := cm.resolveAddress(addr)
	if resolvedAddr != addr {
		log.Printf("[ConnectionManager] Resolved %s to %s", addr, resolvedAddr)
	}

	log.Printf("[ConnectionManager] Attempting to connect to backend: %s", resolvedAddr)

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
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", resolvedAddr, tlsConfig)
	} else {
		// Plain connection (either no TLS, or TLS will be negotiated via StartTLS)
		conn, err = dialer.DialContext(ctx, "tcp", resolvedAddr)
	}

	if err != nil {
		log.Printf("[ConnectionManager] Failed to connect to %s: %v", resolvedAddr, err)
		return nil, err
	}

	// Log the actual local and remote addresses of the established connection
	log.Printf("[ConnectionManager] Connected to %s - Local: %s -> Remote: %s",
		resolvedAddr, conn.LocalAddr(), conn.RemoteAddr())

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
		log.Printf("[ConnectionManager] Resolved %s to %s", addr, resolvedAddr)
	}

	log.Printf("[ConnectionManager] Attempting to connect to backend: %s", resolvedAddr)

	// Always establish plain TCP connection first
	conn, err := dialer.DialContext(ctx, "tcp", resolvedAddr)
	if err != nil {
		log.Printf("[ConnectionManager] Failed to connect to %s: %v", resolvedAddr, err)
		return nil, err
	}

	log.Printf("[ConnectionManager] Connected to %s - Local: %s -> Remote: %s",
		resolvedAddr, conn.LocalAddr(), conn.RemoteAddr())

	// Determine effective settings for this connection.
	// Default to the connection manager's global settings.
	useProxyProtocol := cm.remoteUseProxyProtocol
	remoteTLS := cm.remoteTLS
	remoteTLSVerify := cm.remoteTLSVerify

	// If routingInfo is provided and this connection is for that specific server,
	// override the TLS settings with the ones from the prelookup config.
	if routingInfo != nil && routingInfo.ServerAddress == addr {
		useProxyProtocol = routingInfo.RemoteUseProxyProtocol
		remoteTLS = routingInfo.RemoteTLS
		remoteTLSVerify = routingInfo.RemoteTLSVerify
		log.Printf("[ConnectionManager] Using prelookup settings for %s: remoteTLS=%t, remoteTLSVerify=%t, useProxyProtocol=%t", addr, remoteTLS, remoteTLSVerify, useProxyProtocol)
	} else {
		log.Printf("[ConnectionManager] Using global settings for %s: remoteTLS=%t, remoteTLSVerify=%t, useProxyProtocol=%t", addr, remoteTLS, remoteTLSVerify, useProxyProtocol)
	}

	// If we have client IP information and PROXY protocol is enabled, send PROXY protocol header
	if useProxyProtocol && clientIP != "" && clientPort > 0 && serverIP != "" && serverPort > 0 {
		log.Printf("[ConnectionManager] Sending PROXY v2 header: client=%s:%d -> server=%s:%d",
			clientIP, clientPort, serverIP, serverPort)
		err = cm.writeProxyV2Header(conn, clientIP, clientPort, serverIP, serverPort)
		if err != nil {
			conn.Close()
			log.Printf("[ConnectionManager] Failed to send PROXY protocol header to %s: %v", addr, err)
			return nil, fmt.Errorf("failed to send PROXY protocol header: %w", err)
		}
	} else if useProxyProtocol {
		log.Printf("[ConnectionManager] PROXY protocol enabled but not sent (missing client/server info): client=%s:%d server=%s:%d",
			clientIP, clientPort, serverIP, serverPort)
	}

	// Now establish TLS if required
	if remoteTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: !remoteTLSVerify,
			// Explicitly set empty certificates to prevent automatic client certificate presentation
			Certificates: []tls.Certificate{},
			// Disable client certificate authentication
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return nil, nil
			},
		}
		log.Printf("[ConnectionManager] Starting TLS handshake to %s (InsecureSkipVerify=%t)", addr, !remoteTLSVerify)
		tlsConn := tls.Client(conn, tlsConfig)

		// Set a deadline for the TLS handshake
		if err := conn.SetDeadline(time.Now().Add(cm.connectTimeout)); err != nil {
			conn.Close()
			log.Printf("[ConnectionManager] Failed to set TLS handshake deadline for %s: %v", addr, err)
			return nil, fmt.Errorf("failed to set TLS deadline: %w", err)
		}

		err = tlsConn.Handshake()
		if err != nil {
			conn.Close()
			log.Printf("[ConnectionManager] TLS handshake failed for %s: %v", addr, err)
			log.Printf("[ConnectionManager] TLS handshake was using InsecureSkipVerify=%t, no client certificates", !remoteTLSVerify)
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}

		// Clear the deadline after successful handshake
		if err := conn.SetDeadline(time.Time{}); err != nil {
			log.Printf("[ConnectionManager] Warning: failed to clear TLS deadline for %s: %v", addr, err)
		}

		return tlsConn, nil
	}

	return conn, nil
}

// writeProxyV2Header writes a PROXY protocol v2 header manually to avoid circular imports
func (cm *ConnectionManager) writeProxyV2Header(conn net.Conn, clientIP string, clientPort int, serverIP string, serverPort int) error {
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

	// Address family and protocol (byte 13)
	header[13] = (addressFamily << 4) | transportProtocol

	// Length (bytes 14-15, big endian)
	dataLen := len(addressData)
	header[14] = byte(dataLen >> 8)
	header[15] = byte(dataLen & 0xFF)

	// Combine header and address data
	proxyHeader := append(header, addressData...)

	// Send the header
	_, err := conn.Write(proxyHeader)
	if err != nil {
		return fmt.Errorf("failed to write PROXY v2 header: %w", err)
	}

	log.Printf("[PROXY] Sent PROXY v2 header to backend %s: client=%s:%d -> server=%s:%d",
		conn.RemoteAddr(), clientIP, clientPort, serverIP, serverPort)

	return nil
}

func (cm *ConnectionManager) isHealthy(addr string) bool {
	cm.healthyMu.RLock()
	defer cm.healthyMu.RUnlock()
	return cm.healthyStatus[addr]
}

func (cm *ConnectionManager) markHealthy(addr string) {
	cm.healthyMu.Lock()
	defer cm.healthyMu.Unlock()
	cm.healthyStatus[addr] = true
	cm.lastCheck[addr] = time.Now()
}

func (cm *ConnectionManager) markUnhealthy(addr string) {
	cm.healthyMu.Lock()
	defer cm.healthyMu.Unlock()
	cm.healthyStatus[addr] = false
	cm.lastCheck[addr] = time.Now()
}

func (cm *ConnectionManager) shouldRetry(addr string) bool {
	cm.healthyMu.RLock()
	defer cm.healthyMu.RUnlock()

	// Retry unhealthy servers after 30 seconds
	lastCheck, ok := cm.lastCheck[addr]
	if !ok {
		return true
	}

	return time.Since(lastCheck) > 30*time.Second
}

// ConnectToSpecific attempts to connect to a specific server address
// Deprecated: Use ConnectToSpecificWithContext instead to properly propagate context cancellation
func (cm *ConnectionManager) ConnectToSpecific(addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cm.connectTimeout)
	defer cancel()
	return cm.ConnectToSpecificWithContext(ctx, addr)
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
func (cm *ConnectionManager) LookupUserRoute(ctx context.Context, email string) (*UserRoutingInfo, error) {
	if !cm.HasRouting() || email == "" {
		return nil, nil
	}
	return cm.routingLookup.LookupUserRoute(ctx, email)
}

// RouteParams holds all parameters needed to determine a backend route.
type RouteParams struct {
	Ctx                context.Context
	Username           string
	AccountID          int64
	IsPrelookupAccount bool
	RoutingInfo        *UserRoutingInfo
	ConnManager        *ConnectionManager
	RDB                *resilient.ResilientDatabase // For affinity lookup
	EnableAffinity     bool
	AffinityValidity   time.Duration
	AffinityStickiness float64
	ProxyName          string // "IMAP Proxy", "POP3 Proxy", etc. for logging
}

// RouteResult holds the outcome of a routing decision.
type RouteResult struct {
	PreferredAddr    string
	RoutingMethod    string
	IsPrelookupRoute bool
	RoutingInfo      *UserRoutingInfo // Can be updated by the lookup
}

// DetermineRoute centralizes the logic for choosing a backend server.
// The precedence is: Prelookup > Affinity > Round-robin.
func DetermineRoute(params RouteParams) (RouteResult, error) {
	result := RouteResult{
		RoutingMethod: "roundrobin", // Default
		RoutingInfo:   params.RoutingInfo,
	}

	// 1. Try routing lookup first, only if not already available from auth
	if result.RoutingInfo == nil && params.ConnManager.HasRouting() {
		routingCtx, routingCancel := context.WithTimeout(params.Ctx, 5*time.Second)
		var lookupErr error
		result.RoutingInfo, lookupErr = params.ConnManager.LookupUserRoute(routingCtx, params.Username)
		routingCancel()
		if lookupErr != nil {
			log.Printf("[%s] Routing lookup failed for %s: %v, falling back to affinity", params.ProxyName, params.Username, lookupErr)
		}
	}

	if result.RoutingInfo != nil && result.RoutingInfo.ServerAddress != "" {
		result.PreferredAddr = result.RoutingInfo.ServerAddress
		result.RoutingMethod = "prelookup"
		result.IsPrelookupRoute = true
		log.Printf("[%s] Using routing lookup for %s: %s", params.ProxyName, params.Username, result.PreferredAddr)
	}

	// 2. If no routing info from prelookup, try affinity
	if result.PreferredAddr == "" && params.EnableAffinity && !params.IsPrelookupAccount && params.AccountID > 0 {
		affinityCtx, affinityCancel := context.WithTimeout(params.Ctx, 2*time.Second)
		lastAddr, lastTime, affinityErr := params.RDB.GetLastServerAddressWithRetry(affinityCtx, params.AccountID)
		affinityCancel()

		if affinityErr != nil {
			if !errors.Is(affinityErr, consts.ErrNoServerAffinity) {
				log.Printf("[%s] Could not get preferred backend for %s: %v", params.ProxyName, params.Username, affinityErr)
			}
		} else if lastAddr != "" && time.Since(lastTime) < params.AffinityValidity {
			result.PreferredAddr = lastAddr
			result.RoutingMethod = "affinity"
			log.Printf("[%s] Using server affinity for %s: %s", params.ProxyName, params.Username, result.PreferredAddr)
		}
	}

	// 3. Apply stickiness to affinity address ONLY. Prelookup routes are absolute.
	if result.PreferredAddr != "" && !result.IsPrelookupRoute && params.AffinityStickiness < 1.0 {
		if rand.Float64() > params.AffinityStickiness {
			log.Printf("[%s] Ignoring affinity for %s due to stickiness factor (%.2f), falling back to round-robin", params.ProxyName, params.Username, params.AffinityStickiness)
			result.PreferredAddr = "" // This will cause the connection manager to use round-robin
			result.RoutingMethod = "roundrobin"
		}
	}

	return result, nil
}
