package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionManager manages connections to multiple remote servers with round-robin and failover
type ConnectionManager struct {
	remoteAddrs            []string
	remoteTLS              bool
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
func NewConnectionManager(remoteAddrs []string, remoteTLS bool, remoteTLSVerify bool, remoteUseProxyProtocol bool, connectTimeout time.Duration) (*ConnectionManager, error) {
	return NewConnectionManagerWithRouting(remoteAddrs, remoteTLS, remoteTLSVerify, remoteUseProxyProtocol, connectTimeout, nil)
}

// NewConnectionManagerWithRouting creates a new connection manager with optional user routing
func NewConnectionManagerWithRouting(remoteAddrs []string, remoteTLS bool, remoteTLSVerify bool, remoteUseProxyProtocol bool, connectTimeout time.Duration, routingLookup UserRoutingLookup) (*ConnectionManager, error) {
	if len(remoteAddrs) == 0 {
		return nil, fmt.Errorf("no remote addresses provided")
	}

	healthyStatus := make(map[string]bool)
	lastCheck := make(map[string]time.Time)

	// Initially mark all servers as healthy
	for _, addr := range remoteAddrs {
		healthyStatus[addr] = true
		lastCheck[addr] = time.Now()
	}

	return &ConnectionManager{
		remoteAddrs:            remoteAddrs,
		remoteTLS:              remoteTLS,
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

// Connect attempts to connect to a remote server with round-robin and failover
func (cm *ConnectionManager) Connect(preferredAddr string) (net.Conn, string, error) {
	return cm.ConnectWithProxy(context.Background(), preferredAddr, "", 0, "", 0, nil)
}

// ConnectWithProxy attempts to connect to a remote server and sends PROXY protocol header
func (cm *ConnectionManager) ConnectWithProxy(ctx context.Context, preferredAddr, clientIP string, clientPort int, serverIP string, serverPort int, routingInfo *UserRoutingInfo) (net.Conn, string, error) {
	// If we have a preferred address (from affinity or prelookup), try it first.
	if preferredAddr != "" {
		// Check if this is a prelookup-routed connection
		isPrelookupRoute := routingInfo != nil && routingInfo.IsPrelookupAccount && routingInfo.ServerAddress == preferredAddr
		
		// Check if the preferred address is in our managed list of servers.
		isInList := false
		for _, addr := range cm.remoteAddrs {
			if addr == preferredAddr {
				isInList = true
				break
			}
		}

		// Only try the preferred address if it's not in the list,
		// or if it is in the list and is currently marked as healthy.
		if !isInList || cm.isHealthy(preferredAddr) {
			conn, err := cm.dialWithProxy(ctx, preferredAddr, clientIP, clientPort, serverIP, serverPort, routingInfo)
			if err == nil {
				// Success, return the connection.
				return conn, preferredAddr, nil
			}

			// If the connection failed...
			if isPrelookupRoute {
				// For prelookup routes, do NOT fall back to round-robin
				log.Printf("[ConnectionManager] Failed to connect to prelookup-designated server %s: %v. NOT falling back to round-robin as prelookup result is definitive.", preferredAddr, err)
				if isInList {
					cm.markUnhealthy(preferredAddr)
				}
				return nil, "", fmt.Errorf("failed to connect to prelookup-designated server %s: %w", preferredAddr, err)
			}
			
			// For affinity-based connections, fall back to round-robin
			log.Printf("[ConnectionManager] Failed to connect to preferred address %s: %v. Falling back to round-robin.", preferredAddr, err)

			// If it was a server from our list, mark it as unhealthy.
			if isInList {
				cm.markUnhealthy(preferredAddr)
			}
		} else if isPrelookupRoute {
			// If the prelookup server is in our list but marked as unhealthy, we should still fail
			// rather than falling back to round-robin, because prelookup results are definitive
			log.Printf("[ConnectionManager] Prelookup-designated server %s is marked as unhealthy. NOT falling back to round-robin as prelookup result is definitive.", preferredAddr)
			return nil, "", fmt.Errorf("prelookup-designated server %s is marked as unhealthy", preferredAddr)
		}
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

	log.Printf("[ConnectionManager] Attempting to connect to backend: %s", addr)

	var conn net.Conn
	var err error
	if cm.remoteTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: !cm.remoteTLSVerify,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		log.Printf("[ConnectionManager] Failed to connect to %s: %v", addr, err)
		return nil, err
	}

	// Log the actual local and remote addresses of the established connection
	log.Printf("[ConnectionManager] Connected to %s - Local: %s -> Remote: %s",
		addr, conn.LocalAddr(), conn.RemoteAddr())

	return conn, nil
}

func (cm *ConnectionManager) dialWithProxy(ctx context.Context, addr, clientIP string, clientPort int, serverIP string, serverPort int, routingInfo *UserRoutingInfo) (net.Conn, error) {
	// For PROXY protocol, we need to establish plain TCP connection first
	dialer := &net.Dialer{
		Timeout: cm.connectTimeout,
	}

	log.Printf("[ConnectionManager] Attempting to connect to backend: %s", addr)

	// Always establish plain TCP connection first
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		log.Printf("[ConnectionManager] Failed to connect to %s: %v", addr, err)
		return nil, err
	}

	log.Printf("[ConnectionManager] Connected to %s - Local: %s -> Remote: %s",
		addr, conn.LocalAddr(), conn.RemoteAddr())

	// Determine whether to use PROXY protocol. Check both global setting and routing-specific override.
	useProxyProtocol := cm.remoteUseProxyProtocol
	
	// If routingInfo is provided and this connection is for that specific server,
	// check for routing-specific PROXY protocol override
	if routingInfo != nil && routingInfo.ServerAddress == addr {
		useProxyProtocol = routingInfo.RemoteUseProxyProtocol
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
	} else {
		log.Printf("[ConnectionManager] No PROXY header sent - useProxyProtocol=%t clientIP=%s:%d serverIP=%s:%d",
			useProxyProtocol, clientIP, clientPort, serverIP, serverPort)
	}

	// Determine TLS settings. Default to the connection manager's global settings.
	remoteTLS := cm.remoteTLS
	remoteTLSVerify := cm.remoteTLSVerify

	// If routingInfo is provided and this connection is for that specific server,
	// override the TLS settings with the ones from the prelookup config.
	if routingInfo != nil && routingInfo.ServerAddress == addr {
		remoteTLS = routingInfo.RemoteTLS
		remoteTLSVerify = routingInfo.RemoteTLSVerify
	}

	// Now establish TLS if required
	if remoteTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: !remoteTLSVerify,
		}
		log.Printf("[ConnectionManager] Starting TLS handshake to %s", addr)
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
func (cm *ConnectionManager) ConnectToSpecific(addr string) (net.Conn, error) {
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

	return cm.dial(context.Background(), addr)
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
