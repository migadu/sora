package managesieveproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieve"
	"github.com/migadu/sora/server/proxy"
)

// maxAuthErrors is the number of invalid commands tolerated during the
// authentication phase before the connection is dropped.
const maxAuthErrors = 2

// Session represents a ManageSieve proxy session.
type Session struct {
	server             *Server
	clientConn         net.Conn
	backendConn        net.Conn
	clientReader       *bufio.Reader
	clientWriter       *bufio.Writer
	username           string
	accountID          int64
	isPrelookupAccount bool
	routingInfo        *proxy.UserRoutingInfo
	serverAddr         string
	mu                 sync.Mutex
	ctx                context.Context
	cancel             context.CancelFunc
	errorCount         int
}

// newSession creates a new ManageSieve proxy session.
func newSession(server *Server, conn net.Conn) *Session {
	sessionCtx, sessionCancel := context.WithCancel(server.ctx)
	return &Session{
		server:       server,
		clientConn:   conn,
		clientReader: bufio.NewReader(conn),
		clientWriter: bufio.NewWriter(conn),
		ctx:          sessionCtx,
		cancel:       sessionCancel,
		errorCount:   0,
	}
}

// handleConnection handles the proxy session.
func (s *Session) handleConnection() {
	defer s.cancel()
	defer s.close()

	clientAddr := s.clientConn.RemoteAddr().String()
	log.Printf("ManageSieve Proxy [%s] New connection from %s", s.server.name, clientAddr)

	// Debug: Log connection type
	if s.server.debug {
		log.Printf("ManageSieve Proxy [%s] [DEBUG] Connection type: %T", s.server.name, s.clientConn)
	}

	// Perform TLS handshake if this is a TLS connection
	if tlsConn, ok := s.clientConn.(interface{ PerformHandshake() error }); ok {
		if err := tlsConn.PerformHandshake(); err != nil {
			log.Printf("ManageSieve Proxy [%s] TLS handshake failed for %s: %v", s.server.name, clientAddr, err)
			return
		}
	}

	// Send initial greeting with capabilities
	if err := s.sendGreeting(); err != nil {
		log.Printf("ManageSieve Proxy [%s] Failed to send greeting to %s: %v", s.server.name, clientAddr, err)
		return
	}

	// Handle authentication phase
	authenticated := false
	for !authenticated {
		// Set a read deadline for the client command to prevent idle connections.
		if s.server.sessionTimeout > 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.sessionTimeout)); err != nil {
				log.Printf("ManageSieve Proxy [%s] Failed to set read deadline for %s: %v", s.server.name, clientAddr, err)
				return
			}
		}

		// Read command from client
		line, err := s.clientReader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("ManageSieve Proxy [%s] Client %s timed out waiting for command", s.server.name, clientAddr)
				s.sendResponse(`NO "Idle timeout"`)
				return
			}
			if err != io.EOF {
				log.Printf("ManageSieve Proxy [%s] Error reading from client %s: %v", s.server.name, clientAddr, err)
			}
			return
		}

		line = strings.TrimRight(line, "\r\n")

		// Use the shared command parser. ManageSieve commands do not have tags.
		_, command, args, err := server.ParseLine(line, false)
		if err != nil {
			if s.handleAuthError(fmt.Sprintf(`NO "%s"`, err.Error())) {
				return
			}
			continue
		}

		if command == "" { // Empty line
			continue
		}

		log.Printf("ManageSieve Proxy [%s] Client %s: %s", s.server.name, clientAddr, helpers.MaskSensitive(line, command, "AUTHENTICATE", "LOGIN"))
		switch command {
		case "AUTHENTICATE":
			if s.server.debug {
				log.Printf("ManageSieve Proxy [%s] [DEBUG] AUTHENTICATE: len(args)=%d", s.server.name, len(args))
				for i, arg := range args {
					log.Printf("ManageSieve Proxy [%s] [DEBUG] AUTHENTICATE: args[%d]=%q", s.server.name, i, arg)
				}
			}

			if len(args) < 1 || strings.ToUpper(server.UnquoteString(args[0])) != "PLAIN" {
				if s.handleAuthError(`NO "AUTHENTICATE PLAIN is the only supported mechanism"`) {
					return
				}
				continue
			}

			// Check if initial response is included
			var saslLine string
			if len(args) >= 2 {
				// Initial response provided (either quoted string or literal)
				if s.server.debug {
					log.Printf("ManageSieve Proxy [%s] [DEBUG] AUTHENTICATE: using initial response from args[1]", s.server.name)
				}
				arg1 := args[1]

				// Check if it's a literal string {number+} or {number}
				if strings.HasPrefix(arg1, "{") && strings.HasSuffix(arg1, "}") || strings.HasSuffix(arg1, "+}") {
					// Literal string - need to read the specified number of bytes
					var literalSize int
					literalStr := strings.TrimPrefix(arg1, "{")
					literalStr = strings.TrimSuffix(literalStr, "}")
					literalStr = strings.TrimSuffix(literalStr, "+")

					_, err := fmt.Sscanf(literalStr, "%d", &literalSize)
					if err != nil || literalSize < 0 || literalSize > 8192 {
						if s.handleAuthError(`NO "Invalid literal size"`) {
							return
						}
						continue
					}

					if s.server.debug {
						log.Printf("ManageSieve Proxy [%s] [DEBUG] AUTHENTICATE: reading literal of %d bytes", s.server.name, literalSize)
					}

					// Read the literal data
					literalData := make([]byte, literalSize)
					_, err = io.ReadFull(s.clientReader, literalData)
					if err != nil {
						log.Printf("ManageSieve Proxy [%s] Error reading literal data: %v", s.server.name, err)
						return
					}

					// Read the trailing CRLF after literal
					s.clientReader.ReadString('\n')

					saslLine = string(literalData)
				} else {
					// Quoted string
					saslLine = server.UnquoteString(arg1)
				}
			} else {
				if s.server.debug {
					log.Printf("ManageSieve Proxy [%s] [DEBUG] AUTHENTICATE: sending continuation, waiting for response", s.server.name)
				}
				// Send continuation and wait for response
				s.sendContinuation()

				// Read SASL response
				saslLine, err = s.clientReader.ReadString('\n')
				if err != nil {
					log.Printf("ManageSieve Proxy [%s] Error reading SASL response: %v", s.server.name, err)
					return
				}
				// The response to a continuation can also be a quoted string.
				saslLine = server.UnquoteString(strings.TrimRight(saslLine, "\r\n"))
			}

			// Handle cancellation
			if saslLine == "*" {
				// Client-side cancellation is not an error we should count.
				s.sendResponse(`NO "Authentication cancelled"`)
				continue
			}

			// Decode SASL PLAIN
			decoded, err := base64.StdEncoding.DecodeString(saslLine)
			if err != nil {
				if s.handleAuthError(`NO "Invalid base64 encoding"`) {
					return
				}
				continue
			}

			parts := strings.Split(string(decoded), "\x00")
			if len(parts) != 3 {
				if s.handleAuthError(`NO "Invalid SASL PLAIN response"`) {
					return
				}
				continue
			}

			// authzID := parts[0] // Not used in proxy
			authnID := parts[1]
			password := parts[2]

			if err := s.authenticateUser(authnID, password); err != nil {
				log.Printf("ManageSieve Proxy [%s] Authentication failed for %s: %v", s.server.name, authnID, err)
				// This is an actual authentication failure, not a protocol error.
				// The rate limiter handles this, so we don't count it as a command error.
				s.sendResponse(`NO "Authentication failed"`)
				continue
			}

			s.username = authnID

			// Connect to backend and authenticate
			if err := s.connectToBackendAndAuth(); err != nil {
				log.Printf("ManageSieve Proxy [%s] Backend connection/auth failed for %s: %v", s.server.name, authnID, err)
				s.sendResponse(`NO "Backend server temporarily unavailable"`)
				continue
			}

			// Register connection
			if err := s.registerConnection(); err != nil {
				log.Printf("ManageSieve Proxy [%s] Failed to register connection for %s: %v", s.server.name, authnID, err)
			}

			s.sendResponse(`OK "Authenticated"`)
			authenticated = true

		case "LOGOUT":
			s.sendResponse(`OK "Bye"`)
			return

		case "NOOP":
			s.sendResponse(`OK "NOOP completed"`)

		case "CAPABILITY":
			// Re-send capabilities as per RFC 5804
			if err := s.sendCapabilities(); err != nil {
				log.Printf("ManageSieve Proxy [%s] Error sending capabilities: %v", s.server.name, err)
				return
			}

		case "STARTTLS":
			// Check if STARTTLS is enabled
			if !s.server.tls || !s.server.tlsUseStartTLS {
				if s.handleAuthError(`NO "STARTTLS not available"`) {
					return
				}
				continue
			}

			// Check if already using TLS
			if _, ok := s.clientConn.(*tls.Conn); ok {
				if s.handleAuthError(`NO "Already using TLS"`) {
					return
				}
				continue
			}

			// Send OK response
			if err := s.sendResponse(`OK "Begin TLS negotiation now"`); err != nil {
				log.Printf("ManageSieve Proxy [%s] Failed to send STARTTLS response: %v", s.server.name, err)
				return
			}

			// Load TLS config
			cert, err := tls.LoadX509KeyPair(s.server.tlsCertFile, s.server.tlsKeyFile)
			if err != nil {
				log.Printf("ManageSieve Proxy [%s] Failed to load TLS certificate: %v", s.server.name, err)
				return
			}

			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
				ClientAuth:   tls.NoClientCert,
			}
			if s.server.tlsVerify {
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			}

			// Upgrade connection to TLS
			tlsConn := tls.Server(s.clientConn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("ManageSieve Proxy [%s] TLS handshake failed: %v", s.server.name, err)
				return
			}

			// Update session with TLS connection
			s.clientConn = tlsConn
			s.clientReader = bufio.NewReader(tlsConn)
			s.clientWriter = bufio.NewWriter(tlsConn)

			log.Printf("ManageSieve Proxy [%s] STARTTLS negotiation successful for %s", s.server.name, clientAddr)

			// Re-send greeting with updated capabilities (now with SASL mechanisms available)
			if err := s.sendGreeting(); err != nil {
				log.Printf("ManageSieve Proxy [%s] Failed to send greeting after STARTTLS: %v", s.server.name, err)
				return
			}

			// Continue to next command after STARTTLS
			continue

		default:
			if s.handleAuthError(`NO "Command not supported before authentication"`) {
				return
			}
			continue
		}
	}

	// Clear the read deadline once authenticated. ManageSieve is transactional,
	// but we'll follow the IMAP proxy pattern. The backend is expected to handle
	// its own connection lifetime.
	if s.server.sessionTimeout > 0 {
		if err := s.clientConn.SetReadDeadline(time.Time{}); err != nil {
			log.Printf("ManageSieve Proxy [%s] Warning: failed to clear read deadline for %s: %v", s.server.name, clientAddr, err)
		}
	}

	// Start proxying only if backend connection was successful
	if s.backendConn != nil {
		log.Printf("ManageSieve Proxy [%s] Starting proxy for user %s", s.server.name, s.username)
		s.startProxy()
	} else {
		log.Printf("ManageSieve Proxy [%s] Cannot start proxy for user %s: no backend connection", s.server.name, s.username)
	}
}

// handleAuthError increments the error count, sends an error response, and
// returns true if the connection should be dropped.
func (s *Session) handleAuthError(response string) bool {
	s.errorCount++
	s.sendResponse(response)
	if s.errorCount >= maxAuthErrors {
		log.Printf("ManageSieve Proxy [%s] Too many authentication errors from %s, dropping connection.", s.server.name, s.clientConn.RemoteAddr())
		// Send a final error message before closing.
		s.sendResponse(`NO "Too many invalid commands"`)
		return true
	}
	return false
}

// sendResponse sends a response to the client.
func (s *Session) sendResponse(response string) error {
	_, err := s.clientWriter.WriteString(response + "\r\n")
	if err != nil {
		return err
	}
	return s.clientWriter.Flush()
}

// sendContinuation sends a ManageSieve continuation response.
func (s *Session) sendContinuation() error {
	// RFC 5804: server MUST respond with a "go-ahead" that is an empty string literal.
	_, err := s.clientWriter.WriteString("\"\"\r\n")
	if err != nil {
		return err
	}
	return s.clientWriter.Flush()
}

// authenticateUser authenticates the user against the database.
func (s *Session) authenticateUser(username, password string) error {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	// Apply progressive authentication delay BEFORE any other checks
	remoteAddr := s.clientConn.RemoteAddr()
	server.ApplyAuthenticationDelay(s.ctx, s.server.authLimiter, remoteAddr, "MANAGESIEVE-PROXY")

	// Check if the authentication attempt is allowed by the rate limiter using proxy-aware methods
	if err := s.server.authLimiter.CanAttemptAuthWithProxy(s.ctx, s.clientConn, nil, username); err != nil {
		// Don't record as auth failure - this is rate limiting, not authentication failure
		metrics.ProtocolErrors.WithLabelValues("managesieve_proxy", "AUTH", "rate_limited", "client_error").Inc()
		return err
	}

	// Try prelookup authentication/routing first if configured
	// Skip strict address validation if prelookup is enabled, as it may support master tokens
	// with syntax like user@domain.com@TOKEN (multiple @ symbols)
	if s.server.debug {
		log.Printf("ManageSieve Proxy [%s] [DEBUG] Attempting authentication for user %s via prelookup", s.server.name, username)
	}
	routingInfo, authResult, err := s.server.connManager.AuthenticateAndRoute(ctx, username, password)

	if err != nil {
		// Categorize the error type to determine fallback behavior
		if errors.Is(err, proxy.ErrPrelookupInvalidResponse) {
			// Invalid response from prelookup (malformed 2xx) - this is a server bug, fail hard
			log.Printf("ManageSieve Proxy [%s] Prelookup returned invalid response for '%s': %v. This is a server bug - rejecting authentication.", s.server.name, username, err)
			s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
			metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", "failure").Inc()
			return fmt.Errorf("prelookup server error: invalid response")
		}

		if errors.Is(err, proxy.ErrPrelookupTransient) {
			// Transient error (network, 5xx, circuit breaker) - check fallback config
			if s.server.prelookupConfig != nil && s.server.prelookupConfig.FallbackDefault {
				if s.server.debug {
					log.Printf("ManageSieve Proxy [%s] [DEBUG] Prelookup transient error for '%s': %v. Fallback enabled - attempting main DB authentication.", s.server.name, username, err)
				}
				// Fallthrough to main DB auth
			} else {
				log.Printf("ManageSieve Proxy [%s] Prelookup transient error for '%s': %v. Fallback disabled (fallback_to_default=false) - rejecting authentication.", s.server.name, username, err)
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", "failure").Inc()
				return fmt.Errorf("prelookup service unavailable")
			}
		} else {
			// Unknown error type - log and fallthrough
			if s.server.debug {
				log.Printf("ManageSieve Proxy [%s] [DEBUG] Prelookup unknown error for '%s': %v. Attempting fallback to main DB.", s.server.name, username, err)
			}
			// Fallthrough to main DB auth
		}
	} else {
		switch authResult {
		case proxy.AuthSuccess:
			// Prelookup auth was successful. Use the accountID and flag from the prelookup result.
			log.Printf("ManageSieve Proxy [%s] Prelookup authentication successful for %s, AccountID: %d (prelookup)", s.server.name, username, routingInfo.AccountID)
			if s.server.debug {
				log.Printf("ManageSieve Proxy [%s] [DEBUG] Prelookup routing: server=%s, TLS=%t, StartTLS=%t, TLSVerify=%t, ProxyProtocol=%t",
					s.server.name, routingInfo.ServerAddress, routingInfo.RemoteTLS, routingInfo.RemoteTLSUseStartTLS,
					routingInfo.RemoteTLSVerify, routingInfo.RemoteUseProxyProtocol)
			}
			s.accountID = routingInfo.AccountID
			s.isPrelookupAccount = routingInfo.IsPrelookupAccount
			s.routingInfo = routingInfo
			// Use the actual email (without token) for backend impersonation
			if routingInfo.ActualEmail != "" {
				s.username = routingInfo.ActualEmail
			} else {
				s.username = username // Fallback to original
			}
			s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, true)
			metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", "success").Inc()
			// For metrics, use username as-is (may contain token, but that's ok for tracking)
			if addr, err := server.NewAddress(username); err == nil {
				metrics.TrackDomainConnection("managesieve_proxy", addr.Domain())
				metrics.TrackUserActivity("managesieve_proxy", addr.FullAddress(), "connection", 1)
			}
			return nil // Authentication complete

		case proxy.AuthFailed:
			// User found in prelookup, but password was wrong. Reject immediately.
			log.Printf("ManageSieve Proxy [%s] Prelookup authentication failed for %s (bad password)", s.server.name, username)
			s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
			metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", "failure").Inc()
			return fmt.Errorf("authentication failed")

		case proxy.AuthUserNotFound:
			// User not in prelookup DB. Fallthrough to main DB auth.
			if s.server.debug {
				log.Printf("ManageSieve Proxy [%s] [DEBUG] User '%s' not found in prelookup. Falling back to main DB.", s.server.name, username)
			}
		}
	}

	// Fallback to main DB - validate address format for normal email
	address, err := server.NewAddress(username)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	// Fallback/default: Authenticate against the main database.
	if s.server.debug {
		log.Printf("ManageSieve Proxy [%s] [DEBUG] Authenticating user %s via main database", s.server.name, username)
	}
	accountID, err := s.server.rdb.AuthenticateWithRetry(ctx, address.FullAddress(), password)
	if err != nil {
		s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
		metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", "failure").Inc()
		return fmt.Errorf("authentication failed: %w", err)
	}

	s.accountID = accountID
	s.isPrelookupAccount = false // Authenticated against the main DB
	s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, true)
	metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", "success").Inc()
	metrics.TrackDomainConnection("managesieve_proxy", address.Domain())
	metrics.TrackUserActivity("managesieve_proxy", address.FullAddress(), "connection", 1)
	return nil
}

// sendGreeting sends the initial ManageSieve greeting with capabilities.
func (s *Session) sendGreeting() error {
	return s.sendCapabilities()
}

// sendCapabilities sends ManageSieve capabilities.
func (s *Session) sendCapabilities() error {
	// Send a minimal set of capabilities for the proxy
	if _, err := s.clientWriter.WriteString(`"IMPLEMENTATION" "Sora ManageSieve Proxy"` + "\r\n"); err != nil {
		return fmt.Errorf("failed to write IMPLEMENTATION: %w", err)
	}

	// Build SIEVE capabilities: builtin + configured extensions (from managesieve package)
	capabilities := managesieve.GetSieveCapabilities(s.server.supportedExtensions)
	capabilitiesStr := strings.Join(capabilities, " ")
	if _, err := s.clientWriter.WriteString(fmt.Sprintf(`"SIEVE" "%s"`, capabilitiesStr) + "\r\n"); err != nil {
		return fmt.Errorf("failed to write SIEVE: %w", err)
	}

	// Check if we're on a TLS connection
	_, isSecure := s.clientConn.(*tls.Conn)

	// Advertise STARTTLS if configured and not already using TLS
	if s.server.tls && s.server.tlsUseStartTLS && !isSecure {
		// Before STARTTLS: Don't advertise SASL mechanisms (RFC 5804 security requirement)
		if _, err := s.clientWriter.WriteString(`"SASL" ""` + "\r\n"); err != nil {
			return fmt.Errorf("failed to write SASL: %w", err)
		}
		if _, err := s.clientWriter.WriteString(`"STARTTLS"` + "\r\n"); err != nil {
			return fmt.Errorf("failed to write STARTTLS: %w", err)
		}
	} else {
		// After STARTTLS or on implicit TLS: Advertise available SASL mechanisms
		if _, err := s.clientWriter.WriteString(`"SASL" "PLAIN"` + "\r\n"); err != nil {
			return fmt.Errorf("failed to write SASL: %w", err)
		}
	}

	if _, err := s.clientWriter.WriteString(`"VERSION" "1.0"` + "\r\n"); err != nil {
		return fmt.Errorf("failed to write VERSION: %w", err)
	}

	if _, err := s.clientWriter.WriteString(`OK "ManageSieve proxy ready"` + "\r\n"); err != nil {
		return fmt.Errorf("failed to write OK: %w", err)
	}

	if err := s.clientWriter.Flush(); err != nil {
		return fmt.Errorf("failed to flush: %w", err)
	}

	return nil
}

// connectToBackendAndAuth connects to backend and authenticates.
func (s *Session) connectToBackendAndAuth() error {
	routeResult, err := proxy.DetermineRoute(proxy.RouteParams{
		Ctx:                s.ctx,
		Username:           s.username,
		Protocol:           "managesieve",
		IsPrelookupAccount: s.isPrelookupAccount,
		RoutingInfo:        s.routingInfo,
		ConnManager:        s.server.connManager,
		EnableAffinity:     s.server.enableAffinity,
		ProxyName:          "ManageSieve Proxy",
	})
	if err != nil {
		log.Printf("ManageSieve Proxy [%s] Error determining route for %s: %v", s.server.name, s.username, err)
	}

	// Update session routing info if it was fetched by DetermineRoute
	s.routingInfo = routeResult.RoutingInfo
	preferredAddr := routeResult.PreferredAddr
	isPrelookupRoute := routeResult.IsPrelookupRoute

	// 4. Connect using the determined address (or round-robin if empty)
	// Track which routing method was used for this connection.
	metrics.ProxyRoutingMethod.WithLabelValues("managesieve", routeResult.RoutingMethod).Inc()

	connectCtx, connectCancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer connectCancel()

	clientHost, clientPort := server.GetHostPortFromAddr(s.clientConn.RemoteAddr())
	serverHost, serverPort := server.GetHostPortFromAddr(s.clientConn.LocalAddr())
	conn, actualAddr, err := s.server.connManager.ConnectWithProxy(
		connectCtx,
		preferredAddr,
		clientHost, clientPort, serverHost, serverPort, s.routingInfo,
	)
	if err != nil {
		metrics.ProxyBackendConnections.WithLabelValues("managesieve", "failure").Inc()
		return fmt.Errorf("failed to connect to backend: %w", err)
	}
	if isPrelookupRoute && actualAddr != preferredAddr {
		// The prelookup route specified a server, but we connected to a different one.
		// This means the preferred server failed and the connection manager fell back.
		// For prelookup routes, this is a hard failure.
		conn.Close()
		metrics.ProxyBackendConnections.WithLabelValues("managesieve", "failure").Inc()
		return fmt.Errorf("prelookup route to %s failed, and fallback is disabled for prelookup routes", preferredAddr)
	}

	metrics.ProxyBackendConnections.WithLabelValues("managesieve", "success").Inc()
	s.backendConn = conn
	s.serverAddr = actualAddr

	// Record successful connection for future affinity
	if s.server.enableAffinity && !s.isPrelookupAccount && actualAddr != "" {
		proxy.UpdateAffinityAfterConnection(proxy.RouteParams{
			Username:           s.username,
			Protocol:           "managesieve",
			IsPrelookupAccount: s.isPrelookupAccount,
			ConnManager:        s.server.connManager,
			EnableAffinity:     s.server.enableAffinity,
			ProxyName:          "ManageSieve Proxy",
		}, actualAddr, routeResult.RoutingMethod == "affinity")
	}

	// Read backend greeting and capabilities
	backendReader := bufio.NewReader(s.backendConn)
	backendWriter := bufio.NewWriter(s.backendConn)
	for {
		line, err := backendReader.ReadString('\n')
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("failed to read backend greeting: %w", err)
		}

		// Just consume the backend greeting, don't forward it (we already sent our own)
		// Check if this is the OK line (end of capabilities)
		if strings.HasPrefix(strings.TrimSpace(line), "OK") {
			break
		}
	}

	// Check if we need to negotiate StartTLS with the backend
	// This happens when prelookup (or global config) specifies remote_tls_use_starttls
	shouldUseStartTLS := false
	var tlsConfig *tls.Config

	if s.routingInfo != nil && s.routingInfo.RemoteTLSUseStartTLS {
		// Prelookup routing specified StartTLS
		shouldUseStartTLS = true
		tlsConfig = &tls.Config{
			InsecureSkipVerify: !s.routingInfo.RemoteTLSVerify,
		}
		log.Printf("ManageSieve Proxy [%s] Using prelookup StartTLS settings for backend: remoteTLSVerify=%t",
			s.server.name, s.routingInfo.RemoteTLSVerify)
	} else if s.server.connManager.IsRemoteStartTLS() {
		// Global proxy config specified StartTLS
		shouldUseStartTLS = true
		tlsConfig = s.server.connManager.GetTLSConfig()
		log.Printf("ManageSieve Proxy [%s] Using global StartTLS settings for backend", s.server.name)
	}

	if shouldUseStartTLS && tlsConfig != nil {
		if s.server.debug {
			log.Printf("ManageSieve Proxy [%s] [DEBUG] Negotiating StartTLS with backend %s (InsecureSkipVerify=%t)",
				s.server.name, actualAddr, tlsConfig.InsecureSkipVerify)
		} else {
			log.Printf("ManageSieve Proxy [%s] Negotiating StartTLS with backend %s", s.server.name, actualAddr)
		}

		// Send STARTTLS command
		_, err := backendWriter.WriteString("STARTTLS\r\n")
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("failed to send STARTTLS command: %w", err)
		}
		backendWriter.Flush()

		if s.server.debug {
			log.Printf("ManageSieve Proxy [%s] [DEBUG] Sent STARTTLS command to backend", s.server.name)
		}

		// Read STARTTLS response
		response, err := backendReader.ReadString('\n')
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("failed to read STARTTLS response: %w", err)
		}

		if s.server.debug {
			log.Printf("ManageSieve Proxy [%s] [DEBUG] Backend STARTTLS response: %s", s.server.name, strings.TrimSpace(response))
		}

		if !strings.HasPrefix(strings.TrimSpace(response), "OK") {
			s.backendConn.Close()
			return fmt.Errorf("backend STARTTLS failed: %s", strings.TrimSpace(response))
		}

		// Upgrade connection to TLS
		tlsConn := tls.Client(s.backendConn, tlsConfig)
		err = tlsConn.Handshake()
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("TLS handshake with backend failed: %w", err)
		}

		log.Printf("ManageSieve Proxy [%s] StartTLS negotiation successful with backend %s", s.server.name, actualAddr)
		s.backendConn = tlsConn
	}

	// Now authenticate to backend
	return s.authenticateToBackend()
}

// authenticateToBackend authenticates to the backend using master credentials.
func (s *Session) authenticateToBackend() error {
	backendWriter := bufio.NewWriter(s.backendConn)
	backendReader := bufio.NewReader(s.backendConn)

	// Send AUTHENTICATE PLAIN command with impersonation
	authString := fmt.Sprintf("%s\x00%s\x00%s", s.username, string(s.server.masterSASLUsername), string(s.server.masterSASLPassword))
	encoded := base64.StdEncoding.EncodeToString([]byte(authString))

	if s.server.debug {
		log.Printf("ManageSieve Proxy [%s] [DEBUG] Auth string format: authorize-id=%s, authenticate-id=%s",
			s.server.name, s.username, string(s.server.masterSASLUsername))
		log.Printf("ManageSieve Proxy [%s] [DEBUG] Sending AUTHENTICATE command with base64: %s", s.server.name, encoded)
	}

	// ManageSieve requires quoted strings for command arguments
	_, err := backendWriter.WriteString(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"\r\n", encoded))
	if err != nil {
		return fmt.Errorf("failed to send AUTHENTICATE command: %w", err)
	}
	backendWriter.Flush()

	// Read authentication response
	response, err := backendReader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if s.server.debug {
		log.Printf("ManageSieve Proxy [%s] [DEBUG] Backend auth response: %s", s.server.name, strings.TrimSpace(response))
	}

	if !strings.HasPrefix(response, "OK") {
		return fmt.Errorf("backend authentication failed: %s", response)
	}

	log.Printf("ManageSieve Proxy [%s] Backend authentication successful for user %s", s.server.name, s.username)

	return nil
}

// startProxy starts bidirectional proxying between client and backend.
func (s *Session) startProxy() {
	if s.backendConn == nil {
		log.Printf("ManageSieve Proxy [%s] backend connection not established for %s", s.server.name, s.username)
		return
	}

	var wg sync.WaitGroup

	// Start activity updater
	activityCtx, activityCancel := context.WithCancel(s.ctx)
	defer activityCancel()
	go s.updateActivityPeriodically(activityCtx)

	// Client to backend
	wg.Add(1)
	go func() {
		defer wg.Done()
		// If this copy returns, it means the client has closed the connection or there was an error.
		// We must close the backend connection to unblock the other copy operation.
		defer s.backendConn.Close()
		bytesIn, err := io.Copy(s.backendConn, s.clientConn)
		metrics.BytesThroughput.WithLabelValues("managesieve_proxy", "in").Add(float64(bytesIn))
		if err != nil && !isClosingError(err) {
			log.Printf("ManageSieve Proxy [%s] Error copying from client to backend: %v", s.server.name, err)
		}
	}()

	// Backend to client
	wg.Add(1)
	go func() {
		defer wg.Done()
		// If this copy returns, it means the backend has closed the connection or there was an error.
		// We must close the client connection to unblock the other copy operation.
		defer s.clientConn.Close()
		bytesOut, err := io.Copy(s.clientConn, s.backendConn)
		metrics.BytesThroughput.WithLabelValues("managesieve_proxy", "out").Add(float64(bytesOut))
		if err != nil && !isClosingError(err) {
			log.Printf("ManageSieve Proxy [%s] Error copying from backend to client: %v", s.server.name, err)
		}
	}()

	go func() {
		<-s.ctx.Done()
		s.clientConn.Close()
		s.backendConn.Close()
	}()

	wg.Wait() // Wait for both copy operations to finish
}

// close closes all connections.
func (s *Session) close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Decrement current connections metric
	metrics.ConnectionsCurrent.WithLabelValues("managesieve_proxy").Dec()

	// Unregister connection
	if s.accountID > 0 {
		// Use a new background context for this final operation, as s.ctx is likely already cancelled.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		clientAddr := s.clientConn.RemoteAddr().String()

		if s.server.connTracker != nil && s.server.connTracker.IsEnabled() {
			if err := s.server.connTracker.UnregisterConnection(ctx, s.accountID, "ManageSieve", clientAddr); err != nil {
				log.Printf("ManageSieve Proxy [%s] Failed to unregister connection for %s: %v", s.server.name, s.username, err)
			}
		}
	}

	if s.clientConn != nil {
		s.clientConn.Close()
	}

	if s.backendConn != nil {
		s.backendConn.Close()
	}
}

// registerConnection registers the connection in the database.
func (s *Session) registerConnection() error {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	clientAddr := s.clientConn.RemoteAddr().String()

	if s.server.connTracker != nil && s.server.connTracker.IsEnabled() {
		return s.server.connTracker.RegisterConnection(ctx, s.accountID, "ManageSieve", clientAddr, s.serverAddr)
	}
	return nil
}

// updateActivityPeriodically updates the connection activity in the database.
func (s *Session) updateActivityPeriodically(ctx context.Context) {
	// If connection tracking is disabled, do nothing and wait for session to end.
	if s.server.connTracker == nil || !s.server.connTracker.IsEnabled() {
		<-ctx.Done()
		return
	}

	clientAddr := s.clientConn.RemoteAddr().String()
	activityTicker := time.NewTicker(30 * time.Second)
	defer activityTicker.Stop()
	kickChan := s.server.connTracker.KickChannel()

	checkAndTerminate := func() (terminated bool) {
		checkCtx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
		defer cancel()

		shouldTerminate, err := s.server.connTracker.CheckTermination(checkCtx, s.accountID, "ManageSieve", clientAddr)
		if err != nil {
			log.Printf("ManageSieve Proxy [%s] Failed to check termination for %s: %v", s.server.name, s.username, err)
			return false
		}
		if shouldTerminate {
			log.Printf("ManageSieve Proxy [%s] Connection kicked - disconnecting user: %s (client: %s, backend: %s)", s.server.name, s.username, clientAddr, s.serverAddr)
			s.clientConn.Close()
			s.backendConn.Close()
			return true
		}
		return false
	}

	for {
		select {
		case <-kickChan:
			log.Printf("ManageSieve Proxy [%s] Received kick notification for %s", s.server.name, s.username)
			if checkAndTerminate() {
				return
			}
		case <-activityTicker.C:
			updateCtx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
			if err := s.server.connTracker.UpdateActivity(updateCtx, s.accountID, "ManageSieve", clientAddr); err != nil {
				log.Printf("ManageSieve Proxy [%s] Failed to update activity for %s: %v", s.server.name, s.username, err)
			}
			cancel()
		case <-ctx.Done():
			return
		}
	}
}

func isClosingError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}
