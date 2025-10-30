package managesieveproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/migadu/sora/logger"
	"io"
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
	isTLS              bool // Whether the client connection is over TLS
	mu                 sync.Mutex
	ctx                context.Context
	cancel             context.CancelFunc
	errorCount         int
}

// newSession creates a new ManageSieve proxy session.
func newSession(server *Server, conn net.Conn) *Session {
	sessionCtx, sessionCancel := context.WithCancel(server.ctx)
	// Check if connection is already TLS (implicit TLS)
	_, isTLS := conn.(*tls.Conn)
	return &Session{
		server:       server,
		clientConn:   conn,
		clientReader: bufio.NewReader(conn),
		clientWriter: bufio.NewWriter(conn),
		isTLS:        isTLS,
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
	if s.server.debug {
		logger.Debug("ManageSieve Proxy: New connection", "name", s.server.name, "remote", clientAddr)
	}

	// Perform TLS handshake if this is a TLS connection
	if tlsConn, ok := s.clientConn.(interface{ PerformHandshake() error }); ok {
		if err := tlsConn.PerformHandshake(); err != nil {
			logger.Debug("ManageSieve Proxy: TLS handshake failed", "name", s.server.name, "remote", clientAddr, "error", err)
			return
		}
	}

	// Send initial greeting with capabilities
	if err := s.sendGreeting(); err != nil {
		logger.Debug("ManageSieve Proxy: Failed to send greeting", "name", s.server.name, "remote", clientAddr, "error", err)
		return
	}

	// Handle authentication phase
	authenticated := false
	for !authenticated {
		// Set a read deadline for the client command to prevent idle connections.
		if s.server.sessionTimeout > 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.sessionTimeout)); err != nil {
				logger.Debug("ManageSieve Proxy: Failed to set read deadline", "name", s.server.name, "remote", clientAddr, "error", err)
				return
			}
		}

		// Read command from client
		line, err := s.clientReader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				logger.Debug("ManageSieve Proxy: Client timed out waiting for command", "name", s.server.name, "remote", clientAddr)
				s.sendResponse(`NO "Idle timeout"`)
				return
			}
			if err != io.EOF {
				logger.Debug("ManageSieve Proxy: Error reading from client", "name", s.server.name, "remote", clientAddr, "error", err)
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

		if s.server.debug {
			logger.Debug("ManageSieve Proxy: Client command", "name", s.server.name, "remote", clientAddr, "command", helpers.MaskSensitive(line, command, "AUTHENTICATE", "LOGIN"))
		}
		switch command {
		case "AUTHENTICATE":
			if s.server.debug {
				logger.Debug("ManageSieve Proxy: AUTHENTICATE debug", "name", s.server.name, "args_len", len(args))
				for i, arg := range args {
					logger.Debug("ManageSieve Proxy: AUTHENTICATE arg", "name", s.server.name, "index", i, "arg", arg)
				}
			}

			// Check if authentication is allowed over non-TLS connection
			if !s.isTLS && !s.server.insecureAuth {
				if s.handleAuthError(`NO "Authentication not permitted on insecure connection. Use STARTTLS first."`) {
					return
				}
				continue
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
					logger.Debug("ManageSieve Proxy: AUTHENTICATE using initial response", "name", s.server.name)
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
						logger.Debug("ManageSieve Proxy: AUTHENTICATE reading literal", "name", s.server.name, "bytes", literalSize)
					}

					// Read the literal data
					literalData := make([]byte, literalSize)
					_, err = io.ReadFull(s.clientReader, literalData)
					if err != nil {
						logger.Debug("ManageSieve Proxy: Error reading literal data", "name", s.server.name, "error", err)
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
					logger.Debug("ManageSieve Proxy: AUTHENTICATE sending continuation", "name", s.server.name)
				}
				// Send continuation and wait for response
				s.sendContinuation()

				// Read SASL response
				saslLine, err = s.clientReader.ReadString('\n')
				if err != nil {
					logger.Debug("ManageSieve Proxy: Error reading SASL response", "name", s.server.name, "error", err)
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
				logger.Debug("ManageSieve Proxy: Authentication failed", "name", s.server.name, "user", authnID, "error", err)
				// This is an actual authentication failure, not a protocol error.
				// The rate limiter handles this, so we don't count it as a command error.
				s.sendResponse(`NO "Authentication failed"`)
				continue
			}

			// Parse and use base address (without +detail) for backend impersonation
			if addr, err := server.NewAddress(authnID); err == nil {
				s.username = addr.BaseAddress()
			} else {
				s.username = authnID // Fallback if parsing fails
			}

			// Connect to backend and authenticate
			if err := s.connectToBackendAndAuth(); err != nil {
				logger.Debug("ManageSieve Proxy: Backend connection/auth failed", "name", s.server.name, "user", authnID, "error", err)
				s.sendResponse(`NO "Backend server temporarily unavailable"`)
				continue
			}

			// Register connection
			if err := s.registerConnection(); err != nil {
				logger.Debug("ManageSieve Proxy: Failed to register connection", "name", s.server.name, "user", authnID, "error", err)
			}

			// Set username on client connection for timeout logging
			if soraConn, ok := s.clientConn.(interface{ SetUsername(string) }); ok {
				soraConn.SetUsername(s.username)
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
				logger.Debug("ManageSieve Proxy: Error sending capabilities", "name", s.server.name, "error", err)
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
				logger.Debug("ManageSieve Proxy: Failed to send STARTTLS response", "name", s.server.name, "error", err)
				return
			}

			// Load TLS config: Use global TLS manager config if available, otherwise load from files
			var tlsConfig *tls.Config
			if s.server.tlsConfig != nil {
				// Use global TLS manager (e.g., Let's Encrypt autocert)
				// Don't clone - use directly like the non-proxy ManageSieve server does
				tlsConfig = s.server.tlsConfig
			} else if s.server.tlsCertFile != "" && s.server.tlsKeyFile != "" {
				// Load from cert files
				cert, err := tls.LoadX509KeyPair(s.server.tlsCertFile, s.server.tlsKeyFile)
				if err != nil {
					logger.Debug("ManageSieve Proxy: Failed to load TLS certificate", "name", s.server.name, "error", err)
					return
				}

				tlsConfig = &tls.Config{
					Certificates:  []tls.Certificate{cert},
					ClientAuth:    tls.NoClientCert,
					Renegotiation: tls.RenegotiateNever,
				}
				if s.server.tlsVerify {
					tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
				}
			} else {
				logger.Debug("ManageSieve Proxy: STARTTLS config error", "name", s.server.name)
				if s.handleAuthError(`NO "STARTTLS configuration error"`) {
					return
				}
				continue
			}

			// Upgrade connection to TLS
			tlsConn := tls.Server(s.clientConn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				logger.Debug("ManageSieve Proxy: TLS handshake failed", "name", s.server.name, "error", err)
				return
			}

			// Update session with TLS connection
			s.clientConn = tlsConn
			s.clientReader = bufio.NewReader(tlsConn)
			s.clientWriter = bufio.NewWriter(tlsConn)
			s.isTLS = true

			if s.server.debug {
				logger.Debug("ManageSieve Proxy: STARTTLS negotiation successful", "name", s.server.name, "remote", clientAddr)
			}

			// Re-send greeting with updated capabilities (now with SASL mechanisms available)
			if err := s.sendGreeting(); err != nil {
				logger.Debug("ManageSieve Proxy: Failed to send greeting after STARTTLS", "name", s.server.name, "error", err)
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
			logger.Debug("ManageSieve Proxy: Failed to clear read deadline", "name", s.server.name, "remote", clientAddr, "error", err)
		}
	}

	// Start proxying only if backend connection was successful
	if s.backendConn != nil {
		if s.server.debug {
			logger.Debug("ManageSieve Proxy: Starting proxy", "name", s.server.name, "user", s.username)
		}
		s.startProxy()
	} else {
		logger.Debug("ManageSieve Proxy: Cannot start proxy - no backend connection", "name", s.server.name, "user", s.username)
	}
}

// handleAuthError increments the error count, sends an error response, and
// returns true if the connection should be dropped.
func (s *Session) handleAuthError(response string) bool {
	s.errorCount++
	s.sendResponse(response)
	if s.errorCount >= maxAuthErrors {
		logger.Debug("ManageSieve Proxy: Too many auth errors - dropping connection", "name", s.server.name, "remote", s.clientConn.RemoteAddr())
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
		logger.Debug("ManageSieve Proxy: Attempting prelookup auth", "name", s.server.name, "user", username)
	}
	routingInfo, authResult, err := s.server.connManager.AuthenticateAndRoute(ctx, username, password)

	if err != nil {
		// Categorize the error type to determine fallback behavior
		if errors.Is(err, proxy.ErrPrelookupInvalidResponse) {
			// Invalid response from prelookup (malformed 2xx) - this is a server bug, fail hard
			logger.Debug("ManageSieve Proxy: Prelookup invalid response - server bug", "name", s.server.name, "user", username, "error", err)
			s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
			metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", "failure").Inc()
			return fmt.Errorf("prelookup server error: invalid response")
		}

		if errors.Is(err, proxy.ErrPrelookupTransient) {
			// Transient error (network, 5xx, circuit breaker) - check fallback config
			if s.server.prelookupConfig != nil && s.server.prelookupConfig.FallbackDefault {
				if s.server.debug {
					logger.Debug("ManageSieve Proxy: Prelookup transient error - fallback enabled", "name", s.server.name, "user", username, "error", err)
				}
				// Fallthrough to main DB auth
			} else {
				logger.Debug("ManageSieve Proxy: Prelookup transient error - fallback disabled", "name", s.server.name, "user", username, "error", err)
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", "failure").Inc()
				return fmt.Errorf("prelookup service unavailable")
			}
		} else {
			// Unknown error type - log and fallthrough
			if s.server.debug {
				logger.Debug("ManageSieve Proxy: Prelookup unknown error - attempting fallback", "name", s.server.name, "user", username, "error", err)
			}
			// Fallthrough to main DB auth
		}
	} else {
		switch authResult {
		case proxy.AuthSuccess:
			// Prelookup auth was successful. Use the accountID and flag from the prelookup result.
			if s.server.debug {
				logger.Debug("ManageSieve Proxy: Prelookup auth successful", "name", s.server.name, "user", username, "account_id", routingInfo.AccountID)
				logger.Debug("ManageSieve Proxy: Prelookup routing", "name", s.server.name, "server", routingInfo.ServerAddress, "tls", routingInfo.RemoteTLS, "starttls", routingInfo.RemoteTLSUseStartTLS, "tls_verify", routingInfo.RemoteTLSVerify, "proxy_protocol", routingInfo.RemoteUseProxyProtocol)
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
			logger.Debug("ManageSieve Proxy: Prelookup auth failed - bad password", "name", s.server.name, "user", username)
			s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
			metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", "failure").Inc()
			return fmt.Errorf("authentication failed")

		case proxy.AuthTemporarilyUnavailable:
			// Prelookup service is temporarily unavailable - tell user to retry later
			logger.Debug("ManageSieve Proxy: Prelookup service temporarily unavailable", "name", s.server.name, "user", username)
			metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", "unavailable").Inc()
			return fmt.Errorf("authentication service temporarily unavailable, please try again later")

		case proxy.AuthUserNotFound:
			// User not found in prelookup (404). This means the user is NOT in the other system.
			// Always fall through to main DB auth - this is the expected behavior for partitioning.
			if s.server.debug {
				logger.Debug("ManageSieve Proxy: User not found in prelookup - trying main DB", "name", s.server.name, "user", username)
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
		logger.Debug("ManageSieve Proxy: Authenticating via main DB", "name", s.server.name, "user", username)
	}
	// Use base address (without +detail) for authentication
	accountID, err := s.server.rdb.AuthenticateWithRetry(ctx, address.BaseAddress(), password)
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
		logger.Debug("ManageSieve Proxy: Error determining route", "name", s.server.name, "user", s.username, "error", err)
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
			Renegotiation:      tls.RenegotiateNever,
		}
		if s.server.debug {
			logger.Debug("ManageSieve Proxy: Using prelookup StartTLS settings", "name", s.server.name, "remote_tls_verify", s.routingInfo.RemoteTLSVerify)
		}
	} else if s.server.connManager.IsRemoteStartTLS() {
		// Global proxy config specified StartTLS
		shouldUseStartTLS = true
		tlsConfig = s.server.connManager.GetTLSConfig()
		if s.server.debug {
			logger.Debug("ManageSieve Proxy: Using global StartTLS settings", "name", s.server.name)
		}
	}

	if shouldUseStartTLS && tlsConfig != nil {
		if s.server.debug {
			logger.Debug("ManageSieve Proxy: Negotiating StartTLS with backend", "name", s.server.name, "backend", actualAddr, "insecure_skip_verify", tlsConfig.InsecureSkipVerify)
		}

		// Send STARTTLS command
		_, err := backendWriter.WriteString("STARTTLS\r\n")
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("failed to send STARTTLS command: %w", err)
		}
		backendWriter.Flush()

		// Read STARTTLS response
		response, err := backendReader.ReadString('\n')
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("failed to read STARTTLS response: %w", err)
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

		logger.Debug("ManageSieve Proxy: StartTLS negotiation successful with backend", "name", s.server.name, "backend", actualAddr)
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
		logger.Debug("ManageSieve Proxy: Auth string format", "name", s.server.name, "authorize_id", s.username, "authenticate_id", string(s.server.masterSASLUsername))
		logger.Debug("ManageSieve Proxy: Sending AUTHENTICATE command", "name", s.server.name, "encoded", encoded)
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
		logger.Debug("ManageSieve Proxy: Backend auth response", "name", s.server.name, "response", strings.TrimSpace(response))
	}

	if !strings.HasPrefix(response, "OK") {
		return fmt.Errorf("backend authentication failed: %s", response)
	}

	logger.Debug("ManageSieve Proxy: Backend authentication successful", "name", s.server.name, "user", s.username)

	return nil
}

// startProxy starts bidirectional proxying between client and backend.
func (s *Session) startProxy() {
	if s.backendConn == nil {
		logger.Debug("ManageSieve Proxy: Backend connection not established", "name", s.server.name, "user", s.username)
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
			logger.Debug("ManageSieve Proxy: Error copying from client to backend", "name", s.server.name, "error", err)
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
			logger.Debug("ManageSieve Proxy: Error copying from backend to client", "name", s.server.name, "error", err)
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

	// Remove session from active tracking
	s.server.removeSession(s)

	// Decrement current connections metric
	metrics.ConnectionsCurrent.WithLabelValues("managesieve_proxy").Dec()

	// Unregister connection asynchronously - don't block session cleanup
	if s.accountID > 0 {
		accountID := s.accountID
		clientAddr := s.clientConn.RemoteAddr().String()
		username := s.username
		connTracker := s.server.connTracker
		serverName := s.server.name

		// Fire-and-forget: unregister in background to avoid blocking session teardown
		go func() {
			// Check if connection tracker is available before using it
			if connTracker == nil || !connTracker.IsEnabled() {
				return
			}

			// Use a new background context for this final operation, as s.ctx is likely already cancelled.
			// Use configurable timeout from connection tracker to handle database load spikes during heavy connection churn.
			timeout := connTracker.GetOperationTimeout()
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if err := connTracker.UnregisterConnection(ctx, accountID, "ManageSieve", clientAddr); err != nil {
				// Connection tracking is non-critical monitoring data, so log but continue
				logger.Debug("ManageSieve Proxy: Failed to unregister connection", "name", serverName, "user", username, "error", err)
			}
		}()
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
		return s.server.connTracker.RegisterConnection(ctx, s.accountID, s.username, "ManageSieve", clientAddr)
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

	// Register for kick notifications
	kickChan := s.server.connTracker.RegisterSession(s.accountID)
	defer s.server.connTracker.UnregisterSession(s.accountID, kickChan)

	for {
		select {
		case <-kickChan:
			// Kick notification received - close connections
			logger.Debug("ManageSieve Proxy: Connection kicked", "name", s.server.name, "user", s.username, "client", clientAddr, "backend", s.serverAddr)
			s.clientConn.Close()
			s.backendConn.Close()
			return
		case <-ctx.Done():
			return
		}
	}
}

func isClosingError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}
