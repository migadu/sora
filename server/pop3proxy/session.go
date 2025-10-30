package pop3proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/migadu/sora/logger"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// maxAuthErrors is the number of invalid commands tolerated during the
// authentication phase before the connection is dropped.
const maxAuthErrors = 2

type POP3ProxySession struct {
	server             *POP3ProxyServer
	clientConn         net.Conn
	backendConn        net.Conn
	ctx                context.Context
	cancel             context.CancelFunc
	RemoteIP           string
	username           string
	accountID          int64
	isPrelookupAccount bool
	routingInfo        *proxy.UserRoutingInfo
	serverAddr         string
	authenticated      bool
	mutex              sync.Mutex
	errorCount         int
}

func (s *POP3ProxySession) handleConnection() {
	defer s.cancel()
	defer s.close()

	// Perform TLS handshake if this is a TLS connection
	if tlsConn, ok := s.clientConn.(interface{ PerformHandshake() error }); ok {
		if err := tlsConn.PerformHandshake(); err != nil {
			logger.Debug("POP3 Proxy: TLS handshake failed", "proxy", s.server.name, "remote", s.RemoteIP, "error", err)
			return
		}
	}

	// Send initial greeting to client
	writer := bufio.NewWriter(s.clientConn)
	writer.WriteString("+OK POP3 proxy ready\r\n")
	writer.Flush()

	reader := bufio.NewReader(s.clientConn)

	for {
		// Set a read deadline for the client command to prevent idle connections.
		if s.server.sessionTimeout > 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.sessionTimeout)); err != nil {
				logger.Debug("POP3 Proxy: Failed to set read deadline", "proxy", s.server.name, "remote", s.RemoteIP, "error", err)
				return
			}
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				logger.Debug("POP3 Proxy: Client timed out waiting for command", "proxy", s.server.name, "remote", s.RemoteIP)
				writer.WriteString("-ERR Idle timeout, closing connection\r\n")
				writer.Flush()
				return
			}
			if err == io.EOF {
				logger.Debug("POP3 Proxy: Client dropped connection", "proxy", s.server.name, "remote", s.RemoteIP)
			} else {
				logger.Debug("POP3 Proxy: Client read error", "proxy", s.server.name, "remote", s.RemoteIP, "error", err)
			}
			return
		}

		line = strings.TrimSpace(line)

		// Log client command with password masking if debug is enabled
		s.Log("C: %s\r\n", line)

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue // Ignore empty lines
		}
		cmd := strings.ToUpper(parts[0])

		switch cmd {
		case "CAPA":
			// Return proxy capabilities before authentication
			writer.WriteString("+OK Capability list follows\r\n")
			writer.WriteString("USER\r\n")
			writer.WriteString("SASL PLAIN\r\n")
			writer.WriteString("RESP-CODES\r\n")
			writer.WriteString("AUTH-RESP-CODE\r\n")
			writer.WriteString("IMPLEMENTATION Sora-POP3-Proxy\r\n")
			writer.WriteString(".\r\n")
			writer.Flush()

		case "USER":
			if len(parts) < 2 {
				if s.handleAuthError(writer, "-ERR Missing username\r\n") {
					return
				}
				continue
			}
			// Remove quotes if present for compatibility
			s.username = server.UnquoteString(parts[1])
			writer.WriteString("+OK User accepted\r\n")
			writer.Flush()

		case "PASS":
			if s.username == "" {
				if s.handleAuthError(writer, "-ERR Must provide USER first\r\n") {
					return
				}
				continue
			}
			if len(parts) < 2 {
				if s.handleAuthError(writer, "-ERR Missing password\r\n") {
					return
				}
				continue
			}
			// Remove quotes if present for compatibility
			password := server.UnquoteString(parts[1])

			if err := s.authenticate(s.username, password); err != nil {
				// Check if the error is due to a backend connection failure.
				if strings.Contains(err.Error(), "failed to connect to backend") {
					writer.WriteString("-ERR [SYS/TEMP] Backend server temporarily unavailable\r\n")
				} else {
					writer.WriteString("-ERR Authentication failed\r\n")
				}
				writer.Flush()
				logger.Debug("POP3 Proxy: Authentication failed", "proxy", s.server.name, "user", s.username, "remote", s.RemoteIP, "error", err)
				continue
			}

			writer.WriteString("+OK Authentication successful\r\n")
			writer.Flush()

			// Clear the read deadline before moving to the proxying phase, which sets its own.
			if s.server.sessionTimeout > 0 {
				if err := s.clientConn.SetReadDeadline(time.Time{}); err != nil {
					logger.Debug("POP3 Proxy: Warning - failed to clear read deadline", "proxy", s.server.name, "remote", s.RemoteIP, "error", err)
				}
			}

			// Register connection
			if err := s.registerConnection(); err != nil {
				logger.Debug("POP3 Proxy: Failed to register connection", "proxy", s.server.name, "user", s.username, "remote", s.RemoteIP, "error", err)
			}

			// Start proxying
			s.startProxying()
			return

		case "AUTH":
			if len(parts) < 2 {
				if s.handleAuthError(writer, "-ERR Missing authentication mechanism\r\n") {
					return
				}
				continue
			}

			// Remove quotes from mechanism if present for compatibility
			mechanism := server.UnquoteString(parts[1])
			mechanism = strings.ToUpper(mechanism)
			if mechanism != "PLAIN" {
				if s.handleAuthError(writer, "-ERR Unsupported authentication mechanism\r\n") {
					return
				}
				continue
			}

			var authData string
			if len(parts) > 2 {
				// Initial response provided - remove quotes if present
				authData = server.UnquoteString(parts[2])
			} else {
				// Request the authentication data
				writer.WriteString("+ \r\n")
				writer.Flush()

				// Read the authentication data
				authLine, err := reader.ReadString('\n')
				if err != nil {
					writer.WriteString("-ERR Authentication failed\r\n")
					writer.Flush()
					continue
				}
				authData = strings.TrimSpace(authLine)
				// Remove quotes if present in continuation response
				authData = server.UnquoteString(authData)
			}

			// Check for cancellation
			if authData == "*" {
				writer.WriteString("-ERR Authentication cancelled\r\n")
				writer.Flush()
				continue
			}

			// Decode base64
			decoded, err := base64.StdEncoding.DecodeString(authData)
			if err != nil {
				if s.handleAuthError(writer, "-ERR Invalid authentication data\r\n") {
					return
				}
				continue
			}

			// Parse SASL PLAIN format: [authz-id] \0 authn-id \0 password
			authParts := strings.Split(string(decoded), "\x00")
			if len(authParts) != 3 {
				if s.handleAuthError(writer, "-ERR Invalid authentication format\r\n") {
					return
				}
				continue
			}

			authzID := authParts[0]
			authnID := authParts[1]
			password := authParts[2]

			// For proxy, we expect authzID to be empty or same as authnID
			// Authorization identity is handled by master SASL on the backend
			if authzID != "" && authzID != authnID {
				if s.handleAuthError(writer, "-ERR Authorization identity not supported on proxy (configure master SASL on backend)\r\n") {
					return
				}
				continue
			}

			if err := s.authenticate(authnID, password); err != nil {
				// Check if the error is due to a backend connection failure.
				if strings.Contains(err.Error(), "failed to connect to backend") {
					writer.WriteString("-ERR [SYS/TEMP] Backend server temporarily unavailable\r\n")
				} else {
					writer.WriteString("-ERR Authentication failed\r\n")
				}
				writer.Flush()
				logger.Debug("POP3 Proxy: SASL authentication failed", "proxy", s.server.name, "user", authnID, "remote", s.RemoteIP, "error", err)
				continue
			}

			writer.WriteString("+OK Authentication successful\r\n")
			writer.Flush()

			// Clear the read deadline before moving to the proxying phase, which sets its own.
			if s.server.sessionTimeout > 0 {
				if err := s.clientConn.SetReadDeadline(time.Time{}); err != nil {
					logger.Debug("POP3 Proxy: Warning - failed to clear read deadline", "proxy", s.server.name, "user", authnID, "error", err)
				}
			}

			// Register connection
			if err := s.registerConnection(); err != nil {
				logger.Debug("POP3 Proxy: Failed to register connection for user %s from %s: %v", "name", s.server.name, "param", authnID, s.RemoteIP, err)
			}

			// Start proxying
			s.startProxying()
			return

		case "QUIT":
			writer.WriteString("+OK Goodbye\r\n")
			writer.Flush()
			return

		default:
			if s.handleAuthError(writer, "-ERR Command not available before authentication\r\n") {
				return
			}
			continue
		}
	}
}

// handleAuthError increments the error count, sends an error response, and
// returns true if the connection should be dropped.
func (s *POP3ProxySession) handleAuthError(writer *bufio.Writer, response string) bool {
	s.errorCount++
	writer.WriteString(response)
	writer.Flush()
	if s.errorCount >= maxAuthErrors {
		logger.Debug("POP3 Proxy: Too many authentication errors, dropping connection", "proxy", s.server.name, "remote", s.RemoteIP)
		// Send a final error message before closing.
		writer.WriteString("-ERR Too many invalid commands, closing connection\r\n")
		writer.Flush()
		return true
	}
	return false
}

// Log logs a client command with password masking if debug is enabled.
func (s *POP3ProxySession) Log(format string, args ...interface{}) {
	if s.server.debugWriter != nil {
		message := fmt.Sprintf(format, args...)
		s.server.debugWriter.Write([]byte(message))
	}
}

func (s *POP3ProxySession) authenticate(username, password string) error {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	// Apply progressive authentication delay BEFORE any other checks
	remoteAddr := s.clientConn.RemoteAddr()
	server.ApplyAuthenticationDelay(ctx, s.server.authLimiter, remoteAddr, "POP3-PROXY")

	// Check if the authentication attempt is allowed by the rate limiter using proxy-aware methods
	if err := s.server.authLimiter.CanAttemptAuthWithProxy(ctx, s.clientConn, nil, username); err != nil {
		// Don't record as auth failure - this is rate limiting, not authentication failure
		metrics.ProtocolErrors.WithLabelValues("pop3_proxy", "AUTH", "rate_limited", "client_error").Inc()
		return err
	}

	// Try prelookup authentication/routing first if configured
	// Skip strict address validation if prelookup is enabled, as it may support master tokens
	// with syntax like user@domain.com@TOKEN (multiple @ symbols)
	if s.server.connManager.HasRouting() {
		if s.server.debug {
			logger.Debug("POP3 Proxy: Attempting authentication via prelookup", "proxy", s.server.name, "user", username)
		}
		routingInfo, authResult, err := s.server.connManager.AuthenticateAndRoute(ctx, username, password)

		if err != nil {
			// Categorize the error type to determine fallback behavior
			if errors.Is(err, proxy.ErrPrelookupInvalidResponse) {
				// Invalid response from prelookup (malformed 2xx) - this is a server bug, fail hard
				logger.Debug("POP3 Proxy: Prelookup returned invalid response - server bug, rejecting authentication", "proxy", s.server.name, "user", username, "error", err)
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, nil, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "failure").Inc()
				return fmt.Errorf("prelookup server error: invalid response")
			}

			if errors.Is(err, proxy.ErrPrelookupTransient) {
				// Transient error (network, 5xx, circuit breaker) - check fallback config
				if s.server.prelookupConfig != nil && s.server.prelookupConfig.FallbackDefault {
					if s.server.debug {
						logger.Debug("POP3 Proxy: Prelookup transient error, fallback enabled - attempting main DB", "proxy", s.server.name, "user", username, "error", err)
					}
					// Fallthrough to main DB auth
				} else {
					logger.Debug("POP3 Proxy: Prelookup transient error, fallback disabled - rejecting authentication", "proxy", s.server.name, "user", username, "error", err)
					s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, nil, username, false)
					metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "failure").Inc()
					return fmt.Errorf("prelookup service unavailable")
				}
			} else {
				// Unknown error type - fallthrough to main DB auth
			}
		} else {
			switch authResult {
			case proxy.AuthSuccess:
				// Prelookup auth was successful.
				if s.server.debug {
					logger.Debug("POP3 Proxy: Prelookup authentication successful", "proxy", s.server.name, "user", username, "account_id", routingInfo.AccountID)
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

				// Set username on client connection for timeout logging
				if soraConn, ok := s.clientConn.(interface{ SetUsername(string) }); ok {
					soraConn.SetUsername(s.username)
				}

				s.authenticated = true
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, nil, username, true)
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "success").Inc()
				// For metrics, use username as-is (may contain token, but that's ok for tracking)
				if addr, err := server.NewAddress(username); err == nil {
					metrics.TrackDomainConnection("pop3_proxy", addr.Domain())
					metrics.TrackUserActivity("pop3_proxy", addr.FullAddress(), "connection", 1)
				}

				// Connect to backend
				if err := s.connectToBackend(); err != nil {
					return fmt.Errorf("failed to connect to backend: %w", err)
				}
				return nil // Authentication complete

			case proxy.AuthFailed:
				// User found in prelookup, but password was wrong. Reject immediately.
				logger.Debug("POP3 Proxy: Prelookup authentication failed - bad password", "proxy", s.server.name, "user", username, "remote", s.RemoteIP)
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, nil, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "failure").Inc()
				return fmt.Errorf("authentication failed")

			case proxy.AuthTemporarilyUnavailable:
				// Prelookup service is temporarily unavailable - tell user to retry later
				logger.Debug("POP3 Proxy: Prelookup service temporarily unavailable", "proxy", s.server.name, "user", username)
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "unavailable").Inc()
				return fmt.Errorf("authentication service temporarily unavailable, please try again later")

			case proxy.AuthUserNotFound:
				// User not found in prelookup (404). This means the user is NOT in the other system.
				// Always fall through to main DB auth - this is the expected behavior for partitioning.
				if s.server.debug {
					logger.Debug("POP3 Proxy: User not found in prelookup, attempting main DB", "proxy", s.server.name, "user", username)
				}
			}
		}
	}

	// Fallback to main DB - validate address format for normal email
	address, err := server.NewAddress(username)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	if s.server.debug {
		logger.Debug("POP3 Proxy: Authenticating user via main database", "proxy", s.server.name, "user", username)
	}
	// Use base address (without +detail) for authentication
	accountID, err := s.server.rdb.AuthenticateWithRetry(ctx, address.BaseAddress(), password)
	if err != nil {
		s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, nil, username, false)
		metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "failure").Inc()
		return fmt.Errorf("authentication failed: %w", err)
	}

	s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, nil, username, true)

	// Track successful authentication.
	metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "success").Inc()
	metrics.TrackDomainConnection("pop3_proxy", address.Domain())
	metrics.TrackUserActivity("pop3_proxy", address.FullAddress(), "connection", 1)

	// Store user details on the session
	s.authenticated = true
	// Use base address (without +detail) for backend impersonation
	s.username = address.BaseAddress()
	s.accountID = accountID
	s.isPrelookupAccount = false // Authenticated against the main DB

	// Set username on client connection for timeout logging
	if soraConn, ok := s.clientConn.(interface{ SetUsername(string) }); ok {
		soraConn.SetUsername(s.username)
	}

	// Connect to backend
	if err := s.connectToBackend(); err != nil {
		return fmt.Errorf("failed to connect to backend: %w", err)
	}

	return nil
}

func (s *POP3ProxySession) connectToBackend() error {
	routeResult, err := proxy.DetermineRoute(proxy.RouteParams{
		Ctx:                s.ctx,
		Username:           s.username,
		Protocol:           "pop3",
		IsPrelookupAccount: s.isPrelookupAccount,
		RoutingInfo:        s.routingInfo,
		ConnManager:        s.server.connManager,
		EnableAffinity:     s.server.enableAffinity,
		ProxyName:          "POP3 Proxy",
	})
	if err != nil {
		logger.Debug("POP3 Proxy: Error determining route", "proxy", s.server.name, "user", s.username, "error", err)
	}

	// Update session routing info if it was fetched by DetermineRoute
	s.routingInfo = routeResult.RoutingInfo
	preferredAddr := routeResult.PreferredAddr
	isPrelookupRoute := routeResult.IsPrelookupRoute

	// 4. Connect using the determined address (or round-robin if empty)
	// Track which routing method was used for this connection.
	metrics.ProxyRoutingMethod.WithLabelValues("pop3", routeResult.RoutingMethod).Inc()

	clientHost, clientPort := server.GetHostPortFromAddr(s.clientConn.RemoteAddr())
	serverHost, serverPort := server.GetHostPortFromAddr(s.clientConn.LocalAddr())
	backendConn, actualAddr, err := s.server.connManager.ConnectWithProxy(
		s.ctx,
		preferredAddr,
		clientHost, clientPort, serverHost, serverPort, s.routingInfo,
	)
	if err != nil {
		metrics.ProxyBackendConnections.WithLabelValues("pop3", "failure").Inc()
		return fmt.Errorf("failed to connect to backend: %w", err)
	}
	if isPrelookupRoute && actualAddr != preferredAddr {
		// The prelookup route specified a server, but we connected to a different one.
		// This means the preferred server failed and the connection manager fell back.
		// For prelookup routes, this is a hard failure.
		backendConn.Close()
		metrics.ProxyBackendConnections.WithLabelValues("pop3", "failure").Inc()
		return fmt.Errorf("prelookup route to %s failed, and fallback is disabled for prelookup routes", preferredAddr)
	}

	metrics.ProxyBackendConnections.WithLabelValues("pop3", "success").Inc()
	s.backendConn = backendConn
	s.serverAddr = actualAddr

	// Record successful connection for future affinity if enabled
	if s.server.enableAffinity && !s.isPrelookupAccount && actualAddr != "" {
		proxy.UpdateAffinityAfterConnection(proxy.RouteParams{
			Username:           s.username,
			Protocol:           "pop3",
			IsPrelookupAccount: s.isPrelookupAccount,
			ConnManager:        s.server.connManager,
			EnableAffinity:     s.server.enableAffinity,
			ProxyName:          "POP3 Proxy",
		}, actualAddr, routeResult.RoutingMethod == "affinity")
	}

	// Read backend greeting
	backendReader := bufio.NewReader(s.backendConn)
	greeting, err := backendReader.ReadString('\n')
	if err != nil {
		s.backendConn.Close()
		return fmt.Errorf("failed to read backend greeting: %w", err)
	}

	if !strings.HasPrefix(greeting, "+OK") {
		s.backendConn.Close()
		return fmt.Errorf("unexpected backend greeting: %s", greeting)
	}

	backendWriter := bufio.NewWriter(s.backendConn)

	// Send XCLIENT command to backend with forwarding parameters if enabled.
	// This MUST be done before authenticating.
	useXCLIENT := s.server.remoteUseXCLIENT
	// Override with routing-specific setting if available
	if s.routingInfo != nil {
		useXCLIENT = s.routingInfo.RemoteUseXCLIENT
	}
	if useXCLIENT {
		if err := s.sendForwardingParametersToBackend(backendWriter, backendReader); err != nil {
			logger.Debug("POP3 Proxy: Failed to send forwarding parameters to backend", "proxy", s.server.name, "error", err)
			// Continue anyway - forwarding parameters are not critical for functionality
		}
	}

	// Authenticate to backend using master SASL credentials via AUTH PLAIN
	authString := fmt.Sprintf("%s\x00%s\x00%s", s.username, s.server.masterSASLUsername, s.server.masterSASLPassword)
	encoded := base64.StdEncoding.EncodeToString([]byte(authString))

	if _, err := backendWriter.WriteString(fmt.Sprintf("AUTH PLAIN %s\r\n", encoded)); err != nil {
		s.backendConn.Close()
		return fmt.Errorf("failed to send AUTH PLAIN to backend: %w", err)
	}
	if err := backendWriter.Flush(); err != nil {
		s.backendConn.Close()
		return fmt.Errorf("failed to flush AUTH PLAIN to backend: %w", err)
	}

	// Read auth response
	authResp, err := backendReader.ReadString('\n')
	if err != nil {
		s.backendConn.Close()
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if !strings.HasPrefix(authResp, "+OK") {
		s.backendConn.Close()
		return fmt.Errorf("backend authentication failed: %s", authResp)
	}

	if s.server.debug {
		logger.Debug("POP3 Proxy: Authenticated to backend", "proxy", s.server.name, "user", s.username)
	}

	return nil
}

func (s *POP3ProxySession) startProxying() {
	if s.backendConn == nil {
		logger.Debug("POP3 Proxy: Backend connection not established", "proxy", s.server.name, "user", s.username)
		return
	}

	defer s.backendConn.Close()

	if s.server.debug {
		logger.Debug("POP3 Proxy: starting bidirectional proxy for %s", "name", s.server.name, "param", s.username)
	}

	var wg sync.WaitGroup

	// Start activity updater
	activityCtx, activityCancel := context.WithCancel(s.ctx)
	defer activityCancel()
	go s.updateActivityPeriodically(activityCtx)

	// Copy from client to backend with command filtering
	wg.Add(1)
	go func() {
		defer wg.Done()
		// If this copy returns, it means the client has closed the connection or there was an error.
		// We must close the backend connection to unblock the other copy operation.
		defer s.backendConn.Close()
		s.filteredCopyClientToBackend()
	}()

	// Copy from backend to client
	wg.Add(1)
	go func() {
		defer wg.Done()
		// If this copy returns, it means the backend has closed the connection or there was an error.
		// We must close the client connection to unblock the other copy operation.
		defer s.clientConn.Close()
		bytesOut, err := io.Copy(s.clientConn, s.backendConn)
		metrics.BytesThroughput.WithLabelValues("pop3_proxy", "out").Add(float64(bytesOut))
		if err != nil && !isClosingError(err) {
			logger.Debug("POP3 Proxy: error copying backend to client for %s: %v", "name", s.server.name, "param", s.username, err)
		}
	}()

	// This goroutine will unblock the io.Copy operations when the session context is cancelled.
	go func() {
		<-s.ctx.Done()
		s.clientConn.Close()
		s.backendConn.Close()
	}()

	wg.Wait() // Wait for both copy operations to finish
	if s.server.debug {
		logger.Debug("POP3 Proxy: proxy session ended for %s", "name", s.server.name, "param", s.username)
	}
}

// close closes all connections and unregisters from tracking.
func (s *POP3ProxySession) close() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Remove session from active tracking
	s.server.removeSession(s)

	// Decrement current connections metric
	metrics.ConnectionsCurrent.WithLabelValues("pop3_proxy").Dec()

	// Unregister connection asynchronously - don't block session cleanup
	if s.accountID > 0 {
		accountID := s.accountID
		remoteIP := s.RemoteIP
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

			if err := connTracker.UnregisterConnection(ctx, accountID, "POP3", remoteIP); err != nil {
				// Connection tracking is non-critical monitoring data, so log but continue
				logger.Debug("POP3 Proxy: Failed to unregister connection", "name", serverName, "user", username, "error", err)
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
func (s *POP3ProxySession) registerConnection() error {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	if s.server.connTracker != nil && s.server.connTracker.IsEnabled() {
		return s.server.connTracker.RegisterConnection(ctx, s.accountID, s.username, "POP3", s.RemoteIP)
	}
	return nil
}

// updateActivityPeriodically updates the connection activity in the database.
func (s *POP3ProxySession) updateActivityPeriodically(ctx context.Context) {
	// If connection tracking is disabled, do nothing and wait for session to end.
	if s.server.connTracker == nil || !s.server.connTracker.IsEnabled() {
		<-ctx.Done()
		return
	}

	// Register for kick notifications
	kickChan := s.server.connTracker.RegisterSession(s.accountID)
	defer s.server.connTracker.UnregisterSession(s.accountID, kickChan)

	for {
		select {
		case <-kickChan:
			// Kick notification received - close connections
			logger.Debug("POP3 Proxy: Connection kicked - disconnecting user: %s (client: %s, backend: %s)", "name", s.server.name, "param", s.username, s.RemoteIP, s.serverAddr)
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

// filteredCopyClientToBackend copies data from client to backend, filtering out empty commands
func (s *POP3ProxySession) filteredCopyClientToBackend() {
	reader := bufio.NewReader(s.clientConn)
	writer := bufio.NewWriter(s.backendConn)
	var totalBytesIn int64
	defer func() {
		// Record total bytes when the copy loop exits
		metrics.BytesThroughput.WithLabelValues("pop3_proxy", "in").Add(float64(totalBytesIn))
	}()

	for {
		// Set a read deadline to prevent idle authenticated connections.
		if s.server.sessionTimeout > 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.sessionTimeout)); err != nil {
				logger.Debug("POP3 Proxy: Failed to set read deadline for %s: %v", "name", s.server.name, "param", s.username, err)
				return
			}
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				logger.Debug("POP3 Proxy: Idle timeout for authenticated user, closing connection", "proxy", s.server.name, "user", s.username)
				return
			}
			if err != io.EOF && !isClosingError(err) {
				logger.Debug("POP3 Proxy: error reading from client for %s: %v", "name", s.server.name, "param", s.username, err)
			}
			return
		}

		// Check for context cancellation
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Skip empty lines (just \r\n or \n)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Forward the command to backend
		n, err := writer.WriteString(line)
		totalBytesIn += int64(n)
		if err != nil {
			if !isClosingError(err) {
				logger.Debug("POP3 Proxy: error writing to backend for %s: %v", "name", s.server.name, "param", s.username, err)
			}
			return
		}

		if err := writer.Flush(); err != nil {
			if !isClosingError(err) {
				logger.Debug("POP3 Proxy: error flushing to backend for %s: %v", "name", s.server.name, "param", s.username, err)
			}
			return
		}
	}
}
