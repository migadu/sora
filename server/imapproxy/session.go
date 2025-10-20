package imapproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
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

// Session represents an IMAP proxy session.
type Session struct {
	server             *Server
	clientConn         net.Conn
	backendConn        net.Conn
	backendReader      *bufio.Reader
	backendWriter      *bufio.Writer
	clientReader       *bufio.Reader
	clientWriter       *bufio.Writer
	username           string
	accountID          int64
	isPrelookupAccount bool
	routingInfo        *proxy.UserRoutingInfo
	serverAddr         string
	sessionID          string // Proxy session ID for end-to-end tracing
	mu                 sync.Mutex
	ctx                context.Context
	cancel             context.CancelFunc
	errorCount         int
}

// newSession creates a new IMAP proxy session.
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
	if s.server.debug {
		log.Printf("IMAP Proxy [%s] New connection from %s", s.server.name, clientAddr)
	}

	// Perform TLS handshake if this is a TLS connection
	if tlsConn, ok := s.clientConn.(interface{ PerformHandshake() error }); ok {
		if err := tlsConn.PerformHandshake(); err != nil {
			log.Printf("IMAP Proxy [%s] TLS handshake failed for %s: %v", s.server.name, clientAddr, err)
			return
		}
	}

	// Send greeting
	if err := s.sendGreeting(); err != nil {
		log.Printf("IMAP Proxy [%s] Failed to send greeting to %s: %v", s.server.name, clientAddr, err)
		return
	}

	// Handle authentication phase
	authenticated := false
	for !authenticated {
		// Set a read deadline for the client command to prevent idle connections
		// from sitting in the authentication phase forever.
		if s.server.sessionTimeout > 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.sessionTimeout)); err != nil {
				log.Printf("IMAP Proxy [%s] Failed to set read deadline for %s: %v", s.server.name, clientAddr, err)
				return
			}
		}

		// Read command from client
		line, err := s.clientReader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("IMAP Proxy [%s] Client %s timed out waiting for command", s.server.name, clientAddr)
				s.sendResponse("* BYE Idle timeout")
				return
			}
			if err != io.EOF {
				log.Printf("IMAP Proxy [%s] Error reading from client %s: %v", s.server.name, clientAddr, err)
			}
			return
		}

		line = strings.TrimRight(line, "\r\n")

		// Log client command with password masking if debug is enabled
		s.Log("C: %s\r\n", line)

		// Use the shared command parser. IMAP commands have tags.
		tag, command, args, err := server.ParseLine(line, true)
		if err != nil {
			// This would be a malformed line, e.g., unclosed quote.
			// Send a tagged BAD response if we have a tag.
			var resp string
			if tag != "" {
				resp = fmt.Sprintf("%s BAD %s", tag, err.Error())
			} else {
				resp = fmt.Sprintf("* BAD %s", err.Error())
			}
			if s.handleAuthError(resp) {
				return
			}
			continue
		}

		if tag == "" { // Empty line
			continue
		}
		if command == "" { // Tag only
			if s.handleAuthError(fmt.Sprintf("%s BAD Command is missing", tag)) {
				return
			}
			continue
		}

		switch command {
		case "LOGIN":
			if len(args) < 2 {
				if s.handleAuthError(fmt.Sprintf("%s NO LOGIN requires username and password", tag)) {
					return
				}
				continue
			}

			username := server.UnquoteString(args[0])
			password := server.UnquoteString(args[1])

			if err := s.authenticateUser(username, password); err != nil {
				log.Printf("IMAP Proxy [%s] Authentication failed for %s: %v", s.server.name, username, err)
				s.sendResponse(fmt.Sprintf("%s NO Authentication failed", tag))
				continue
			}

			// Only set username if it wasn't already set by prelookup (which may have extracted actual email from token)
			if s.username == "" {
				s.username = username
			}
			s.postAuthenticationSetup(tag)
			authenticated = true

		case "AUTHENTICATE":
			if len(args) < 1 || strings.ToUpper(args[0]) != "PLAIN" {
				if s.handleAuthError(fmt.Sprintf("%s NO AUTHENTICATE PLAIN is the only supported mechanism", tag)) {
					return
				}
				continue
			}

			var saslLine string
			if len(args) > 1 {
				// Initial response was provided with the command
				saslLine = server.UnquoteString(args[1])
			} else {
				// No initial response, send continuation request
				s.sendResponse("+")

				// Read SASL response from client
				var err error
				saslLine, err = s.clientReader.ReadString('\n')
				if err != nil {
					if err != io.EOF {
						log.Printf("IMAP Proxy [%s] Error reading SASL response: %v", s.server.name, err)
					}
					return // Client connection error, can't continue
				}
				// The response to a continuation can also be a quoted string.
				saslLine = server.UnquoteString(strings.TrimRight(saslLine, "\r\n"))
			}

			if saslLine == "*" {
				// Client-side cancellation is not an error we should count.
				s.sendResponse(fmt.Sprintf("%s BAD Authentication cancelled", tag))
				continue
			}

			// Decode SASL PLAIN
			decoded, err := base64.StdEncoding.DecodeString(saslLine)
			if err != nil {
				if s.handleAuthError(fmt.Sprintf("%s NO Invalid base64 encoding", tag)) {
					return
				}
				continue
			}

			parts := strings.Split(string(decoded), "\x00")
			if len(parts) != 3 {
				if s.handleAuthError(fmt.Sprintf("%s NO Invalid SASL PLAIN response", tag)) {
					return
				}
				continue
			}

			// authzID := parts[0] // Not used in proxy
			authnID := parts[1]
			password := parts[2]

			if err := s.authenticateUser(authnID, password); err != nil {
				log.Printf("IMAP Proxy [%s] Authentication failed for %s: %v", s.server.name, authnID, err)
				// This is an actual authentication failure, not a protocol error.
				// The rate limiter handles this, so we don't count it as a command error.
				s.sendResponse(fmt.Sprintf("%s NO Authentication failed", tag))
				continue
			}

			// Only set username if it wasn't already set by prelookup (which may have extracted actual email from token)
			if s.username == "" {
				s.username = authnID
			}
			s.postAuthenticationSetup(tag)
			authenticated = true

		case "LOGOUT":
			s.sendResponse("* BYE Proxy logging out")
			s.sendResponse(fmt.Sprintf("%s OK LOGOUT completed", tag))
			return

		case "CAPABILITY":
			s.sendResponse("* CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN")
			s.sendResponse(fmt.Sprintf("%s OK CAPABILITY completed", tag))

		case "ID":
			// Handle ID command - this is where we add forwarding parameter support
			// For now, just respond with a basic server ID
			s.sendResponse("* ID (\"name\" \"Sora-Proxy\" \"version\" \"1.0\")")
			s.sendResponse(fmt.Sprintf("%s OK ID completed", tag))

		case "NOOP":
			s.sendResponse(fmt.Sprintf("%s OK NOOP completed", tag))

		default:
			if s.handleAuthError(fmt.Sprintf("%s NO Command not supported before authentication", tag)) {
				return
			}
			continue
		}
	}

	// Clear the read deadline once authenticated, as the connection will now be
	// in proxy mode where idle is handled by the backend (e.g., IDLE command).
	if s.server.sessionTimeout > 0 {
		if err := s.clientConn.SetReadDeadline(time.Time{}); err != nil {
			log.Printf("IMAP Proxy [%s] Warning: failed to clear read deadline for %s: %v", s.server.name, clientAddr, err)
		}
	}
	// Start proxying only if backend connection was successful
	if s.backendConn != nil {
		if s.server.debug {
			log.Printf("IMAP Proxy [%s] Starting proxy for user %s", s.server.name, s.username)
		}
		s.startProxy()
	} else {
		log.Printf("IMAP Proxy [%s] Cannot start proxy for user %s: no backend connection", s.server.name, s.username)
	}
}

// handleAuthError increments the error count, sends an error response, and
// returns true if the connection should be dropped.
func (s *Session) handleAuthError(response string) bool {
	s.errorCount++
	s.sendResponse(response)
	if s.errorCount >= maxAuthErrors {
		log.Printf("IMAP Proxy [%s] Too many authentication errors from %s, dropping connection.", s.server.name, s.clientConn.RemoteAddr())
		// Send a final BYE message before closing.
		s.sendResponse("* BYE Too many invalid commands")
		return true
	}
	return false
}

// sendGreeting sends the IMAP greeting.
func (s *Session) sendGreeting() error {
	greeting := "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN] Proxy Ready\r\n"
	_, err := s.clientWriter.WriteString(greeting)
	if err != nil {
		return err
	}
	return s.clientWriter.Flush()
}

// sendResponse sends a response to the client.
func (s *Session) sendResponse(response string) error {
	_, err := s.clientWriter.WriteString(response + "\r\n")
	if err != nil {
		return err
	}
	return s.clientWriter.Flush()
}

// Log logs a client command with password masking if debug is enabled.
func (s *Session) Log(format string, args ...interface{}) {
	if s.server.debug {
		message := fmt.Sprintf(format, args...)
		s.server.debugWriter.Write([]byte(message))
	}
}

// authenticateUser authenticates the user against the database.
func (s *Session) authenticateUser(username, password string) error {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	// Apply progressive authentication delay BEFORE any other checks
	remoteAddr := s.clientConn.RemoteAddr()
	server.ApplyAuthenticationDelay(s.ctx, s.server.authLimiter, remoteAddr, "IMAP-PROXY")

	// Check if the authentication attempt is allowed by the rate limiter using proxy-aware methods
	if err := s.server.authLimiter.CanAttemptAuthWithProxy(s.ctx, s.clientConn, nil, username); err != nil {
		// Don't record as auth failure - this is rate limiting, not authentication failure
		metrics.ProtocolErrors.WithLabelValues("imap_proxy", "AUTH", "rate_limited", "client_error").Inc()
		return err
	}

	// Try prelookup authentication/routing first if configured
	// Skip strict address validation if prelookup is enabled, as it may support master tokens
	// with syntax like user@domain.com@TOKEN (multiple @ symbols)
	if s.server.connManager.HasRouting() {
		if s.server.debug {
			log.Printf("IMAP Proxy [%s] Attempting authentication for user %s via prelookup", s.server.name, username)
		}
		routingInfo, authResult, err := s.server.connManager.AuthenticateAndRoute(ctx, username, password)

		if err != nil {
			// Categorize the error type to determine fallback behavior
			if errors.Is(err, proxy.ErrPrelookupInvalidResponse) {
				// Invalid response from prelookup (malformed 2xx) - this is a server bug, fail hard
				log.Printf("IMAP Proxy [%s] Prelookup returned invalid response for '%s': %v. This is a server bug - rejecting authentication.", s.server.name, username, err)
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", "failure").Inc()
				return fmt.Errorf("prelookup server error: invalid response")
			}

			if errors.Is(err, proxy.ErrPrelookupTransient) {
				// Transient error (network, 5xx, circuit breaker) - check fallback config
				if s.server.prelookupConfig != nil && s.server.prelookupConfig.FallbackDefault {
					if s.server.debug {
						log.Printf("IMAP Proxy [%s] Prelookup transient error for '%s': %v. Fallback enabled - attempting main DB authentication.", s.server.name, username, err)
					}
					// Fallthrough to main DB auth
				} else {
					log.Printf("IMAP Proxy [%s] Prelookup transient error for '%s': %v. Fallback disabled (fallback_to_default=false) - rejecting authentication.", s.server.name, username, err)
					s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
					metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", "failure").Inc()
					return fmt.Errorf("prelookup service unavailable")
				}
			} else {
				// Unknown error type - fallthrough to main DB auth
			}
		} else {
			switch authResult {
			case proxy.AuthSuccess:
				// Prelookup auth was successful. Use the accountID and flag from the prelookup result.
				if s.server.debug {
					log.Printf("IMAP Proxy [%s] Prelookup authentication successful for %s, AccountID: %d (prelookup)", s.server.name, username, routingInfo.AccountID)
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
				metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", "success").Inc()
				// For metrics, use username as-is (may contain token, but that's ok for tracking)
				if addr, err := server.NewAddress(username); err == nil {
					metrics.TrackDomainConnection("imap_proxy", addr.Domain())
					metrics.TrackUserActivity("imap_proxy", addr.FullAddress(), "connection", 1)
				}
				return nil // Authentication complete

			case proxy.AuthFailed:
				// User found in prelookup, but password was wrong. Reject immediately.
				log.Printf("IMAP Proxy [%s] Prelookup authentication failed for %s (bad password)", s.server.name, username)
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", "failure").Inc()
				return fmt.Errorf("authentication failed")

			case proxy.AuthUserNotFound:
				// User not in prelookup DB. Fallthrough to main DB auth.
				if s.server.debug {
					log.Printf("IMAP Proxy [%s] User '%s' not found in prelookup. Falling back to main DB.", s.server.name, username)
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
		log.Printf("IMAP Proxy [%s] Authenticating user %s via main database", s.server.name, username)
	}
	accountID, err := s.server.rdb.AuthenticateWithRetry(ctx, address.FullAddress(), password)
	if err != nil {
		s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
		metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", "failure").Inc()
		return fmt.Errorf("authentication failed: %w", err)
	}

	s.accountID = accountID
	s.isPrelookupAccount = false // Authenticated against the main DB
	s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, true)

	// Track successful authentication.
	metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", "success").Inc()

	// Track domain and user connection activity for the login event.
	metrics.TrackDomainConnection("imap_proxy", address.Domain())
	metrics.TrackUserActivity("imap_proxy", address.FullAddress(), "connection", 1)

	return nil
}

// connectToBackend establishes a connection to the backend server.
func (s *Session) connectToBackend() error {
	routeResult, err := proxy.DetermineRoute(proxy.RouteParams{
		Ctx:                s.ctx,
		Username:           s.username,
		Protocol:           "imap",
		IsPrelookupAccount: s.isPrelookupAccount,
		RoutingInfo:        s.routingInfo,
		ConnManager:        s.server.connManager,
		EnableAffinity:     s.server.enableAffinity,
		ProxyName:          "IMAP Proxy",
	})
	if err != nil {
		log.Printf("IMAP Proxy [%s] Error determining route for %s: %v", s.server.name, s.username, err)
	}

	// Update session routing info if it was fetched by DetermineRoute
	s.routingInfo = routeResult.RoutingInfo
	preferredAddr := routeResult.PreferredAddr
	isPrelookupRoute := routeResult.IsPrelookupRoute

	// 4. Connect using the determined address (or round-robin if empty)
	// Create a new context for this connection attempt, respecting the overall session context.
	// Track which routing method was used for this connection.
	metrics.ProxyRoutingMethod.WithLabelValues("imap", routeResult.RoutingMethod).Inc()

	connectCtx, connectCancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer connectCancel()

	// Generate session ID if not already generated
	if s.sessionID == "" {
		s.sessionID = s.generateSessionID()
	}

	// Ensure routing info has client connection for JA4 fingerprint extraction
	if s.routingInfo == nil {
		// Create minimal routing info with client connection for JA4 extraction
		// Copy server's settings to avoid overriding them with zero values later
		s.routingInfo = &proxy.UserRoutingInfo{
			ClientConn:         s.clientConn,
			RemoteUseIDCommand: s.server.remoteUseIDCommand,
			ProxySessionID:     s.sessionID, // Include session ID for end-to-end tracing
		}
	} else {
		s.routingInfo.ClientConn = s.clientConn
		s.routingInfo.ProxySessionID = s.sessionID
	}

	clientHost, clientPort := server.GetHostPortFromAddr(s.clientConn.RemoteAddr())
	serverHost, serverPort := server.GetHostPortFromAddr(s.clientConn.LocalAddr())
	backendConn, actualAddr, err := s.server.connManager.ConnectWithProxy(
		connectCtx,
		preferredAddr,
		clientHost, clientPort, serverHost, serverPort, s.routingInfo,
	)
	if err != nil {
		metrics.ProxyBackendConnections.WithLabelValues("imap", "failure").Inc()
		return fmt.Errorf("failed to connect to backend: %w", err)
	}
	if isPrelookupRoute && actualAddr != preferredAddr {
		// The prelookup route specified a server, but we connected to a different one.
		// This means the preferred server failed and the connection manager fell back.
		// For prelookup routes, this is a hard failure.
		backendConn.Close()
		metrics.ProxyBackendConnections.WithLabelValues("imap", "failure").Inc()
		return fmt.Errorf("prelookup route to %s failed, and fallback is disabled for prelookup routes", preferredAddr)
	}

	// Track backend connection success
	metrics.ProxyBackendConnections.WithLabelValues("imap", "success").Inc()

	s.backendConn = backendConn
	s.serverAddr = actualAddr
	s.backendReader = bufio.NewReader(s.backendConn)
	s.backendWriter = bufio.NewWriter(s.backendConn)

	// Record successful connection for future affinity if enabled
	if s.server.enableAffinity && !s.isPrelookupAccount && actualAddr != "" {
		proxy.UpdateAffinityAfterConnection(proxy.RouteParams{
			Username:           s.username,
			Protocol:           "imap",
			IsPrelookupAccount: s.isPrelookupAccount,
			ConnManager:        s.server.connManager,
			EnableAffinity:     s.server.enableAffinity,
			ProxyName:          "IMAP Proxy",
		}, actualAddr, routeResult.RoutingMethod == "affinity")
	}

	// Set a deadline for reading the greeting to prevent hanging
	readTimeout := s.server.connManager.GetConnectTimeout()
	if err := s.backendConn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		s.backendConn.Close()
		log.Printf("IMAP Proxy [%s] Failed to set read deadline for backend greeting from %s: %v", s.server.name, s.serverAddr, err)
		return fmt.Errorf("failed to set read deadline for greeting: %w", err)
	}

	// Read greeting from backend
	_, err = s.backendReader.ReadString('\n')
	if err != nil {
		s.backendConn.Close()
		log.Printf("IMAP Proxy [%s] Failed to read backend greeting from %s for user %s: %v", s.server.name, s.serverAddr, s.username, err)
		return fmt.Errorf("failed to read backend greeting: %w", err)
	}

	// Clear the read deadline after successful greeting
	if err := s.backendConn.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("IMAP Proxy [%s] Warning: failed to clear read deadline for %s: %v", s.server.name, s.serverAddr, err)
	}

	return nil
}

// authenticateToBackend authenticates to the backend using master credentials.
func (s *Session) authenticateToBackend() (string, error) {
	// Authenticate to the backend using master credentials in a single step.
	// SASL PLAIN format: [authz-id]\0authn-id\0password
	authString := fmt.Sprintf("%s\x00%s\x00%s", s.username, string(s.server.masterSASLUsername), string(s.server.masterSASLPassword))
	encoded := base64.StdEncoding.EncodeToString([]byte(authString))

	// Set a deadline for the authentication process
	authTimeout := s.server.connManager.GetConnectTimeout()
	if err := s.backendConn.SetDeadline(time.Now().Add(authTimeout)); err != nil {
		log.Printf("IMAP Proxy [%s] Failed to set auth deadline for %s: %v", s.server.name, s.serverAddr, err)
		return "", fmt.Errorf("failed to set auth deadline: %w", err)
	}

	tag := fmt.Sprintf("p%d", rand.Intn(10000))
	// Send AUTHENTICATE PLAIN with initial response
	authCmd := fmt.Sprintf("%s AUTHENTICATE PLAIN %s\r\n", tag, encoded)
	_, err := s.backendWriter.WriteString(authCmd)
	if err != nil {
		log.Printf("IMAP Proxy [%s] Failed to send AUTHENTICATE command to %s: %v", s.server.name, s.serverAddr, err)
		return "", fmt.Errorf("failed to send AUTHENTICATE command: %w", err)
	}
	s.backendWriter.Flush()

	// Read authentication response
	response, err := s.backendReader.ReadString('\n')
	if err != nil {
		log.Printf("IMAP Proxy [%s] Failed to read auth response from %s: %v", s.server.name, s.serverAddr, err)
		return "", fmt.Errorf("failed to read auth response: %w", err)
	}

	// Clear the deadline after successful authentication
	if err := s.backendConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("IMAP Proxy [%s] Warning: failed to clear auth deadline for %s: %v", s.server.name, s.serverAddr, err)
	}

	if !strings.HasPrefix(strings.TrimSpace(response), tag+" OK") {
		return "", fmt.Errorf("backend authentication failed: %s", response)
	}

	if s.server.debug {
		log.Printf("IMAP Proxy [%s] Backend authentication successful for user %s", s.server.name, s.username)
	}

	return strings.TrimRight(response, "\r\n"), nil
}

// postAuthenticationSetup handles the common tasks after a user is successfully authenticated.
func (s *Session) postAuthenticationSetup(clientTag string) {
	// Connect to backend
	if err := s.connectToBackend(); err != nil {
		log.Printf("IMAP Proxy [%s] Failed to connect to backend for %s: %v", s.server.name, s.username, err)
		s.sendResponse(fmt.Sprintf("%s NO [UNAVAILABLE] Backend server temporarily unavailable", clientTag))
		return
	}

	// Send ID command to backend with forwarding parameters if enabled.
	// This MUST be done before authenticating to the backend, as the ID command
	// is only valid in the "Not Authenticated" state.
	useIDCommand := s.server.remoteUseIDCommand
	// Override with routing-specific setting if available
	if s.routingInfo != nil {
		useIDCommand = s.routingInfo.RemoteUseIDCommand
	}
	if useIDCommand {
		if err := s.sendForwardingParametersToBackend(); err != nil {
			log.Printf("IMAP Proxy [%s] Failed to send forwarding parameters to backend: %v", s.server.name, err)
			// Continue anyway - forwarding parameters are not critical
		}
	}

	// Authenticate to backend with master credentials
	backendResponse, err := s.authenticateToBackend()
	if err != nil {
		log.Printf("IMAP Proxy [%s] Backend authentication failed for %s: %v", s.server.name, s.username, err)
		s.sendResponse(fmt.Sprintf("%s NO [UNAVAILABLE] Backend server authentication failed", clientTag))
		// Close the backend connection since authentication failed
		if s.backendConn != nil {
			s.backendConn.Close()
			s.backendConn = nil
			s.backendReader = nil
			s.backendWriter = nil
		}
		return
	}

	// Register connection
	if err := s.registerConnection(); err != nil {
		log.Printf("IMAP Proxy [%s] Failed to register connection for %s: %v", s.server.name, s.username, err)
	}

	// Forward the backend's success response, replacing the client's tag.
	var responsePayload string
	if idx := strings.Index(backendResponse, " "); idx != -1 {
		// The payload is everything after the first space (e.g., "OK Authentication successful")
		responsePayload = backendResponse[idx+1:]
	} else {
		// Fallback if the response format is unexpected
		responsePayload = "OK Authentication successful"
	}
	s.sendResponse(fmt.Sprintf("%s %s", clientTag, responsePayload))
}

// startProxy starts bidirectional proxying between client and backend.
func (s *Session) startProxy() {
	if s.backendConn == nil {
		log.Printf("IMAP Proxy [%s] backend connection not established for %s", s.server.name, s.username)
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
		metrics.BytesThroughput.WithLabelValues("imap_proxy", "in").Add(float64(bytesIn))
		if err != nil && !isClosingError(err) {
			log.Printf("IMAP Proxy [%s] Error copying from client to backend: %v", s.server.name, err)
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
		metrics.BytesThroughput.WithLabelValues("imap_proxy", "out").Add(float64(bytesOut))
		if err != nil && !isClosingError(err) {
			log.Printf("IMAP Proxy [%s] Error copying from backend to client: %v", s.server.name, err)
		}
	}()

	go func() {
		<-s.ctx.Done()
		s.clientConn.Close()
		s.backendConn.Close()
	}()

	wg.Wait()
}

// close closes all connections.
func (s *Session) close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Decrement current connections metric
	metrics.ConnectionsCurrent.WithLabelValues("imap_proxy").Dec()

	// Unregister connection
	if s.accountID > 0 {
		// Use a new background context for this final operation, as s.ctx is likely already cancelled.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		clientAddr := s.clientConn.RemoteAddr().String()

		if s.server.connTracker != nil && s.server.connTracker.IsEnabled() {
			if err := s.server.connTracker.UnregisterConnection(ctx, s.accountID, "IMAP", clientAddr); err != nil {
				log.Printf("IMAP Proxy [%s] Failed to unregister connection for %s: %v", s.server.name, s.username, err)
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
		return s.server.connTracker.RegisterConnection(ctx, s.accountID, "IMAP", clientAddr, s.serverAddr)
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

	// New mechanism: listen for kick notifications and only update activity periodically.
	activityTicker := time.NewTicker(30 * time.Second)
	defer activityTicker.Stop()

	kickChan := s.server.connTracker.KickChannel()

	checkAndTerminate := func() (terminated bool) {
		checkCtx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
		defer cancel()

		shouldTerminate, err := s.server.connTracker.CheckTermination(checkCtx, s.accountID, "IMAP", clientAddr)
		if err != nil {
			log.Printf("IMAP Proxy [%s] Failed to check termination for %s: %v", s.server.name, s.username, err)
			return false
		}
		if shouldTerminate {
			log.Printf("IMAP Proxy [%s] Connection kicked - disconnecting user: %s (client: %s, backend: %s)", s.server.name, s.username, clientAddr, s.serverAddr)
			s.clientConn.Close()
			s.backendConn.Close()
			return true
		}
		return false
	}

	for {
		select {
		case <-kickChan:
			log.Printf("IMAP Proxy [%s] Received kick notification for %s", s.server.name, s.username)
			if checkAndTerminate() {
				return
			}
		case <-activityTicker.C:
			updateCtx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
			if err := s.server.connTracker.UpdateActivity(updateCtx, s.accountID, "IMAP", clientAddr); err != nil {
				log.Printf("IMAP Proxy [%s] Failed to update activity for %s: %v", s.server.name, s.username, err)
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
