package imapproxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/logger"
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
	startTime          time.Time
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
		startTime:    time.Now(),
	}
}

// handleConnection handles the proxy session.
func (s *Session) handleConnection() {
	defer s.cancel()
	defer s.close()

	s.Log("connected")

	// Perform TLS handshake if this is a TLS connection
	if tlsConn, ok := s.clientConn.(interface{ PerformHandshake() error }); ok {
		if err := tlsConn.PerformHandshake(); err != nil {
			s.WarnLog("TLS handshake failed: %v", err)
			return
		}
	}

	clientAddr := server.GetAddrString(s.clientConn.RemoteAddr())
	// Send greeting
	if err := s.sendGreeting(); err != nil {
		logger.Error("Failed to send greeting", "proxy", s.server.name, "remote", clientAddr, "error", err)
		return
	}

	// Handle authentication phase
	authenticated := false
	for !authenticated {
		// Set a read deadline for the client command to prevent idle connections
		// from sitting in the authentication phase forever.
		if s.server.sessionTimeout > 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.sessionTimeout)); err != nil {
				logger.Error("Failed to set read deadline", "proxy", s.server.name, "remote", clientAddr, "error", err)
				return
			}
		}

		// Read command from client
		line, err := s.clientReader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.DebugLog("client timed out waiting for command")
				s.sendResponse("* BYE Idle timeout")
				return
			}
			if err != io.EOF {
				s.DebugLog("error reading from client: %v", err)
			}
			return
		}

		line = strings.TrimRight(line, "\r\n")

		// Log client command with password masking if debug is enabled
		s.DebugLog("C: %s", line)

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
				s.DebugLog("authentication failed: %v", err)
				s.sendResponse(fmt.Sprintf("%s NO Authentication failed", tag))
				continue
			}

			// Only set username if it wasn't already set by prelookup (which may have extracted actual email from token)
			if s.username == "" {
				// Parse and use base address (without +detail) for backend impersonation
				if addr, err := server.NewAddress(username); err == nil {
					s.username = addr.BaseAddress()
				} else {
					s.username = username // Fallback if parsing fails
				}
			}

			// Set username on client connection for timeout logging
			if soraConn, ok := s.clientConn.(interface{ SetUsername(string) }); ok {
				soraConn.SetUsername(s.username)
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
						s.DebugLog("error reading SASL response: %v", err)
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
				s.DebugLog("authentication failed: %v", err)
				// This is an actual authentication failure, not a protocol error.
				// The rate limiter handles this, so we don't count it as a command error.
				s.sendResponse(fmt.Sprintf("%s NO Authentication failed", tag))
				continue
			}

			// Only set username if it wasn't already set by prelookup (which may have extracted actual email from token)
			if s.username == "" {
				// Parse and use base address (without +detail) for backend impersonation
				if addr, err := server.NewAddress(authnID); err == nil {
					s.username = addr.BaseAddress()
				} else {
					s.username = authnID // Fallback if parsing fails
				}
			}

			// Set username on client connection for timeout logging
			if soraConn, ok := s.clientConn.(interface{ SetUsername(string) }); ok {
				soraConn.SetUsername(s.username)
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
			s.WarnLog("failed to clear read deadline: %v", err)
		}
	}
	// Start proxying only if backend connection was successful
	if s.backendConn != nil {
		s.DebugLog("starting proxy for user")
		s.startProxy()
	} else {
		logger.Error("Cannot start proxy - no backend connection", "proxy", s.server.name, "user", s.username)
	}
}

// handleAuthError increments the error count, sends an error response, and
// returns true if the connection should be dropped.
func (s *Session) handleAuthError(response string) bool {
	s.errorCount++
	s.sendResponse(response)
	if s.errorCount >= maxAuthErrors {
		s.WarnLog("too many authentication errors, dropping connection")
		// Send a final BYE message before closing.
		s.sendResponse("* BYE Too many invalid commands")
		return true
	}
	return false
}

// sendGreeting sends the IMAP greeting.
func (s *Session) sendGreeting() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	greeting := "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN] Proxy Ready\r\n"
	_, err := s.clientWriter.WriteString(greeting)
	if err != nil {
		return err
	}
	return s.clientWriter.Flush()
}

// sendResponse sends a response to the client.
func (s *Session) sendResponse(response string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.clientWriter.WriteString(response + "\r\n")
	if err != nil {
		return err
	}
	return s.clientWriter.Flush()
}

// Log logs at INFO level with session context
func (s *Session) Log(format string, args ...any) {
	remoteAddr := server.GetAddrString(s.clientConn.RemoteAddr())
	user := "none"
	if s.username != "" && s.accountID > 0 {
		user = fmt.Sprintf("%s/%d", s.username, s.accountID)
	} else if s.username != "" {
		user = s.username
	}

	logger.Info("Session", "proto", "imap_proxy", "name", s.server.name, "remote", remoteAddr, "user", user, "msg", fmt.Sprintf(format, args...))
}

// DebugLog logs at DEBUG level with session context
func (s *Session) DebugLog(format string, args ...any) {
	if s.server.debug {
		remoteAddr := server.GetAddrString(s.clientConn.RemoteAddr())
		user := "none"
		if s.username != "" && s.accountID > 0 {
			user = fmt.Sprintf("%s/%d", s.username, s.accountID)
		} else if s.username != "" {
			user = s.username
		}

		logger.Debug("Session", "proto", "imap_proxy", "name", s.server.name, "remote", remoteAddr, "user", user, "msg", fmt.Sprintf(format, args...))
	}
}

// WarnLog logs at WARN level with session context
func (s *Session) WarnLog(format string, args ...any) {
	remoteAddr := server.GetAddrString(s.clientConn.RemoteAddr())
	user := "none"
	if s.username != "" && s.accountID > 0 {
		user = fmt.Sprintf("%s/%d", s.username, s.accountID)
	} else if s.username != "" {
		user = s.username
	}

	logger.Warn("Session", "proto", "imap_proxy", "name", s.server.name, "remote", remoteAddr, "user", user, "msg", fmt.Sprintf(format, args...))
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

	// Parse username to check for master username or token suffix
	// Format: user@domain.com@SUFFIX
	// If SUFFIX matches configured master username: validate locally, send base address to prelookup
	// Otherwise: treat as token, send full username (including @SUFFIX) to prelookup
	var usernameForPrelookup string
	var masterAuthValidated bool

	// Parse username (handles both regular addresses and addresses with @SUFFIX)
	parsedAddr, parseErr := server.NewAddress(username)

	if parseErr == nil && parsedAddr.HasSuffix() {
		// Has suffix - check if it matches configured master username
		if len(s.server.masterUsername) > 0 && checkMasterCredential(parsedAddr.Suffix(), s.server.masterUsername) {
			// Suffix matches master username - validate master password locally
			if !checkMasterCredential(password, s.server.masterPassword) {
				// Wrong master password - fail immediately
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, parsedAddr.BaseAddress(), false)
				metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", "failure").Inc()
				return fmt.Errorf("authentication failed")
			}
			// Master credentials validated - use base address (without @MASTER suffix) for prelookup
			s.DebugLog("master username authentication successful for '%s', using base address for routing", parsedAddr.BaseAddress())
			usernameForPrelookup = parsedAddr.BaseAddress()
			masterAuthValidated = true
		} else {
			// Suffix doesn't match master username - treat as token
			// Send FULL username (including @TOKEN) to prelookup for validation
			s.DebugLog("token detected in username, sending full username to prelookup: %s", username)
			usernameForPrelookup = username
			masterAuthValidated = false
		}
	} else {
		// No suffix - regular username
		usernameForPrelookup = username
		masterAuthValidated = false
	}

	// Try prelookup authentication/routing if configured
	// - For master username: sends base address to get routing info (password already validated)
	// - For others: sends full username (may contain token) for prelookup authentication
	if s.server.connManager.HasRouting() {
		s.DebugLog("attempting authentication via prelookup for user: %s", usernameForPrelookup)
		routingInfo, authResult, err := s.server.connManager.AuthenticateAndRouteWithOptions(ctx, usernameForPrelookup, password, masterAuthValidated)

		if err != nil {
			// Categorize the error type to determine fallback behavior
			if errors.Is(err, proxy.ErrPrelookupInvalidResponse) {
				// Invalid response from prelookup (malformed 2xx) - this is a server bug, fail hard
				logger.Error("Prelookup returned invalid response - server bug", "proxy", s.server.name, "user", username, "error", err)
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", "failure").Inc()
				return fmt.Errorf("prelookup server error: invalid response")
			}

			if errors.Is(err, proxy.ErrPrelookupTransient) {
				// Transient error (network, 5xx, circuit breaker) - check fallback config
				if s.server.prelookupConfig != nil && s.server.prelookupConfig.FallbackDefault {
					s.DebugLog("prelookup transient error, fallback enabled: %v", err)
					// Fallthrough to main DB auth
				} else {
					s.WarnLog("prelookup transient error, fallback disabled: %v", err)
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
				// Prelookup returned success - use routing info
				s.DebugLog("prelookup successful (account_id: %d, master_auth_validated: %v)", routingInfo.AccountID, masterAuthValidated)
				s.accountID = routingInfo.AccountID
				s.isPrelookupAccount = routingInfo.IsPrelookupAccount
				s.routingInfo = routingInfo
				// Use the actual email (without token) for backend impersonation
				if routingInfo.ActualEmail != "" {
					s.username = routingInfo.ActualEmail
				} else if masterAuthValidated {
					s.username = usernameForPrelookup // Base address already
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
				// User found in prelookup, but password was wrong
				// For master username, this shouldn't happen (password already validated)
				// For others, reject immediately
				if masterAuthValidated {
					s.WarnLog("prelookup failed but master auth was already validated - routing issue?")
				}
				s.DebugLog("prelookup authentication failed - bad password")
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", "failure").Inc()
				return fmt.Errorf("authentication failed")

			case proxy.AuthTemporarilyUnavailable:
				// Prelookup service is temporarily unavailable - tell user to retry later
				s.WarnLog("prelookup service temporarily unavailable")
				metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", "unavailable").Inc()
				return fmt.Errorf("authentication service temporarily unavailable, please try again later")

			case proxy.AuthUserNotFound:
				// User not found in prelookup (404). This means the user is NOT in the other system.
				// Always fall through to main DB auth - this is the expected behavior for partitioning.
				s.DebugLog("user not found in prelookup, attempting main DB")
			}
		}
	}

	// Fallback to main DB
	// If master auth was already validated, just get account ID and continue
	// Otherwise, authenticate via main DB
	var address server.Address
	var err error
	// Use already parsed address if available
	if parseErr == nil {
		address = parsedAddr
	} else {
		// Parse failed earlier - try again with NewAddress (shouldn't happen but handle it)
		address, err = server.NewAddress(username)
		if err != nil {
			return fmt.Errorf("invalid address format: %w", err)
		}
	}

	var accountID int64
	if masterAuthValidated {
		// Master authentication already validated - just get account ID
		s.DebugLog("master auth already validated, getting account ID from main database")
		accountID, err = s.server.rdb.GetAccountIDByAddressWithRetry(ctx, address.BaseAddress())
		if err != nil {
			s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, address.BaseAddress(), false)
			metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", "failure").Inc()
			return fmt.Errorf("account not found: %w", err)
		}
	} else {
		// Regular authentication via main DB
		s.DebugLog("authenticating user via main database")
		// Use base address (without +detail) for authentication
		accountID, err = s.server.rdb.AuthenticateWithRetry(ctx, address.BaseAddress(), password)
		if err != nil {
			s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
			metrics.AuthenticationAttempts.WithLabelValues("imap_proxy", "failure").Inc()
			return fmt.Errorf("authentication failed: %w", err)
		}
	}

	s.accountID = accountID
	s.isPrelookupAccount = false
	// Set username to base address (without master username suffix or +detail)
	// This is what gets sent to the backend for impersonation
	s.username = address.BaseAddress()
	s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, true)

	// Track successful authentication.
	s.DebugLog("main DB auth successful (account_id: %d)", accountID)
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
		s.WarnLog("error determining route: %v", err)
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
		logger.Error("Failed to set read deadline for backend greeting", "proxy", s.server.name, "backend", s.serverAddr, "error", err)
		return fmt.Errorf("failed to set read deadline for greeting: %w", err)
	}

	// Read greeting from backend
	_, err = s.backendReader.ReadString('\n')
	if err != nil {
		s.backendConn.Close()
		logger.Error("Failed to read backend greeting", "proxy", s.server.name, "backend", s.serverAddr, "user", s.username, "error", err)
		return fmt.Errorf("failed to read backend greeting: %w", err)
	}

	// Clear the read deadline after successful greeting
	if err := s.backendConn.SetReadDeadline(time.Time{}); err != nil {
		s.WarnLog("failed to clear read deadline: %v", err)
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
		logger.Error("Failed to set auth deadline", "proxy", s.server.name, "backend", s.serverAddr, "error", err)
		return "", fmt.Errorf("failed to set auth deadline: %w", err)
	}

	tag := fmt.Sprintf("p%d", rand.Intn(10000))
	// Send AUTHENTICATE PLAIN with initial response
	authCmd := fmt.Sprintf("%s AUTHENTICATE PLAIN %s\r\n", tag, encoded)

	s.mu.Lock()
	_, err := s.backendWriter.WriteString(authCmd)
	if err != nil {
		s.mu.Unlock()
		logger.Error("Failed to send AUTHENTICATE command to backend", "proxy", s.server.name, "backend", s.serverAddr, "error", err)
		return "", fmt.Errorf("failed to send AUTHENTICATE command: %w", err)
	}
	s.backendWriter.Flush()
	s.mu.Unlock()

	// Read authentication response
	response, err := s.backendReader.ReadString('\n')
	if err != nil {
		logger.Error("Failed to read auth response from backend", "proxy", s.server.name, "backend", s.serverAddr, "error", err)
		return "", fmt.Errorf("failed to read auth response: %w", err)
	}

	// Clear the deadline after successful authentication
	if err := s.backendConn.SetDeadline(time.Time{}); err != nil {
		s.WarnLog("failed to clear auth deadline: %v", err)
	}

	if !strings.HasPrefix(strings.TrimSpace(response), tag+" OK") {
		return "", fmt.Errorf("backend authentication failed: %s", response)
	}

	s.DebugLog("backend authentication successful")

	return strings.TrimRight(response, "\r\n"), nil
}

// postAuthenticationSetup handles the common tasks after a user is successfully authenticated.
func (s *Session) postAuthenticationSetup(clientTag string) {
	// Connect to backend
	if err := s.connectToBackend(); err != nil {
		logger.Error("Failed to connect to backend", "proxy", s.server.name, "user", s.username, "error", err)
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
			s.WarnLog("failed to send forwarding parameters to backend: %v", err)
			// Continue anyway - forwarding parameters are not critical
		}
	}

	// Authenticate to backend with master credentials
	backendResponse, err := s.authenticateToBackend()
	if err != nil {
		logger.Error("Backend authentication failed", "proxy", s.server.name, "user", s.username, "backend", s.serverAddr, "error", err)
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
		s.WarnLog("failed to register connection: %v", err)
	}

	// Log authentication at INFO level
	s.Log("authenticated (backend: %s)", s.serverAddr)

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
		logger.Error("Backend connection not established", "proxy", s.server.name, "user", s.username)
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
		bytesIn, err := server.CopyWithDeadline(s.ctx, s.backendConn, s.clientConn, "client-to-backend")
		metrics.BytesThroughput.WithLabelValues("imap_proxy", "in").Add(float64(bytesIn))
		if err != nil && !isClosingError(err) {
			s.DebugLog("error copying from client to backend: %v", err)
		}
	}()

	// Backend to client
	wg.Add(1)
	go func() {
		defer wg.Done()
		// If this copy returns, it means the backend has closed the connection or there was an error.
		// We must close the client connection to unblock the other copy operation.
		defer s.clientConn.Close()
		var bytesOut int64
		var err error
		// Use the buffered reader from authentication phase to avoid losing buffered data
		if s.backendReader != nil {
			// Copy from buffered reader with deadline protection
			// This ensures we don't lose any data that was buffered during authentication
			// or any subsequent data that gets read into the buffer during the proxy phase
			bytesOut, err = s.copyBufferedReaderToConn(s.clientConn, s.backendReader)
		} else {
			// Fallback to direct copy if no buffered reader (shouldn't happen in normal flow)
			bytesOut, err = server.CopyWithDeadline(s.ctx, s.clientConn, s.backendConn, "backend-to-client")
		}
		metrics.BytesThroughput.WithLabelValues("imap_proxy", "out").Add(float64(bytesOut))
		if err != nil && !isClosingError(err) {
			s.DebugLog("error copying from backend to client: %v", err)
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

	// Remove session from active tracking
	s.server.removeSession(s)

	// Log disconnection at INFO level
	duration := time.Since(s.startTime).Round(time.Second)
	if s.username != "" {
		s.Log("disconnected (duration: %v, backend: %s)", duration, s.serverAddr)
	} else {
		s.Log("disconnected (duration: %v)", duration)
	}

	// Decrement current connections metric
	metrics.ConnectionsCurrent.WithLabelValues("imap_proxy").Dec()

	// Unregister connection asynchronously - don't block session cleanup
	if s.accountID > 0 {
		accountID := s.accountID
		clientAddr := server.GetAddrString(s.clientConn.RemoteAddr())
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

			if err := connTracker.UnregisterConnection(ctx, accountID, "IMAP", clientAddr); err != nil {
				// Connection tracking is non-critical monitoring data, so log but continue
				logger.Warn("Failed to unregister connection", "proto", "imap_proxy", "name", serverName, "user", username, "error", err)
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

	clientAddr := server.GetAddrString(s.clientConn.RemoteAddr())

	if s.server.connTracker != nil && s.server.connTracker.IsEnabled() {
		return s.server.connTracker.RegisterConnection(ctx, s.accountID, s.username, "IMAP", clientAddr)
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

	// Register for kick notifications
	kickChan := s.server.connTracker.RegisterSession(s.accountID)
	defer s.server.connTracker.UnregisterSession(s.accountID, kickChan)

	for {
		select {
		case <-kickChan:
			// Kick notification received - close connections
			s.Log("connection kicked - disconnecting user")
			s.clientConn.Close()
			s.backendConn.Close()
			return
		case <-ctx.Done():
			return
		}
	}
}

// copyBufferedReaderToConn copies data from a buffered reader to a connection with write deadline protection.
// This is used for backend-to-client copying when the backend connection has a buffered reader
// from the authentication phase. We must read from the buffered reader to avoid losing any data
// that was buffered but not yet read.
func (s *Session) copyBufferedReaderToConn(dst net.Conn, src *bufio.Reader) (int64, error) {
	const writeDeadline = 30 * time.Second
	var totalBytes int64
	buf := make([]byte, 32*1024)
	nextDeadline := time.Now()

	for {
		select {
		case <-s.ctx.Done():
			return totalBytes, s.ctx.Err()
		default:
		}

		nr, err := src.Read(buf)
		if nr > 0 {
			// Only update write deadline once per second to reduce syscall frequency
			now := time.Now()
			if now.After(nextDeadline) {
				if err := dst.SetWriteDeadline(now.Add(writeDeadline)); err != nil {
					return totalBytes, fmt.Errorf("failed to set write deadline: %w", err)
				}
				nextDeadline = now.Add(time.Second)
			}

			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				totalBytes += int64(nw)
			}
			if ew != nil {
				if netErr, ok := ew.(net.Error); ok && netErr.Timeout() {
					return totalBytes, fmt.Errorf("write timeout in backend-to-client: %w", ew)
				}
				return totalBytes, ew
			}
			if nr != nw {
				return totalBytes, io.ErrShortWrite
			}
		}
		if err != nil {
			if err != io.EOF {
				return totalBytes, err
			}
			return totalBytes, nil
		}
	}
}

func isClosingError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

func checkMasterCredential(provided string, actual []byte) bool {
	return subtle.ConstantTimeCompare([]byte(provided), actual) == 1
}
