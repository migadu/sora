package pop3proxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

type POP3ProxySession struct {
	server             *POP3ProxyServer
	clientConn         net.Conn
	backendConn        net.Conn
	backendReader      *bufio.Reader // Buffered reader from authentication phase
	ctx                context.Context
	cancel             context.CancelFunc
	RemoteIP           string
	username           string
	accountID          int64
	isPrelookupAccount bool
	routingInfo        *proxy.UserRoutingInfo
	routingMethod      string // Routing method used: prelookup, affinity, consistent_hash, roundrobin
	serverAddr         string
	authenticated      bool
	mutex              sync.Mutex
	errorCount         int
	startTime          time.Time
	releaseConn        func() // Connection limiter cleanup function
	proxyInfo          *server.ProxyProtocolInfo
}

func (s *POP3ProxySession) handleConnection() {
	defer s.cancel()
	defer s.close()

	s.startTime = time.Now()

	// Enforce absolute session timeout to prevent hung sessions from leaking
	if s.server.absoluteSessionTimeout > 0 {
		timeout := time.AfterFunc(s.server.absoluteSessionTimeout, func() {
			logger.Info("Absolute session timeout reached - force closing", "proxy", s.server.name, "duration", s.server.absoluteSessionTimeout, "username", s.username)
			s.cancel() // Force cancel context to unblock any stuck I/O
		})
		defer timeout.Stop()
	}

	// Log connection at INFO level
	s.InfoLog("connected")

	// Perform TLS handshake if this is a TLS connection
	if tlsConn, ok := s.clientConn.(interface{ PerformHandshake() error }); ok {
		if err := tlsConn.PerformHandshake(); err != nil {
			s.WarnLog("TLS handshake failed", "error", err)
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
		if s.server.authIdleTimeout > 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.authIdleTimeout)); err != nil {
				s.WarnLog("Failed to set read deadline", "error", err)
				return
			}
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.DebugLog("Client timed out waiting for command")
				writer.WriteString("-ERR Idle timeout, closing connection\r\n")
				writer.Flush()
				return
			}
			if err == io.EOF {
				s.DebugLog("Client dropped connection")
			} else {
				s.WarnLog("Client read error", "error", err)
			}
			return
		}

		line = strings.TrimSpace(line)

		// Log client command with password masking if debug is enabled
		s.DebugLog("client command", "line", line)

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
			authStart := time.Now()
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
				// Check if error is due to server shutdown or temporary unavailability
				if server.IsTemporaryAuthFailure(err) {
					writer.WriteString("-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n")
				} else if server.IsBackendError(err) {
					// Backend connection or authentication issues
					writer.WriteString("-ERR [SYS/TEMP] Backend server temporarily unavailable\r\n")
				} else {
					// Actual authentication failure (wrong password, etc.)
					writer.WriteString("-ERR Authentication failed\r\n")
				}
				writer.Flush()
				s.DebugLog("Authentication failed", "error", err)
				continue
			}

			writer.WriteString("+OK Authentication successful\r\n")
			writer.Flush()

			// Log authentication at INFO level with all required fields
			duration := time.Since(authStart)
			s.InfoLog("authenticated via USER/PASS",
				"address", s.username,
				"backend", s.serverAddr,
				"routing", s.routingMethod,
				"duration", duration.Seconds())

			// Clear the read deadline before moving to the proxying phase, which sets its own.
			if s.server.authIdleTimeout > 0 {
				if err := s.clientConn.SetReadDeadline(time.Time{}); err != nil {
					s.WarnLog("Failed to clear read deadline", "error", err)
				}
			}

			// Register connection
			if err := s.registerConnection(); err != nil {
				s.InfoLog("rejected connection registration", "error", err)
			}

			// Start proxying
			s.startProxying()
			return

		case "AUTH":
			authStart := time.Now()
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
				// Check if error is due to server shutdown or temporary unavailability
				if server.IsTemporaryAuthFailure(err) {
					writer.WriteString("-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n")
				} else if server.IsBackendError(err) {
					// Backend connection or authentication issues
					s.WarnLog("Backend error during SASL authentication", "error", err)
					writer.WriteString("-ERR [SYS/TEMP] Backend server temporarily unavailable\r\n")
				} else {
					// Actual authentication failure (wrong password, etc.)
					writer.WriteString("-ERR Authentication failed\r\n")
				}
				writer.Flush()
				s.DebugLog("SASL authentication failed", "error", err)
				continue
			}

			writer.WriteString("+OK Authentication successful\r\n")
			writer.Flush()

			// Log authentication at INFO level with all required fields
			duration := time.Since(authStart)
			s.InfoLog("authenticated via SASL PLAIN",
				"address", s.username,
				"backend", s.serverAddr,
				"routing", s.routingMethod,
				"duration", duration.Seconds())

			// Clear the read deadline before moving to the proxying phase, which sets its own.
			if s.server.authIdleTimeout > 0 {
				if err := s.clientConn.SetReadDeadline(time.Time{}); err != nil {
					s.WarnLog("Failed to clear read deadline", "error", err)
				}
			}

			// Register connection
			if err := s.registerConnection(); err != nil {
				s.InfoLog("rejected connection registration", "error", err)
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
	if s.errorCount >= s.server.maxAuthErrors {
		s.DebugLog("Too many authentication errors, dropping connection")
		// Send a final error message before closing.
		writer.WriteString("-ERR Too many invalid commands, closing connection\r\n")
		writer.Flush()
		return true
	}
	return false
}

// InfoLog logs a client command with password masking if debug is enabled.
// InfoLog logs at INFO level with session context
// getLogger returns a ProxySessionLogger for this session
func (s *POP3ProxySession) getLogger() *server.ProxySessionLogger {
	return &server.ProxySessionLogger{
		Protocol:   "pop3_proxy",
		ServerName: s.server.name,
		ClientConn: s.clientConn,
		Username:   s.username,
		AccountID:  s.accountID,
		Debug:      s.server.debug,
	}
}

func (s *POP3ProxySession) InfoLog(msg string, keysAndValues ...any) {
	s.getLogger().InfoLog(msg, keysAndValues...)
}

// DebugLog logs at DEBUG level with session context
func (s *POP3ProxySession) DebugLog(msg string, keysAndValues ...any) {
	s.getLogger().DebugLog(msg, keysAndValues...)
}

// WarnLog logs at WARN level with session context
func (s *POP3ProxySession) WarnLog(msg string, keysAndValues ...any) {
	s.getLogger().WarnLog(msg, keysAndValues...)
}

func (s *POP3ProxySession) authenticate(username, password string) error {
	// Reject empty passwords immediately - no cache lookup, no rate limiting needed
	// Empty passwords are never valid under any condition
	if password == "" {
		return consts.ErrAuthenticationFailed
	}

	// Use configured prelookup timeout instead of hardcoded value
	authTimeout := s.server.connManager.GetPrelookupTimeout()
	ctx, cancel := context.WithTimeout(s.ctx, authTimeout)
	defer cancel()

	// Apply progressive authentication delay BEFORE any other checks
	remoteAddr := s.clientConn.RemoteAddr()
	server.ApplyAuthenticationDelay(ctx, s.server.authLimiter, remoteAddr, "POP3-PROXY")

	// Check cache first (before rate limiter to avoid delays for cached successful auth)
	// Use server name as cache key to avoid collisions between different proxies/servers
	if s.server.lookupCache != nil {
		if cached, found := s.server.lookupCache.Get(s.server.name, username); found {
			// Hash the password (never empty - validated at function start)
			passwordHash := lookupcache.HashPassword(password)

			// Check password hash match
			// Note: cached.PasswordHash should also never be empty, but we check defensively
			// in case of cache corruption or edge cases
			passwordMatches := (cached.PasswordHash != "" && cached.PasswordHash == passwordHash)

			if cached.IsNegative {
				// Negative cache entry - authentication previously failed
				if passwordMatches {
					// Same wrong password - return cached failure and refresh TTL
					s.DebugLog("cache hit - negative entry with same password", "username", username, "age", time.Since(cached.CreatedAt))
					metrics.CacheOperationsTotal.WithLabelValues("get", "hit_negative").Inc()
					s.server.lookupCache.Refresh(s.server.name, username)
					s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, nil, username, false)
					metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "failure").Inc()
					return consts.ErrAuthenticationFailed
				} else {
					// Different password - ALWAYS revalidate (user might have fixed their password)
					// Brute force protection is handled by protocol-level rate limiting
					s.DebugLog("cache negative entry - revalidating with different password", "username", username, "age", time.Since(cached.CreatedAt))
					metrics.CacheOperationsTotal.WithLabelValues("get", "revalidate_negative_different_pw").Inc()
					// Fall through to full auth
				}
			} else {
				// Positive cache entry (successful auth)
				if passwordMatches {
					// Same password - use cached routing info and refresh TTL
					s.DebugLog("cache hit - using cached auth", "username", username, "account_id", cached.AccountID, "backend", cached.ServerAddress, "age", time.Since(cached.CreatedAt))
					metrics.CacheOperationsTotal.WithLabelValues("get", "hit").Inc()

					s.accountID = cached.AccountID
					s.isPrelookupAccount = cached.FromPrelookup
					s.routingInfo = &proxy.UserRoutingInfo{
						AccountID:              cached.AccountID,
						ServerAddress:          cached.ServerAddress,
						RemoteTLS:              cached.RemoteTLS,
						RemoteTLSUseStartTLS:   cached.RemoteTLSUseStartTLS,
						RemoteTLSVerify:        cached.RemoteTLSVerify,
						RemoteUseProxyProtocol: cached.RemoteUseProxyProtocol,
					}
					if cached.ActualEmail != "" {
						s.username = cached.ActualEmail
					} else {
						s.username = username
					}

					// Refresh TTL since password matched
					s.server.lookupCache.Refresh(s.server.name, username)

					// Use resolved username for rate limiting and metrics
					s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, nil, s.username, true)
					metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "success").Inc()

					// Track domain and user activity using resolved email
					if addr, err := server.NewAddress(s.username); err == nil {
						metrics.TrackDomainConnection("pop3_proxy", addr.Domain())
						metrics.TrackUserActivity("pop3_proxy", addr.FullAddress(), "connection", 1)
					}

					// Set username on client connection for timeout logging
					if soraConn, ok := s.clientConn.(interface{ SetUsername(string) }); ok {
						soraConn.SetUsername(s.username)
					}

					// Check if context is cancelled (server shutting down) before attempting backend connection
					if err := s.ctx.Err(); err != nil {
						s.WarnLog("context cancelled during cache hit, cannot connect to backend", "error", err)
						return server.ErrServerShuttingDown // Triggers UNAVAILABLE response instead of auth failed
					}

					// Connect to backend to set routing method and establish connection
					if err := s.connectToBackend(); err != nil {
						return fmt.Errorf("failed to connect to backend: %w", err)
					}

					// Single consolidated log for authentication success (AFTER backend connection succeeds)
					s.InfoLog("authentication successful", "cached", true, "method", "cache")

					return nil
				} else {
					// Different password on positive entry - always revalidate
					// Use configured window: revalidate if entry is older than positiveRevalidationWindow
					if cached.IsOld(s.server.positiveRevalidationWindow) {
						s.DebugLog("cache positive entry - revalidating with different password", "username", username, "age", time.Since(cached.CreatedAt), "window", s.server.positiveRevalidationWindow)
						metrics.CacheOperationsTotal.WithLabelValues("get", "revalidate_positive_different_pw").Inc()
						// Fall through to full auth
					} else {
						// Entry is fresh - likely wrong password attempt
						s.DebugLog("cache hit - wrong password on fresh positive entry", "username", username)
						metrics.CacheOperationsTotal.WithLabelValues("get", "hit_positive_wrong_pw").Inc()
						s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, nil, username, false)
						metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "failure").Inc()
						return consts.ErrAuthenticationFailed
					}
				}
			}
		} else {
			s.DebugLog("cache miss", "username", username)
			metrics.CacheOperationsTotal.WithLabelValues("get", "miss").Inc()
		}
	}

	// Check if the authentication attempt is allowed by the rate limiter using proxy-aware methods
	if err := s.server.authLimiter.CanAttemptAuthWithProxy(ctx, s.clientConn, nil, username); err != nil {
		// Check if this is a rate limit error
		var rateLimitErr *server.RateLimitError
		if errors.As(err, &rateLimitErr) {
			logger.Info("POP3 Proxy: Rate limit exceeded",
				"username", username,
				"ip", rateLimitErr.IP,
				"reason", rateLimitErr.Reason,
				"failure_count", rateLimitErr.FailureCount,
				"blocked_until", rateLimitErr.BlockedUntil.Format(time.RFC3339))

			// Track rate limiting
			metrics.ProtocolErrors.WithLabelValues("pop3_proxy", "AUTH", "rate_limited", "client_error").Inc()

			// Return the error - caller will send appropriate POP3 response
			return rateLimitErr
		}

		// Unknown rate limiting error
		metrics.ProtocolErrors.WithLabelValues("pop3_proxy", "AUTH", "rate_limited", "client_error").Inc()
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
		if len(s.server.masterUsername) > 0 && checkMasterCredential(parsedAddr.Suffix(), []byte(s.server.masterUsername)) {
			// Suffix matches master username - validate master password locally
			if !checkMasterCredential(password, []byte(s.server.masterPassword)) {
				// Wrong master password - fail immediately
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, nil, parsedAddr.BaseAddress(), false)
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "failure").Inc()
				return consts.ErrAuthenticationFailed
			}
			// Master credentials validated - use base address (without @MASTER suffix) for prelookup
			s.DebugLog("master username authentication successful, using base address for routing", "base_address", parsedAddr.BaseAddress())
			usernameForPrelookup = parsedAddr.BaseAddress()
			masterAuthValidated = true
		} else {
			// Suffix doesn't match master username - treat as token
			// Send FULL username (including @TOKEN) to prelookup for validation
			s.DebugLog("token detected in username, sending full username to prelookup", "username", username)
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
		routingInfo, authResult, err := s.server.connManager.AuthenticateAndRouteWithOptions(ctx, usernameForPrelookup, password, masterAuthValidated)

		// Log prelookup response with all details
		backend := "none"
		actualEmail := "none"
		if routingInfo != nil {
			if routingInfo.ServerAddress != "" {
				backend = routingInfo.ServerAddress
			}
			if routingInfo.ActualEmail != "" {
				actualEmail = routingInfo.ActualEmail
			}
		}
		// Get client address (GetAddrString is safe - uses IP.String() for TCP/UDP, no DNS lookup)
		clientAddr := server.GetAddrString(s.clientConn.RemoteAddr())
		if err != nil {
			logger.Debug("prelookup authentication", "proto", "pop3_proxy", "name", s.server.name, "remote", clientAddr, "client_username", username, "sent_to_prelookup", usernameForPrelookup, "master_auth", masterAuthValidated, "result", authResult.String(), "backend", backend, "actual_email", actualEmail, "error", err)
		} else {
			logger.Debug("prelookup authentication", "proto", "pop3_proxy", "name", s.server.name, "remote", clientAddr, "client_username", username, "sent_to_prelookup", usernameForPrelookup, "master_auth", masterAuthValidated, "result", authResult.String(), "backend", backend, "actual_email", actualEmail)
		}

		if err != nil {
			// Categorize the error type to determine fallback behavior
			if errors.Is(err, proxy.ErrPrelookupInvalidResponse) {
				// Invalid response from prelookup (malformed 2xx) - this is a server bug, fail hard
				s.WarnLog("prelookup returned invalid response - server bug, rejecting authentication", "error", err)
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, nil, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "failure").Inc()
				return fmt.Errorf("prelookup server error: invalid response")
			}

			if errors.Is(err, proxy.ErrPrelookupTransient) {
				// Check if this is due to context cancellation (server shutdown)
				if errors.Is(err, server.ErrServerShuttingDown) {
					s.InfoLog("prelookup cancelled due to server shutdown")
					metrics.PrelookupResult.WithLabelValues("pop3", "shutdown").Inc()
					return server.ErrServerShuttingDown
				}

				// Transient error (network, 5xx, circuit breaker) - check fallback config
				if s.server.prelookupConfig != nil && s.server.prelookupConfig.FallbackDefault {
					s.WarnLog("prelookup transient error, fallback enabled - attempting main DB: %v", err)
					metrics.PrelookupResult.WithLabelValues("pop3", "transient_error_fallback").Inc()
					// Fallthrough to main DB auth
				} else {
					s.WarnLog("prelookup transient error, fallback disabled - rejecting authentication: %v", err)
					metrics.PrelookupResult.WithLabelValues("pop3", "transient_error_rejected").Inc()
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
				// Prelookup returned success - use routing info
				s.DebugLog("prelookup successful", "account_id", routingInfo.AccountID, "master_auth_validated", masterAuthValidated)
				metrics.PrelookupResult.WithLabelValues("pop3", "success").Inc()
				s.accountID = routingInfo.AccountID
				s.isPrelookupAccount = routingInfo.IsPrelookupAccount
				s.routingInfo = routingInfo

				// Determine the resolved email for caching and backend impersonation
				// Use ActualEmail from prelookup response if available, otherwise derive from username
				var resolvedEmail string
				if routingInfo.ActualEmail != "" {
					resolvedEmail = routingInfo.ActualEmail
				} else if masterAuthValidated {
					resolvedEmail = usernameForPrelookup // Base address already
				} else {
					resolvedEmail = username // Fallback to original
				}
				s.username = resolvedEmail // Use for backend impersonation

				// Set username on client connection for timeout logging
				if soraConn, ok := s.clientConn.(interface{ SetUsername(string) }); ok {
					soraConn.SetUsername(s.username)
				}

				// Cache successful authentication with routing info
				// CRITICAL: Cache key is submitted username (e.g., "user@TOKEN")
				// BUT store ActualEmail so cache hits can use the resolved address
				// Always hash password, even for master auth, to prevent cache bypass
				if s.server.lookupCache != nil {
					passwordHash := ""
					if password != "" {
						passwordHash = lookupcache.HashPassword(password)
					}
					s.server.lookupCache.Set(s.server.name, username, &lookupcache.CacheEntry{
						AccountID:              routingInfo.AccountID,
						PasswordHash:           passwordHash,
						ActualEmail:            resolvedEmail, // Store resolved email for cache hits
						ServerAddress:          routingInfo.ServerAddress,
						RemoteTLS:              routingInfo.RemoteTLS,
						RemoteTLSUseStartTLS:   routingInfo.RemoteTLSUseStartTLS,
						RemoteTLSVerify:        routingInfo.RemoteTLSVerify,
						RemoteUseProxyProtocol: routingInfo.RemoteUseProxyProtocol,
						Result:                 lookupcache.AuthSuccess,
						FromPrelookup:          true,
						IsNegative:             false,
					})
				}

				s.authenticated = true
				// Use resolvedEmail for rate limiting (not submitted username with token)
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, nil, resolvedEmail, true)
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "success").Inc()

				// For metrics, use resolvedEmail for accurate tracking
				if addr, err := server.NewAddress(resolvedEmail); err == nil {
					metrics.TrackDomainConnection("pop3_proxy", addr.Domain())
					metrics.TrackUserActivity("pop3_proxy", addr.FullAddress(), "connection", 1)
				}

				// Single consolidated log for authentication success
				method := "prelookup"
				if masterAuthValidated {
					method = "master"
				}
				s.InfoLog("authentication successful", "cached", false, "method", method)

				// Connect to backend
				if err := s.connectToBackend(); err != nil {
					return fmt.Errorf("failed to connect to backend: %w", err)
				}
				return nil // Authentication complete

			case proxy.AuthFailed:
				// User found in prelookup, but password was wrong
				// For master username, this shouldn't happen (password already validated)
				// For others, reject immediately
				if masterAuthValidated {
					s.WarnLog("prelookup failed but master auth was already validated - routing issue", "user", username)
				}

				// Cache negative result (wrong password)
				if s.server.lookupCache != nil {
					passwordHash := ""
					if password != "" {
						passwordHash = lookupcache.HashPassword(password)
					}
					s.server.lookupCache.Set(s.server.name, username, &lookupcache.CacheEntry{
						PasswordHash: passwordHash,
						Result:       lookupcache.AuthFailed,
						IsNegative:   true,
					})
				}

				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, nil, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "failure").Inc()

				// Single consolidated log for authentication failure
				s.InfoLog("authentication failed", "reason", "invalid_password", "cached", false, "method", "prelookup")

				return consts.ErrAuthenticationFailed

			case proxy.AuthTemporarilyUnavailable:
				// Prelookup service is temporarily unavailable - tell user to retry later
				s.WarnLog("prelookup service temporarily unavailable")
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "unavailable").Inc()
				return fmt.Errorf("authentication service temporarily unavailable, please try again later")

			case proxy.AuthUserNotFound:
				// User not found in prelookup (404). This means the user is NOT in the other system.
				// Always fall through to main DB auth - this is the expected behavior for partitioning.
				s.InfoLog("user not found in prelookup, attempting main DB")
				metrics.PrelookupResult.WithLabelValues("pop3", "user_not_found_fallback").Inc()
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
			// Check if error is due to context cancellation (server shutdown)
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				s.InfoLog("master auth cancelled due to server shutdown")
				return server.ErrServerShuttingDown
			}

			s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, nil, address.BaseAddress(), false)
			metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "failure").Inc()
			return fmt.Errorf("account not found: %w", err)
		}
	} else {
		// Regular authentication via main DB
		s.DebugLog("Authenticating user via main database")
		// Use base address (without +detail) for authentication
		accountID, err = s.server.rdb.AuthenticateWithRetry(ctx, address.BaseAddress(), password)
		if err != nil {
			// Check if error is due to context cancellation (server shutdown)
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				s.InfoLog("authentication cancelled due to server shutdown")
				return server.ErrServerShuttingDown
			}

			// Determine failure reason for logging
			reason := "transient_error"
			if errors.Is(err, consts.ErrUserNotFound) || strings.Contains(err.Error(), "user not found") {
				reason = "user_not_found"
			} else if strings.Contains(err.Error(), "hashedPassword is not the hash") {
				reason = "invalid_password"
			}

			// Cache negative result (authentication failed)
			// Only cache auth failures, not transient DB errors
			isDefinitiveFailure := errors.Is(err, consts.ErrUserNotFound) ||
				strings.Contains(err.Error(), "hashedPassword is not the hash") ||
				strings.Contains(err.Error(), "user not found")

			if isDefinitiveFailure {
				if s.server.lookupCache != nil {
					passwordHash := ""
					if password != "" {
						passwordHash = lookupcache.HashPassword(password)
					}
					s.server.lookupCache.Set(s.server.name, username, &lookupcache.CacheEntry{
						PasswordHash: passwordHash,
						Result:       lookupcache.AuthFailed,
						IsNegative:   true,
					})
				}
				// Single consolidated log for authentication failure
				s.InfoLog("authentication failed", "reason", reason, "cached", false, "method", "main_db")
			} else {
				s.DebugLog("NOT caching transient error - circuit breaker will handle", "username", username, "error", err)
				// Single consolidated log for authentication failure (transient)
				s.InfoLog("authentication failed", "reason", reason, "cached", false, "method", "main_db")
			}

			s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, nil, username, false)
			metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "failure").Inc()
			return fmt.Errorf("%w: %w", consts.ErrAuthenticationFailed, err)
		}
	}

	s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, s.clientConn, nil, username, true)

	// Track successful authentication.
	metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "success").Inc()
	metrics.TrackDomainConnection("pop3_proxy", address.Domain())
	metrics.TrackUserActivity("pop3_proxy", address.FullAddress(), "connection", 1)

	// Single consolidated log for authentication success
	method := "main_db"
	if masterAuthValidated {
		method = "master"
	}
	s.InfoLog("authentication successful", "cached", false, "method", method)

	// Cache successful authentication (main DB)
	if s.server.lookupCache != nil {
		passwordHash := ""
		if password != "" {
			passwordHash = lookupcache.HashPassword(password)
		}
		s.server.lookupCache.Set(s.server.name, username, &lookupcache.CacheEntry{
			AccountID:     accountID,
			PasswordHash:  passwordHash,
			ServerAddress: "", // Will be populated by affinity/routing in next connection
			Result:        lookupcache.AuthSuccess,
			FromPrelookup: false,
			IsNegative:    false,
		})
	}

	// Store user details on the session
	s.authenticated = true
	// Use base address (without +detail) for backend impersonation
	s.username = address.BaseAddress()
	s.accountID = accountID
	s.isPrelookupAccount = false

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
		s.WarnLog("Error determining route", "error", err)
	}

	// Update session routing info if it was fetched by DetermineRoute
	s.routingInfo = routeResult.RoutingInfo
	s.routingMethod = routeResult.RoutingMethod
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
		s.DebugLog("Failed to connect to backend", "error", err, "addr", preferredAddr)
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
	s.DebugLog("Backend connection established in connectToBackend()", "backend", actualAddr)

	// Record successful connection for future affinity if enabled
	// Auth-only prelookup users (IsPrelookupAccount=true but ServerAddress="") should get affinity
	if s.server.enableAffinity && actualAddr != "" {
		proxy.UpdateAffinityAfterConnection(proxy.RouteParams{
			Username:           s.username,
			Protocol:           "pop3",
			IsPrelookupAccount: s.isPrelookupAccount,
			RoutingInfo:        s.routingInfo, // Pass routing info so UpdateAffinity can check ServerAddress
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
		return fmt.Errorf("%w: failed to read backend greeting: %w", server.ErrBackendConnectionFailed, err)
	}

	if !strings.HasPrefix(greeting, "+OK") {
		s.backendConn.Close()
		return fmt.Errorf("%w: unexpected backend greeting: %s", server.ErrBackendConnectionFailed, greeting)
	}

	// Store backendReader for use in proxy phase to avoid losing buffered data
	s.backendReader = backendReader

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
			s.WarnLog("Failed to send forwarding parameters to backend", "error", err)
			// Continue anyway - forwarding parameters are not critical for functionality
		}
	}

	// Authenticate to backend using master SASL credentials via AUTH PLAIN
	authString := fmt.Sprintf("%s\x00%s\x00%s", s.username, s.server.masterSASLUsername, s.server.masterSASLPassword)
	encoded := base64.StdEncoding.EncodeToString([]byte(authString))

	if _, err := backendWriter.WriteString(fmt.Sprintf("AUTH PLAIN %s\r\n", encoded)); err != nil {
		s.backendConn.Close()
		return fmt.Errorf("%w: failed to send AUTH PLAIN to backend: %w", server.ErrBackendAuthFailed, err)
	}
	if err := backendWriter.Flush(); err != nil {
		s.backendConn.Close()
		return fmt.Errorf("%w: failed to flush AUTH PLAIN to backend: %w", server.ErrBackendAuthFailed, err)
	}

	// Read auth response
	authResp, err := backendReader.ReadString('\n')
	if err != nil {
		s.backendConn.Close()
		return fmt.Errorf("%w: failed to read auth response: %w", server.ErrBackendAuthFailed, err)
	}

	if !strings.HasPrefix(authResp, "+OK") {
		s.backendConn.Close()
		return fmt.Errorf("%w: %s", server.ErrBackendAuthFailed, strings.TrimSpace(authResp))
	}

	s.DebugLog("Authenticated to backend")

	return nil
}

func (s *POP3ProxySession) startProxying() {
	if s.backendConn == nil {
		s.WarnLog("Backend connection not established - startProxying() returning early")
		return
	}

	defer s.backendConn.Close()

	s.DebugLog("startProxying() called - backend connected to", "backend", s.serverAddr)

	var wg sync.WaitGroup

	s.DebugLog("Created waitgroup")

	// Start activity updater
	activityCtx, activityCancel := context.WithCancel(s.ctx)
	defer activityCancel()
	s.DebugLog("Starting activity updater")
	go s.updateActivityPeriodically(activityCtx)

	// Copy from client to backend with command filtering
	wg.Add(1)
	s.DebugLog("Starting client-to-backend copy goroutine")
	go func() {
		defer wg.Done()
		// If this copy returns, it means the client has closed the connection or there was an error.
		// We must close the backend connection to unblock the other copy operation.
		defer s.backendConn.Close()
		s.filteredCopyClientToBackend()
		s.DebugLog("Client-to-backend copy goroutine exiting")
	}()

	// Copy from backend to client with write deadline protection
	wg.Add(1)
	s.DebugLog("Starting backend-to-client copy goroutine")
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
			bytesOut, err = s.copyReaderToConnWithDeadline(s.clientConn, s.backendReader, "backend-to-client")
		} else {
			// Fallback to direct copy if no buffered reader (shouldn't happen in normal flow)
			bytesOut, err = server.CopyWithDeadline(s.ctx, s.clientConn, s.backendConn, "backend-to-client")
		}
		metrics.BytesThroughput.WithLabelValues("pop3_proxy", "out").Add(float64(bytesOut))
		if err != nil {
			if isClosingError(err) {
				s.DebugLog("backend-to-client copy ended normally (connection closed)", "error", err, "bytes_copied", bytesOut)
			} else {
				s.WarnLog("error copying backend to client", "error", err, "bytes_copied", bytesOut)
			}
		} else {
			s.DebugLog("backend-to-client copy completed successfully", "bytes_copied", bytesOut)
		}
		s.DebugLog("Backend-to-client copy goroutine exiting")
	}()

	// Context cancellation handler - ensures connections are closed when context is cancelled
	// This unblocks the copy goroutines if they're stuck in blocked Read() calls
	// NOTE: This is NOT part of the waitgroup to avoid circular dependency where:
	//   - wg.Wait() waits for this goroutine
	//   - this goroutine waits for ctx.Done()
	//   - ctx.Done() fires when handleConnection() returns
	//   - handleConnection() can't return because it's blocked in wg.Wait()
	s.DebugLog("Starting context cancellation handler goroutine")
	go func() {
		s.DebugLog("Context cancellation handler waiting for ctx.Done()")
		<-s.ctx.Done()
		s.DebugLog("Context cancelled - closing connections")
		s.clientConn.Close()
		s.backendConn.Close()
		s.DebugLog("Context cancellation handler goroutine exiting")
	}()

	s.DebugLog("Waiting for copy goroutines to finish")
	wg.Wait() // Wait for both copy operations to finish
	s.DebugLog("Copy goroutines finished - startProxying() returning")
}

// close closes all connections and unregisters from tracking.
func (s *POP3ProxySession) close() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Remove session from active tracking
	s.server.removeSession(s)

	// Release connection limiter slot IMMEDIATELY (don't wait for goroutine to exit)
	if s.releaseConn != nil {
		s.releaseConn()
		s.releaseConn = nil // Prevent double-release
		logger.Debug("Connection limit released in close()", "proxy", s.server.name)
	}

	// Log disconnection at INFO level
	duration := time.Since(s.startTime).Round(time.Second)
	s.InfoLog("disconnected", "duration", duration, "backend", s.serverAddr)

	// Decrement current connections metric
	metrics.ConnectionsCurrent.WithLabelValues("pop3_proxy").Dec()

	// Unregister connection SYNCHRONOUSLY to prevent leak
	// CRITICAL: Must be synchronous to ensure unregister completes before session goroutine exits
	// Background goroutine was causing leaks when server shutdown or high load prevented execution
	if s.accountID > 0 && s.server.connTracker != nil {
		// Use a new background context for this final operation, as s.ctx is likely already cancelled.
		// UnregisterConnection is fast (in-memory only), so this won't block for long
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		if err := s.server.connTracker.UnregisterConnection(ctx, s.accountID, "POP3", s.RemoteIP); err != nil {
			// Connection tracking is non-critical monitoring data, so log but continue
			s.WarnLog("Failed to unregister connection", "error", err)
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
func (s *POP3ProxySession) registerConnection() error {
	// Use configured database query timeout for connection tracking (database INSERT)
	queryTimeout := s.server.rdb.GetQueryTimeout()
	ctx, cancel := context.WithTimeout(s.ctx, queryTimeout)
	defer cancel()

	if s.server.connTracker != nil {
		return s.server.connTracker.RegisterConnection(ctx, s.accountID, s.username, "POP3", s.RemoteIP)
	}
	return nil
}

// updateActivityPeriodically updates the connection activity in the database.
func (s *POP3ProxySession) updateActivityPeriodically(ctx context.Context) {
	// If connection tracking is disabled, do nothing and wait for session to end.
	if s.server.connTracker == nil {
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
			s.InfoLog("connection kicked - disconnecting", "backend", s.serverAddr)
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

	// Write deadline for backend writes (30 seconds should be enough for any command)
	const writeDeadline = 30 * time.Second

	for {
		// Set a read deadline to prevent idle authenticated connections.
		if s.server.authIdleTimeout > 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.authIdleTimeout)); err != nil {
				s.WarnLog("Failed to set read deadline", "error", err)
				return
			}
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.DebugLog("Idle timeout for authenticated user, closing connection")
				return
			}
			if err != io.EOF && !isClosingError(err) {
				s.WarnLog("error reading from client", "error", err)
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

		// Set write deadline to prevent blocking on slow backend
		if err := s.backendConn.SetWriteDeadline(time.Now().Add(writeDeadline)); err != nil {
			s.WarnLog("Failed to set write deadline", "error", err)
			return
		}

		// Forward the command to backend
		n, err := writer.WriteString(line)
		totalBytesIn += int64(n)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.WarnLog("Backend write timeout (slow backend), closing connection")
				return
			}
			if !isClosingError(err) {
				s.WarnLog("error writing to backend", "error", err)
			}
			return
		}

		if err := writer.Flush(); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.WarnLog("Backend flush timeout (slow backend), closing connection")
				return
			}
			if !isClosingError(err) {
				s.WarnLog("error flushing to backend", "error", err)
			}
			return
		}
	}
}

// copyReaderToConnWithDeadline copies data from a buffered reader to a connection with write deadline protection.
// This is used for backend-to-client copying when the backend connection has a buffered reader
// from the authentication phase. We must read from the buffered reader to avoid losing any data
// that was buffered but not yet read.
func (s *POP3ProxySession) copyReaderToConnWithDeadline(dst net.Conn, src *bufio.Reader, direction string) (int64, error) {
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
					return totalBytes, fmt.Errorf("write timeout in %s: %w", direction, ew)
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

func checkMasterCredential(provided string, actual []byte) bool {
	return subtle.ConstantTimeCompare([]byte(provided), actual) == 1
}
