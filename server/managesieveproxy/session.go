package managesieveproxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieve"
	"github.com/migadu/sora/server/proxy"
)

// Session represents a ManageSieve proxy session.
type Session struct {
	server                *Server
	clientConn            net.Conn
	backendConn           net.Conn
	backendReader         *bufio.Reader // Buffered reader from authentication phase
	clientReader          *bufio.Reader
	clientWriter          *bufio.Writer
	username              string
	accountID             int64
	isRemoteLookupAccount bool
	routingInfo           *proxy.UserRoutingInfo
	routingMethod         string // Routing method used: remotelookup, affinity, consistent_hash, roundrobin
	serverAddr            string
	clientAddr            string // Cached client address to avoid race with connection close
	isTLS                 bool   // Whether the client connection is over TLS
	mu                    sync.Mutex
	ctx                   context.Context
	cancel                context.CancelFunc
	errorCount            int
	startTime             time.Time
	releaseConn           func() // Connection limiter cleanup function
	proxyInfo             *server.ProxyProtocolInfo
}

// newSession creates a new ManageSieve proxy session.
func newSession(s *Server, conn net.Conn, proxyInfo *server.ProxyProtocolInfo) *Session {
	sessionCtx, sessionCancel := context.WithCancel(s.ctx)
	// Check if connection is already TLS (implicit TLS)
	_, isTLS := conn.(*tls.Conn)

	// Determine client address (use PROXY protocol info if available)
	clientAddr := server.GetAddrString(conn.RemoteAddr())
	if proxyInfo != nil && proxyInfo.SrcIP != "" {
		clientAddr = proxyInfo.SrcIP
	}

	return &Session{
		server:       s,
		clientConn:   conn,
		clientReader: bufio.NewReader(conn),
		clientWriter: bufio.NewWriter(conn),
		clientAddr:   clientAddr, // Use real client IP from PROXY protocol or connection
		isTLS:        isTLS,
		ctx:          sessionCtx,
		cancel:       sessionCancel,
		errorCount:   0,
		startTime:    time.Now(),
		proxyInfo:    proxyInfo,
	}
}

// handleConnection handles the proxy session.
func (s *Session) handleConnection() {
	defer s.cancel()
	defer s.close()

	// Ensure connections are closed when context is cancelled (e.g. by absolute timeout or server shutdown)
	// This serves as a fail-safe to unblock reads that don't inherently respect context cancellation
	go func() {
		<-s.ctx.Done()
		// Force close connection to unblock any pending Read calls
		// Use mutex to ensure safe access consistent with close()
		s.mu.Lock()
		if s.clientConn != nil {
			s.clientConn.Close()
		}
		s.mu.Unlock()
	}()

	// Enforce absolute session timeout to prevent hung sessions from leaking
	if s.server.absoluteSessionTimeout > 0 {
		timeout := time.AfterFunc(s.server.absoluteSessionTimeout, func() {
			logger.Info("Absolute session timeout reached - force closing", "name", s.server.name, "duration", s.server.absoluteSessionTimeout, "username", s.username)
			s.cancel() // Force cancel context to unblock any stuck I/O
		})
		defer timeout.Stop()
	}

	s.InfoLog("connected")

	// Perform TLS handshake if this is a TLS connection
	if tlsConn, ok := s.clientConn.(interface{ PerformHandshake() error }); ok {
		if err := tlsConn.PerformHandshake(); err != nil {
			s.DebugLog("TLS handshake failed", "error", err)
			return
		}
	}

	// Send initial greeting with capabilities
	if err := s.sendGreeting(); err != nil {
		s.DebugLog("failed to send greeting", "error", err)
		return
	}

	// Handle authentication phase
	authenticated := false
	for !authenticated {
		// Set a read deadline for the client command to prevent idle connections.
		if s.server.authIdleTimeout > 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.authIdleTimeout)); err != nil {
				s.DebugLog("failed to set read deadline", "error", err)
				return
			}
		}

		// Read command from client
		line, err := s.clientReader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.DebugLog("client timed out waiting for command")
				s.sendResponse(`NO "Idle timeout"`)
				return
			}
			if err != io.EOF {
				s.DebugLog("error reading from client", "error", err)
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

		s.DebugLog("client command", "command", helpers.MaskSensitive(line, command, "AUTHENTICATE", "LOGIN"))
		switch command {
		case "AUTHENTICATE":
			s.DebugLog("AUTHENTICATE command", "args_len", len(args))
			for i, arg := range args {
				s.DebugLog("AUTHENTICATE arg", "index", i, "value", arg)
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
				s.DebugLog("AUTHENTICATE using initial response")
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

					s.DebugLog("AUTHENTICATE reading literal", "bytes", literalSize)

					// Read the literal data
					literalData := make([]byte, literalSize)
					_, err = io.ReadFull(s.clientReader, literalData)
					if err != nil {
						s.DebugLog("error reading literal data", "error", err)
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
				s.DebugLog("AUTHENTICATE sending continuation")
				// Send continuation and wait for response
				s.sendContinuation()

				// Read SASL response
				saslLine, err = s.clientReader.ReadString('\n')
				if err != nil {
					s.DebugLog("error reading SASL response", "error", err)
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

			authStart := time.Now() // Start authentication timing
			if err := s.authenticateUser(authnID, password, authStart); err != nil {
				s.DebugLog("authentication failed", "error", err)
				// This is an actual authentication failure, not a protocol error.
				// The rate limiter handles this, so we don't count it as a command error.
				// Check if error is due to server shutdown or temporary unavailability
				if server.IsTemporaryAuthFailure(err) {
					s.sendResponse(`NO (UNAVAILABLE) "Service temporarily unavailable, please try again later"`)
				} else {
					s.sendResponse(`NO "Authentication failed"`)
				}
				continue
			}

			// Connect to backend and authenticate
			backendConnStart := time.Now()
			if err := s.connectToBackendAndAuth(); err != nil {
				s.DebugLog("backend connection/auth failed", "error", err)
				// Check if this is a timeout or connection error (backend unavailable)
				if server.IsTemporaryAuthFailure(err) || server.IsBackendError(err) {
					s.sendResponse(`NO (UNAVAILABLE) "Backend server temporarily unavailable"`)
				} else {
					s.sendResponse(`NO "Backend server error"`)
				}
				continue
			}

			// Register connection
			if err := s.registerConnection(); err != nil {
				s.DebugLog("failed to register connection", "error", err)
			}

			// Set username on client connection for timeout logging
			if soraConn, ok := s.clientConn.(interface{ SetUsername(string) }); ok {
				soraConn.SetUsername(s.username)
			}

			// Log backend authentication with total duration
			backendDuration := time.Since(backendConnStart)
			s.InfoLog("authentication complete",
				"address", s.username,
				"backend", s.serverAddr,
				"routing", s.routingMethod,
				"duration", fmt.Sprintf("%.3fs", backendDuration.Seconds()))

			s.sendResponse(`OK "Authenticated"`)
			authenticated = true

		case "LOGOUT":
			s.sendResponse(`OK "Bye"`)
			return

		case "NOOP":
			// Handle NOOP with optional tag argument (e.g., NOOP "STARTTLS-RESYNC-CAPA")
			// sieve-connect uses this to verify capabilities were received
			if len(args) > 0 {
				tag := server.UnquoteString(args[0])
				s.sendResponse(fmt.Sprintf(`OK (TAG "%s") "Done"`, tag))
			} else {
				s.sendResponse(`OK "NOOP completed"`)
			}

		case "CAPABILITY":
			// Re-send capabilities as per RFC 5804
			if err := s.sendCapabilities(); err != nil {
				s.DebugLog("error sending capabilities", "error", err)
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
				s.DebugLog("failed to send STARTTLS response", "error", err)
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
					s.DebugLog("failed to load TLS certificate", "error", err)
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
				s.DebugLog("STARTTLS config error")
				if s.handleAuthError(`NO "STARTTLS configuration error"`) {
					return
				}
				continue
			}

			// Upgrade connection to TLS
			tlsConn := tls.Server(s.clientConn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				s.DebugLog("TLS handshake failed", "error", err)
				return
			}

			// Update session with TLS connection
			s.clientConn = tlsConn
			s.clientReader = bufio.NewReader(tlsConn)
			s.clientWriter = bufio.NewWriter(tlsConn)
			s.isTLS = true

			s.DebugLog("STARTTLS negotiation successful")

			// Re-send greeting with updated capabilities (now with SASL mechanisms available)
			if err := s.sendGreeting(); err != nil {
				s.DebugLog("failed to send greeting after STARTTLS", "error", err)
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
	if s.server.authIdleTimeout > 0 {
		if err := s.clientConn.SetReadDeadline(time.Time{}); err != nil {
			s.DebugLog("failed to clear read deadline", "error", err)
		}
	}

	// Start proxying only if backend connection was successful
	if s.backendConn != nil {
		s.DebugLog("starting proxy")
		s.startProxy()
	} else {
		s.DebugLog("cannot start proxy - no backend connection")
	}
}

// handleAuthError increments the error count, sends an error response, and
// returns true if the connection should be dropped.
func (s *Session) handleAuthError(response string) bool {
	s.errorCount++
	s.sendResponse(response)
	if s.errorCount >= s.server.maxAuthErrors {
		s.WarnLog("too many auth errors - dropping connection")
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

// InfoLog logs at INFO level with session context
// getLogger returns a ProxySessionLogger for this session
func (s *Session) getLogger() *server.ProxySessionLogger {
	return &server.ProxySessionLogger{
		Protocol:   "managesieve_proxy",
		ServerName: s.server.name,
		ClientConn: s.clientConn,
		Username:   s.username,
		AccountID:  s.accountID,
		Debug:      s.server.debug,
	}
}

func (s *Session) InfoLog(msg string, keysAndValues ...any) {
	s.getLogger().InfoLog(msg, keysAndValues...)
}

// DebugLog logs at DEBUG level with session context
func (s *Session) DebugLog(msg string, keyvals ...any) {
	s.getLogger().DebugLog(msg, keyvals...)
}

// WarnLog logs at WARN level with session context
func (s *Session) WarnLog(msg string, keyvals ...any) {
	s.getLogger().WarnLog(msg, keyvals...)
}

// authenticateUser authenticates the user against the database.
func (s *Session) authenticateUser(username, password string, authStart time.Time) error {
	// Reject empty passwords immediately - no cache lookup, no rate limiting needed
	// Empty passwords are never valid under any condition
	if password == "" {
		return consts.ErrAuthenticationFailed
	}

	// Use configured remotelookup timeout instead of hardcoded value
	authTimeout := s.server.connManager.GetRemoteLookupTimeout()
	ctx, cancel := context.WithTimeout(s.ctx, authTimeout)
	defer cancel()

	// Apply progressive authentication delay BEFORE any other checks
	remoteAddr := s.clientConn.RemoteAddr()
	server.ApplyAuthenticationDelay(s.ctx, s.server.authLimiter, remoteAddr, "MANAGESIEVE-PROXY")

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
					// Same wrong password - return cached failure
					// NOTE: We do NOT refresh negative cache entries. They should expire
					// after negative_ttl to allow retry. Brute force protection is handled
					// by rate limiting, not by extending cache TTL.
					s.DebugLog("cache hit - negative entry with same password", "username", username, "age", time.Since(cached.CreatedAt))
					metrics.CacheOperationsTotal.WithLabelValues("get", "hit_negative").Inc()
					return consts.ErrAuthenticationFailed
				} else {
					// Different password - ALWAYS revalidate (user might have fixed their password)
					// Brute force protection is handled by protocol-level rate limiting
					s.DebugLog("cache negative entry - revalidating with different password", "username", username, "age", time.Since(cached.CreatedAt))
					metrics.CacheOperationsTotal.WithLabelValues("get", "revalidate_negative_different_pw").Inc()
					// Fall through to full authentication
				}
			} else {
				// Positive cache entry - successful authentication previously cached
				if passwordMatches {
					// Same password - use cached routing info
					// NOTE: We do NOT refresh routing cache. Entries should expire after
					// positive_ttl to allow periodic revalidation via remotelookup/database.
					// This ensures that when a domain moves backends or password changes,
					// active users eventually pick up the changes.
					s.DebugLog("cache hit - positive entry with matching password", "username", username, "age", time.Since(cached.CreatedAt))
					metrics.CacheOperationsTotal.WithLabelValues("get", "hit_positive").Inc()

					// Populate session with cached routing info
					s.accountID = cached.AccountID
					s.isRemoteLookupAccount = cached.FromRemoteLookup

					// Otherwise parse username to extract base address
					if cached.ActualEmail != "" {
						s.username = cached.ActualEmail
					} else if parsedAddr, parseErr := server.NewAddress(username); parseErr == nil {
						s.username = parsedAddr.BaseAddress() // Use base address (without @SUFFIX)
					} else {
						s.username = username // Fallback
					}

					if cached.ServerAddress != "" {
						s.routingInfo = &proxy.UserRoutingInfo{
							AccountID:              cached.AccountID,
							ServerAddress:          cached.ServerAddress,
							RemoteTLS:              cached.RemoteTLS,
							RemoteTLSUseStartTLS:   cached.RemoteTLSUseStartTLS,
							RemoteTLSVerify:        cached.RemoteTLSVerify,
							RemoteUseProxyProtocol: cached.RemoteUseProxyProtocol,
							IsRemoteLookupAccount:  cached.FromRemoteLookup,
						}
					}

					// Track successful authentication using resolved email
					s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, s.username, true)
					metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", s.server.name, s.server.hostname, "success").Inc()
					if addr, err := server.NewAddress(s.username); err == nil {
						metrics.TrackDomainConnection("managesieve_proxy", addr.Domain())
						metrics.TrackUserActivity("managesieve_proxy", addr.FullAddress(), "connection", 1)
					}

					// Single consolidated log for authentication success
					duration := time.Since(authStart)
					s.InfoLog("authentication successful",
						"address", s.username,
						"backend", "none", // Cache hit - no backend yet
						"method", "cache",
						"cached", true,
						"duration", fmt.Sprintf("%.3fs", duration.Seconds()))

					return nil // Authentication complete from cache
				} else {
					// Different password on positive cache - revalidate if old enough
					if cached.IsOld(s.server.positiveRevalidationWindow) {
						s.DebugLog("cache hit - positive entry with different password (old enough to revalidate)", "username", username, "age", time.Since(cached.CreatedAt))
						metrics.CacheOperationsTotal.WithLabelValues("get", "hit_positive_revalidate").Inc()
						// Fall through to full authentication
					} else {
						// Different password but too fresh
						s.DebugLog("cache hit - positive entry with different password (too fresh)", "username", username, "age", time.Since(cached.CreatedAt))
						metrics.CacheOperationsTotal.WithLabelValues("get", "hit_positive_fresh").Inc()
						return consts.ErrAuthenticationFailed
					}
				}
			}
		} else {
			// Cache miss - proceed with full authentication
			s.DebugLog("cache miss", "username", username)
			metrics.CacheOperationsTotal.WithLabelValues("get", "miss").Inc()
		}
	}

	// Check if the authentication attempt is allowed by the rate limiter using proxy-aware methods
	if err := s.server.authLimiter.CanAttemptAuthWithProxy(s.ctx, s.clientConn, nil, username); err != nil {
		// Check if this is a rate limit error
		var rateLimitErr *server.RateLimitError
		if errors.As(err, &rateLimitErr) {
			logger.Info("ManageSieve Proxy: Rate limit exceeded",
				"username", username,
				"ip", rateLimitErr.IP,
				"reason", rateLimitErr.Reason,
				"failure_count", rateLimitErr.FailureCount,
				"blocked_until", rateLimitErr.BlockedUntil.Format(time.RFC3339))

			// Track rate limiting
			metrics.ProtocolErrors.WithLabelValues("managesieve_proxy", "AUTH", "rate_limited", "client_error").Inc()

			// Return the error - caller will send appropriate ManageSieve response
			return rateLimitErr
		}

		// Unknown rate limiting error
		metrics.ProtocolErrors.WithLabelValues("managesieve_proxy", "AUTH", "rate_limited", "client_error").Inc()
		return err
	}

	// Parse username to check for master username or token suffix
	// Format: user@domain.com@SUFFIX
	// If SUFFIX matches configured master username: validate locally, send base address to remotelookup
	// Otherwise: treat as token, send full username (including @SUFFIX) to remotelookup
	var usernameForRemoteLookup string
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
				metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", s.server.name, s.server.hostname, "failure").Inc()
				return consts.ErrAuthenticationFailed
			}
			// Master credentials validated - use base address (without @MASTER suffix) for remotelookup
			s.DebugLog("master username authentication successful, using base address for routing", "address", parsedAddr.BaseAddress())
			usernameForRemoteLookup = parsedAddr.BaseAddress()
			masterAuthValidated = true
		} else {
			// Suffix doesn't match master username - treat as token
			// Send FULL username (including @TOKEN) to remotelookup for validation
			s.DebugLog("token detected in username, sending full username to remotelookup", "username", username)
			usernameForRemoteLookup = username
			masterAuthValidated = false
		}
	} else {
		// No suffix - regular username
		usernameForRemoteLookup = username
		masterAuthValidated = false
	}

	// Try remotelookup authentication/routing if configured
	// - For master username: sends base address to get routing info (password already validated)
	// - For others: sends full username (may contain token) for remotelookup authentication
	if s.server.connManager.HasRouting() {
		routingInfo, authResult, err := s.server.connManager.AuthenticateAndRouteWithOptions(ctx, usernameForRemoteLookup, password, masterAuthValidated)

		// Log remotelookup response with all details
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
			logger.Debug("remotelookup authentication", "proto", "managesieve_proxy", "name", s.server.name, "remote", clientAddr, "client_username", username, "sent_to_remotelookup", usernameForRemoteLookup, "master_auth", masterAuthValidated, "result", authResult.String(), "backend", backend, "actual_email", actualEmail, "error", err)
		} else {
			logger.Debug("remotelookup authentication", "proto", "managesieve_proxy", "name", s.server.name, "remote", clientAddr, "client_username", username, "sent_to_remotelookup", usernameForRemoteLookup, "master_auth", masterAuthValidated, "result", authResult.String(), "backend", backend, "actual_email", actualEmail)
		}

		if err != nil {
			// Categorize the error type to determine fallback behavior
			if errors.Is(err, proxy.ErrRemoteLookupInvalidResponse) {
				// Invalid response from remotelookup (malformed 2xx) - this is a server bug, fail hard
				s.WarnLog("remotelookup invalid response - server bug", "error", err)
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", s.server.name, s.server.hostname, "failure").Inc()
				return fmt.Errorf("remotelookup server error: invalid response")
			}

			if errors.Is(err, proxy.ErrRemoteLookupTransient) {
				// Check if this is due to context cancellation (server shutdown)
				if errors.Is(err, server.ErrServerShuttingDown) {
					s.InfoLog("remotelookup cancelled due to server shutdown")
					metrics.RemoteLookupResult.WithLabelValues("managesieve", "shutdown").Inc()
					return server.ErrServerShuttingDown
				}

				// Transient error (network, 5xx, circuit breaker) - NEVER fallback to DB
				// These are service availability issues, not "user not found" cases
				s.DebugLog("remotelookup transient error - service unavailable", "error", err)
				metrics.RemoteLookupResult.WithLabelValues("managesieve", "transient_error_rejected").Inc()
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", s.server.name, s.server.hostname, "failure").Inc()
				return fmt.Errorf("remotelookup service unavailable")
			} else {
				// Unknown error type - log and fallthrough
				s.WarnLog("remotelookup unknown error - attempting fallback", "error", err)
				// Fallthrough to main DB auth
			}
		} else {
			switch authResult {
			case proxy.AuthSuccess:
				// RemoteLookup returned success - use routing info
				s.DebugLog("remotelookup successful", "account_id", routingInfo.AccountID, "master_auth_validated", masterAuthValidated)
				s.DebugLog("remotelookup routing", "server", routingInfo.ServerAddress, "tls", routingInfo.RemoteTLS, "starttls", routingInfo.RemoteTLSUseStartTLS, "tls_verify", routingInfo.RemoteTLSVerify, "proxy_protocol", routingInfo.RemoteUseProxyProtocol)
				metrics.RemoteLookupResult.WithLabelValues("managesieve", "success").Inc()
				s.accountID = routingInfo.AccountID
				s.isRemoteLookupAccount = routingInfo.IsRemoteLookupAccount
				s.routingInfo = routingInfo

				// Determine the resolved email for caching and backend impersonation
				// Use ActualEmail from remotelookup response if available, otherwise derive from username
				var resolvedEmail string
				if routingInfo.ActualEmail != "" {
					resolvedEmail = routingInfo.ActualEmail
				} else if masterAuthValidated {
					resolvedEmail = usernameForRemoteLookup // Base address already
				} else {
					resolvedEmail = username // Fallback to original
				}
				s.username = resolvedEmail // Use for backend impersonation

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
						FromRemoteLookup:       true,
						IsNegative:             false,
					})
				}

				// Use resolvedEmail for rate limiting (not submitted username with token)
				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, resolvedEmail, true)
				metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", s.server.name, s.server.hostname, "success").Inc()

				// For metrics, use resolvedEmail for accurate tracking
				if addr, err := server.NewAddress(resolvedEmail); err == nil {
					metrics.TrackDomainConnection("managesieve_proxy", addr.Domain())
					metrics.TrackUserActivity("managesieve_proxy", addr.FullAddress(), "connection", 1)
				}

				// Single consolidated log for authentication success
				method := "remotelookup"
				if masterAuthValidated {
					method = "master"
				}
				duration := time.Since(authStart)
				s.InfoLog("authentication successful",
					"address", s.username,
					"backend", "none", // Backend not connected yet at this point
					"method", method,
					"cached", false,
					"duration", fmt.Sprintf("%.3fs", duration.Seconds()))

				return nil // Authentication complete

			case proxy.AuthFailed:
				// User found in remotelookup, but password was wrong
				// For master username, this shouldn't happen (password already validated)
				// For others, reject immediately
				if masterAuthValidated {
					s.WarnLog("remotelookup failed but master auth was already validated - routing issue", "user", username)
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

				s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", s.server.name, s.server.hostname, "failure").Inc()

				// Single consolidated log for authentication failure
				s.InfoLog("authentication failed", "reason", "invalid_password", "cached", false, "method", "remotelookup")

				return consts.ErrAuthenticationFailed

			case proxy.AuthTemporarilyUnavailable:
				// RemoteLookup service is temporarily unavailable - tell user to retry later
				s.WarnLog("remotelookup service temporarily unavailable")
				metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", s.server.name, s.server.hostname, "unavailable").Inc()
				return fmt.Errorf("authentication service temporarily unavailable, please try again later")

			case proxy.AuthUserNotFound:
				// User not found in remotelookup (404/3xx)
				if s.server.remotelookupConfig != nil && s.server.remotelookupConfig.ShouldLookupLocalUsers() {
					s.InfoLog("User not found in remotelookup, local lookup enabled - trying main DB")
					metrics.RemoteLookupResult.WithLabelValues("managesieve", "user_not_found_fallback").Inc()
					// Fallthrough to main DB auth
				} else {
					s.InfoLog("User not found in remotelookup, local lookup disabled - rejecting")
					metrics.RemoteLookupResult.WithLabelValues("managesieve", "user_not_found_rejected").Inc()
					s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
					metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", s.server.name, s.server.hostname, "failure").Inc()
					return consts.ErrAuthenticationFailed
				}
			}
		}
	}

	// Fallback to main DB
	// If master auth was already validated, just get account ID and continue
	// Otherwise, authenticate via main DB
	var address server.Address
	// Use already parsed address if available
	if parseErr == nil {
		address = parsedAddr
	} else {
		// Parse failed earlier - try again with NewAddress (shouldn't happen but handle it)
		var parseErr2 error
		address, parseErr2 = server.NewAddress(username)
		if parseErr2 != nil {
			return fmt.Errorf("invalid address format: %w", parseErr2)
		}
	}

	var accountID int64
	var err error
	if masterAuthValidated {
		// Master authentication already validated - just get account ID
		s.DebugLog("master auth already validated, getting account ID from main database")
		accountID, err = s.server.rdb.GetAccountIDByAddressWithRetry(ctx, address.BaseAddress())
		if err != nil {
			// Check if error is due to session context cancellation (server shutdown)
			// Note: Must check s.ctx.Err(), not just the query error, because the query context
			// can timeout (DeadlineExceeded) independently from server shutdown
			if s.ctx.Err() != nil {
				s.InfoLog("master auth cancelled due to server shutdown")
				return server.ErrServerShuttingDown
			}

			s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, address.BaseAddress(), false)
			metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", s.server.name, s.server.hostname, "failure").Inc()
			return fmt.Errorf("account not found: %w", err)
		}
	} else {
		// Regular authentication via main DB
		s.DebugLog("Authenticating via main DB")
		// Use base address (without +detail) for authentication
		accountID, err = s.server.rdb.AuthenticateWithRetry(ctx, address.BaseAddress(), password)
		if err != nil {
			// Check if error is due to session context cancellation (server shutdown)
			// Note: Must check s.ctx.Err(), not just the query error, because the query context
			// can timeout (DeadlineExceeded) independently from server shutdown
			if s.ctx.Err() != nil {
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

			s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, false)
			metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", s.server.name, s.server.hostname, "failure").Inc()
			return fmt.Errorf("%w: %w", consts.ErrAuthenticationFailed, err)
		}
	}

	s.accountID = accountID
	s.isRemoteLookupAccount = false
	s.username = address.BaseAddress() // Set username for backend impersonation (without +detail)
	s.server.authLimiter.RecordAuthAttemptWithProxy(s.ctx, s.clientConn, nil, username, true)
	metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", s.server.name, s.server.hostname, "success").Inc()
	metrics.TrackDomainConnection("managesieve_proxy", address.Domain())
	metrics.TrackUserActivity("managesieve_proxy", address.FullAddress(), "connection", 1)

	// Single consolidated log for authentication success
	method := "main_db"
	if masterAuthValidated {
		method = "master"
	}
	duration := time.Since(authStart)
	s.InfoLog("authentication successful",
		"address", s.username,
		"backend", "none", // Backend not connected yet at this point
		"method", method,
		"cached", false,
		"duration", fmt.Sprintf("%.3fs", duration.Seconds()))

	// Cache successful authentication (main DB)
	if s.server.lookupCache != nil {
		passwordHash := ""
		if password != "" {
			passwordHash = lookupcache.HashPassword(password)
		}
		s.server.lookupCache.Set(s.server.name, username, &lookupcache.CacheEntry{
			AccountID:        accountID,
			PasswordHash:     passwordHash,
			ServerAddress:    "", // Will be populated by affinity/routing in next connection
			Result:           lookupcache.AuthSuccess,
			FromRemoteLookup: false,
			IsNegative:       false,
		})
	}

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
		Ctx:                   s.ctx,
		Username:              s.username,
		Protocol:              "managesieve",
		IsRemoteLookupAccount: s.isRemoteLookupAccount,
		RoutingInfo:           s.routingInfo,
		ConnManager:           s.server.connManager,
		EnableAffinity:        s.server.enableAffinity,
		ProxyName:             "ManageSieve Proxy",
	})
	if err != nil {
		s.DebugLog("Error determining route", "error", err)
	}

	// Update session routing info if it was fetched by DetermineRoute
	s.routingInfo = routeResult.RoutingInfo
	s.routingMethod = routeResult.RoutingMethod
	preferredAddr := routeResult.PreferredAddr
	isRemoteLookupRoute := routeResult.IsRemoteLookupRoute

	// 4. Connect using the determined address (or round-robin if empty)
	// Track which routing method was used for this connection.
	metrics.ProxyRoutingMethod.WithLabelValues("managesieve", routeResult.RoutingMethod).Inc()

	// Use configured backend connection timeout instead of hardcoded value
	connectTimeout := s.server.connManager.GetConnectTimeout()
	connectCtx, connectCancel := context.WithTimeout(s.ctx, connectTimeout)
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
	if isRemoteLookupRoute && actualAddr != preferredAddr {
		// The remotelookup route specified a server, but we connected to a different one.
		// This means the preferred server failed and the connection manager fell back.
		// For remotelookup routes, this is a hard failure.
		conn.Close()
		metrics.ProxyBackendConnections.WithLabelValues("managesieve", "failure").Inc()
		return fmt.Errorf("remotelookup route to %s failed, and fallback is disabled for remotelookup routes", preferredAddr)
	}

	metrics.ProxyBackendConnections.WithLabelValues("managesieve", "success").Inc()
	s.backendConn = conn
	s.serverAddr = actualAddr

	// Record successful connection for future affinity
	// Auth-only remotelookup users (IsRemoteLookupAccount=true but ServerAddress="") should get affinity
	if s.server.enableAffinity && actualAddr != "" {
		proxy.UpdateAffinityAfterConnection(proxy.RouteParams{
			Username:              s.username,
			Protocol:              "managesieve",
			IsRemoteLookupAccount: s.isRemoteLookupAccount,
			RoutingInfo:           s.routingInfo, // Pass routing info so UpdateAffinity can check ServerAddress
			ConnManager:           s.server.connManager,
			EnableAffinity:        s.server.enableAffinity,
			ProxyName:             "ManageSieve Proxy",
		}, actualAddr, routeResult.RoutingMethod == "affinity")
	}

	// Read backend greeting and capabilities
	backendReader := bufio.NewReader(s.backendConn)
	backendWriter := bufio.NewWriter(s.backendConn)
	for {
		line, err := backendReader.ReadString('\n')
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("%w: failed to read backend greeting: %w", server.ErrBackendConnectionFailed, err)
		}

		// Just consume the backend greeting, don't forward it (we already sent our own)
		// Check if this is the OK line (end of capabilities)
		if strings.HasPrefix(strings.TrimSpace(line), "OK") {
			break
		}
	}

	// Check if we need to negotiate StartTLS with the backend
	// This happens when remotelookup (or global config) specifies remote_tls_use_starttls
	shouldUseStartTLS := false
	var tlsConfig *tls.Config

	if s.routingInfo != nil && s.routingInfo.RemoteTLSUseStartTLS {
		// RemoteLookup routing specified StartTLS
		shouldUseStartTLS = true
		tlsConfig = &tls.Config{
			InsecureSkipVerify: !s.routingInfo.RemoteTLSVerify,
			Renegotiation:      tls.RenegotiateNever,
		}
		s.DebugLog("Using remotelookup StartTLS settings", "remote_tls_verify", s.routingInfo.RemoteTLSVerify)
	} else if s.server.connManager.IsRemoteStartTLS() {
		// Global proxy config specified StartTLS
		shouldUseStartTLS = true
		tlsConfig = s.server.connManager.GetTLSConfig()
		s.DebugLog("Using global StartTLS settings")
	}

	if shouldUseStartTLS && tlsConfig != nil {
		s.DebugLog("Negotiating StartTLS with backend", "backend", actualAddr, "insecure_skip_verify", tlsConfig.InsecureSkipVerify)

		// Send STARTTLS command
		_, err := backendWriter.WriteString("STARTTLS\r\n")
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("%w: failed to send STARTTLS command: %w", server.ErrBackendConnectionFailed, err)
		}
		backendWriter.Flush()

		// Read STARTTLS response
		response, err := backendReader.ReadString('\n')
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("%w: failed to read STARTTLS response: %w", server.ErrBackendConnectionFailed, err)
		}

		if !strings.HasPrefix(strings.TrimSpace(response), "OK") {
			s.backendConn.Close()
			return fmt.Errorf("%w: backend STARTTLS failed: %s", server.ErrBackendConnectionFailed, strings.TrimSpace(response))
		}

		// Upgrade connection to TLS
		tlsConn := tls.Client(s.backendConn, tlsConfig)
		err = tlsConn.Handshake()
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("%w: TLS handshake with backend failed: %w", server.ErrBackendConnectionFailed, err)
		}

		s.DebugLog("StartTLS negotiation successful with backend", "backend", actualAddr)
		s.backendConn = tlsConn
	}

	// Now authenticate to backend
	return s.authenticateToBackend()
}

// authenticateToBackend authenticates to the backend using master credentials.
func (s *Session) authenticateToBackend() error {
	backendWriter := bufio.NewWriter(s.backendConn)
	backendReader := bufio.NewReader(s.backendConn)
	// Store backendReader for use in proxy phase to avoid losing buffered data
	s.backendReader = backendReader

	// Send AUTHENTICATE PLAIN command with impersonation
	authString := fmt.Sprintf("%s\x00%s\x00%s", s.username, string(s.server.masterSASLUsername), string(s.server.masterSASLPassword))
	encoded := base64.StdEncoding.EncodeToString([]byte(authString))

	s.DebugLog("Auth string format", "authorize_id", s.username, "authenticate_id", string(s.server.masterSASLUsername))
	s.DebugLog("Sending AUTHENTICATE command", "encoded", encoded)

	// ManageSieve requires quoted strings for command arguments
	_, err := backendWriter.WriteString(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"\r\n", encoded))
	if err != nil {
		return fmt.Errorf("%w: failed to send AUTHENTICATE command: %w", server.ErrBackendAuthFailed, err)
	}
	backendWriter.Flush()

	// Read authentication response
	response, err := backendReader.ReadString('\n')
	if err != nil {
		// CRITICAL: Invalidate cache on backend authentication failure
		if s.server.lookupCache != nil && s.username != "" {
			cacheKey := s.server.name + ":" + s.username
			s.server.lookupCache.Invalidate(cacheKey)
			s.DebugLog("invalidated cache due to backend auth read error", "cache_key", cacheKey)
		}
		return fmt.Errorf("%w: failed to read auth response: %w", server.ErrBackendAuthFailed, err)
	}

	s.DebugLog("Backend auth response", "response", strings.TrimSpace(response))

	if !strings.HasPrefix(response, "OK") {
		// CRITICAL: Invalidate cache on backend authentication failure
		// This ensures the next request does fresh remotelookup/database lookup
		// to pick up backend changes (e.g., domain moved to different server)
		if s.server.lookupCache != nil && s.username != "" {
			cacheKey := s.server.name + ":" + s.username
			s.server.lookupCache.Invalidate(cacheKey)
			s.DebugLog("invalidated cache due to backend auth rejection", "cache_key", cacheKey, "response", strings.TrimSpace(response))
		}
		return fmt.Errorf("%w: %s", server.ErrBackendAuthFailed, strings.TrimSpace(response))
	}

	s.DebugLog("Backend authentication successful")

	return nil
}

// startProxy starts bidirectional proxying between client and backend.
func (s *Session) startProxy() {
	if s.backendConn == nil {
		s.DebugLog("Backend connection not established")
		return
	}

	s.DebugLog("startProxy() called")

	var wg sync.WaitGroup

	s.DebugLog("Created waitgroup")

	// Start activity updater
	activityCtx, activityCancel := context.WithCancel(s.ctx)
	defer activityCancel()
	s.DebugLog("Starting activity updater")
	go s.updateActivityPeriodically(activityCtx)

	// Client to backend
	wg.Add(1)
	s.DebugLog("Starting client-to-backend copy goroutine")
	go func() {
		defer wg.Done()
		// If this copy returns, it means the client has closed the connection or there was an error.
		// We must close the backend connection to unblock the other copy operation.
		defer s.backendConn.Close()
		bytesIn, err := server.CopyWithDeadline(s.ctx, s.backendConn, s.clientConn, "client-to-backend")
		metrics.BytesThroughput.WithLabelValues("managesieve_proxy", "in").Add(float64(bytesIn))
		if err != nil && !isClosingError(err) {
			s.DebugLog("Error copying from client to backend", "error", err)
		}
		s.DebugLog("Client-to-backend copy goroutine exiting")
	}()

	// Backend to client
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
			bytesOut, err = s.copyBufferedReaderToConn(s.clientConn, s.backendReader)
		} else {
			// Fallback to direct copy if no buffered reader (shouldn't happen in normal flow)
			bytesOut, err = server.CopyWithDeadline(s.ctx, s.clientConn, s.backendConn, "backend-to-client")
		}
		metrics.BytesThroughput.WithLabelValues("managesieve_proxy", "out").Add(float64(bytesOut))
		if err != nil && !isClosingError(err) {
			s.DebugLog("Error copying from backend to client", "error", err)
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
	s.DebugLog("Copy goroutines finished - startProxy() returning")
}

// close closes all connections.
func (s *Session) close() {
	s.mu.Lock()
	defer s.mu.Unlock()

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
	metrics.ConnectionsCurrent.WithLabelValues("managesieve_proxy", s.server.name, s.server.hostname).Dec()

	// Unregister connection SYNCHRONOUSLY to prevent leak
	// CRITICAL: Must be synchronous to ensure unregister completes before session goroutine exits
	// Background goroutine was causing leaks when server shutdown or high load prevented execution
	// NOTE: accountID can be 0 for remotelookup accounts, so we don't check accountID > 0
	if s.server.connTracker != nil {
		// Use a new background context for this final operation, as s.ctx is likely already cancelled.
		// UnregisterConnection is fast (in-memory only), so this won't block for long
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		// Use cached client address to avoid race with connection close
		if err := s.server.connTracker.UnregisterConnection(ctx, s.accountID, "ManageSieve", s.clientAddr); err != nil {
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
func (s *Session) registerConnection() error {
	// Use configured database query timeout for connection tracking (database INSERT)
	// Default to 30 seconds if database is not available (proxy-only mode)
	queryTimeout := 30 * time.Second
	if s.server.rdb != nil {
		queryTimeout = s.server.rdb.GetQueryTimeout()
	}
	ctx, cancel := context.WithTimeout(s.ctx, queryTimeout)
	defer cancel()

	// Use cached client address (real IP) to match UnregisterConnection in close()
	if s.server.connTracker != nil {
		return s.server.connTracker.RegisterConnection(ctx, s.accountID, s.username, "ManageSieve", s.clientAddr)
	}
	return nil
}

// updateActivityPeriodically updates the connection activity in the database.
func (s *Session) updateActivityPeriodically(ctx context.Context) {
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
			s.InfoLog("connection kicked")
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

// checkMasterCredential compares two credentials using constant-time comparison.

func checkMasterCredential(provided string, expected []byte) bool {
	return subtle.ConstantTimeCompare([]byte(provided), expected) == 1
}
