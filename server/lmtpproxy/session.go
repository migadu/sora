package lmtpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/proxy"
)

// Session represents an LMTP proxy session.
type Session struct {
	server                *Server
	clientConn            net.Conn
	backendConn           net.Conn
	backendReader         *bufio.Reader
	backendWriter         *bufio.Writer
	clientReader          *bufio.Reader
	clientWriter          *bufio.Writer
	sender                string
	mailFromReceived      bool
	to                    string
	toAddress             *server.Address // Parsed recipient address with detail
	username              string
	originalAddress       string // Original base address (cache key) before remotelookup resolution
	isRemoteLookupAccount bool
	routingInfo           *proxy.UserRoutingInfo
	accountID             int64
	serverAddr            string
	routingMethod         string
	sessionID             string // Proxy session ID for end-to-end tracing (also forwarded to the backend)
	clientAddr            string // Cached client address to avoid race with connection close
	clientHelo            string // Client's announced HELO/EHLO/LHLO name, forwarded to the backend via XCLIENT
	releaseConn           func() // Connection limiter cleanup function
	gracefulShutdown      bool   // Set during server shutdown to prevent copy goroutine from closing clientConn
	mu                    sync.Mutex
	ctx                   context.Context
	cancel                context.CancelFunc
	startTime             time.Time
	proxyInfo             *server.ProxyProtocolInfo

	// Connection tracker bookkeeping:
	// LMTP sessions can contain multiple RCPT TO commands (multiple recipients).
	// We register the session as a "connection" against each recipient account we handle.
	// IMPORTANT: s.accountID is overwritten per RCPT; if we only unregister the last one,
	// earlier recipients would leak connection counts permanently.
	registeredAccountIDs map[int64]struct{}
}

// newSession creates a new LMTP proxy session.
func newSession(s *Server, conn net.Conn, proxyInfo *server.ProxyProtocolInfo) *Session {
	sessionCtx, sessionCancel := context.WithCancel(s.ctx)

	// Determine client address (use PROXY protocol info if available)
	clientAddr := server.GetAddrString(conn.RemoteAddr())
	if proxyInfo != nil && proxyInfo.SrcIP != "" {
		clientAddr = proxyInfo.SrcIP
	}

	return &Session{
		server:               s,
		clientConn:           conn,
		clientReader:         bufio.NewReader(conn),
		clientWriter:         bufio.NewWriter(conn),
		clientAddr:           clientAddr, // Use real client IP from PROXY protocol or connection
		ctx:                  sessionCtx,
		cancel:               sessionCancel,
		startTime:            time.Now(),
		proxyInfo:            proxyInfo,
		registeredAccountIDs: make(map[int64]struct{}),
		// Generate the session id once, up front, so every log line carries it.
		// It's also forwarded to the backend (XCLIENT), logged there as proxy_session.
		sessionID: idgen.New(),
	}
}

// handleConnection handles the proxy session.
func (s *Session) handleConnection() {
	defer s.cancel()
	defer s.close()
	defer s.server.unregisterSession(s)
	defer metrics.ConnectionsCurrent.WithLabelValues("lmtp_proxy", s.server.name, s.server.hostname).Dec()

	// Ensure connections are closed when context is cancelled (e.g. by absolute timeout or server shutdown)
	// This serves as a fail-safe to unblock reads that don't inherently respect context cancellation.
	// IMPORTANT: The backend connection must be closed here too. Before this, a backend that
	// hung during the handshake or a RCPT/DATA response read kept the session goroutine blocked
	// forever: the absolute session timeout only closed the client connection, which does not
	// unblock a read on the backend connection.
	go func() {
		<-s.ctx.Done()
		// Force close connections to unblock any pending Read calls
		// Use mutex to ensure safe access consistent with close()
		s.mu.Lock()
		if s.clientConn != nil {
			s.clientConn.Close()
		}
		if s.backendConn != nil {
			s.backendConn.Close()
		}
		s.mu.Unlock()
	}()

	// Enforce absolute session timeout to prevent hung sessions from leaking
	if s.server.absoluteSessionTimeout > 0 {
		timeout := time.AfterFunc(s.server.absoluteSessionTimeout, func() {
			s.InfoLog("Absolute session timeout reached - force closing", "duration", s.server.absoluteSessionTimeout)
			s.cancel() // Force cancel context to unblock any stuck I/O
		})
		defer timeout.Stop()
	}

	// Log connection at INFO level
	s.InfoLog("connected", "absolute_timeout", s.server.absoluteSessionTimeout, "auth_idle_timeout", s.server.authIdleTimeout)

	// Register this session for graceful shutdown tracking
	s.server.registerSession(s)

	// Complete the deferred TLS handshake (implicit-TLS listeners). The helper
	// walks the Unwrap() chain, so the handshake runs through the PROXY conn
	// and consumes any ClientHello bytes buffered alongside the PROXY header.
	// Failure is a silent close: no plaintext banner onto a broken TLS stream.
	if _, err := server.PerformDeferredTLSHandshake(s.clientConn); err != nil {
		s.DebugLog("TLS handshake failed", "error", err)
		return
	}

	// Send greeting
	if err := s.sendGreeting(); err != nil {
		s.DebugLog("Failed to send greeting", "error", err)
		return
	}

	// Handle commands until we get RCPT TO
	for {
		// Check if context is cancelled (server shutdown or absolute timeout)
		select {
		case <-s.ctx.Done():
			s.InfoLog("Session context cancelled", "reason", s.ctx.Err())
			s.sendResponse("421 4.3.2 Service closing connection")
			return
		default:
			// Continue normal operation
		}

		// Set a read deadline for the client command to prevent idle connections.
		if s.server.authIdleTimeout > 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.authIdleTimeout)); err != nil {
				s.DebugLog("Failed to set read deadline", "error", err)
				return
			}
		}

		// Read command from client (bounded to prevent pre-auth memory exhaustion)
		line, err := server.ReadBoundedLine(s.clientReader, 8192)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.DebugLog("Client timed out waiting for command")
				s.sendResponse("421 4.4.2 Idle timeout, closing connection")
				return
			}
			if !isClosingError(err) {
				s.DebugLog("Error reading from client", "error", err)
			}
			return
		}

		line = strings.TrimRight(line, "\r\n")
		s.DebugLog("Client command", "line", line)

		// Use the shared command parser. LMTP commands do not have tags.
		_, command, args, err := server.ParseLine(line, false)
		if err != nil {
			s.sendResponse(fmt.Sprintf("500 5.5.2 Syntax error: %s", err.Error()))
			continue
		}

		if command == "" {
			continue // Ignore empty lines
		}

		switch command {
		case "HELO", "EHLO", "LHLO":
			// LHLO is LMTP-specific greeting
			if len(args) < 1 {
				s.sendResponse("501 5.5.4 Syntax error in parameters")
				continue
			}
			// Remember the client's announced name so we can forward it to the backend via
			// XCLIENT (HELO=...); without it the backend's Received: trace falls back to the
			// proxy's own LHLO name. args[0] is a single tokenized field (no spaces/CRLF).
			s.clientHelo = args[0]
			if command == "EHLO" || command == "LHLO" {
				// Send extended response
				s.sendResponse(fmt.Sprintf("250-%s", s.server.hostname))

				// Advertise STARTTLS if configured and not already using TLS
				if s.server.tls && s.server.tlsUseStartTLS {
					if _, ok := s.clientConn.(*tls.Conn); !ok {
						s.sendResponse("250-STARTTLS")
					}
				}

				s.sendResponse("250-PIPELINING")
				if s.server.maxMessageSize > 0 {
					s.sendResponse(fmt.Sprintf("250-SIZE %d", s.server.maxMessageSize))
				}
				s.sendResponse("250-ENHANCEDSTATUSCODES")
				s.sendResponse("250-8BITMIME")
				s.sendResponse("250 DSN")
			} else {
				s.sendResponse(fmt.Sprintf("250 %s", s.server.hostname))
			}

		case "MAIL":
			fromParam, found := findParameter(args, "FROM:")
			if !found {
				s.sendResponse("501 5.5.4 Syntax error in MAIL command (missing FROM)")
				continue
			}
			// Note: extractAddress can return an empty string for a null sender "<>", which is valid.
			sender := s.extractAddress(fromParam)
			s.sender = sender
			s.mailFromReceived = true
			s.sendResponse("250 2.1.0 Ok")

		case "RCPT":
			toParam, found := findParameter(args, "TO:")
			if !found {
				s.DebugLog("RCPT command missing TO parameter", "args", fmt.Sprintf("%v", args))
				s.sendResponse("501 5.5.4 Syntax error in RCPT command (missing TO)")
				continue
			}

			// Extract the recipient address (first part before any parameters)
			// toParam may contain the address and additional ESMTP parameters
			// Example: "<user@example.com> NOTIFY=NEVER ORCPT=rfc822;user@example.com"
			s.DebugLog("Parsing RCPT TO", "toParam", toParam, "args", fmt.Sprintf("%v", args))
			to := s.extractAddress(toParam)
			if to == "" {
				s.DebugLog("Failed to extract address", "toParam", toParam)
				s.sendResponse("501 5.1.3 Bad recipient address syntax")
				continue
			}
			s.DebugLog("Extracted recipient address", "to", to)

			lookupStart := time.Now() // Start account lookup timing
			if err := s.handleRecipient(to, lookupStart); err != nil {
				s.DebugLog("Recipient rejected", "to", to, "error", err)
				// Check if error is due to server shutdown
				if errors.Is(err, server.ErrServerShuttingDown) {
					s.InfoLog("Recipient lookup failed due to server shutdown", "to", to)
					s.sendResponse("421 4.3.2 Service shutting down, please try again later")
					return
				}
				// Check if error is a temporary service unavailability (remotelookup transient error)
				if errors.Is(err, server.ErrAuthServiceUnavailable) {
					s.InfoLog("rejecting recipient - remote lookup service temporarily unavailable",
						"to", to,
						"response", "451 4.4.3")
					s.sendResponse("451 4.4.3 Service temporarily unavailable, please try again later")
					continue
				}
				// Check if error is user not found (permanent failure)
				if errors.Is(err, server.ErrUserNotFound) {
					s.InfoLog("rejecting recipient - user not found",
						"to", to,
						"response", "550 5.1.1")
					s.sendResponse("550 5.1.1 User unknown")
					continue
				}
				// Check if user not found with tempfail response
				if errors.Is(err, server.ErrUserNotFoundTempFail) {
					s.InfoLog("tempfail recipient - user not found (tempfail configured)",
						"to", to,
						"response", "450 4.1.1")
					s.sendResponse("450 4.1.1 User unknown (temporary failure)")
					continue
				}
				// Check if recipient address is syntactically invalid (permanent failure)
				if errors.Is(err, server.ErrInvalidAddress) {
					s.InfoLog("rejecting recipient - invalid address syntax",
						"to", to,
						"error", err.Error(),
						"response", "550 5.1.3")
					s.sendResponse("550 5.1.3 Bad destination mailbox address syntax")
					continue
				}
				// Unknown/unexpected error - use temporary failure to be safe
				// If this is actually a permanent issue, it will keep failing on retry
				// If it's transient (e.g., database timeout), sender can retry
				s.InfoLog("rejecting recipient - unexpected lookup error, temporary failure",
					"to", to,
					"error", err.Error(),
					"response", "451 4.3.0")
				s.sendResponse("451 4.3.0 Temporary failure, please try again later")
				continue
			}

			// Clear the read deadline before connecting to the backend and starting the proxy.
			// The proxy loop will manage its own deadlines.
			if s.server.authIdleTimeout > 0 {
				if err := s.clientConn.SetReadDeadline(time.Time{}); err != nil {
					s.DebugLog("Failed to clear read deadline", "error", err)
				}
			}

			// Connect to backend if not already connected
			if s.backendConn == nil {
				if err := s.connectToBackend(); err != nil {
					s.InfoLog("backend connection failed", "from", s.sender, "to", s.to, "error", err)
					// NOTE: we deliberately do NOT invalidate the lookup cache here.
					// The cache exists to protect remotelookup; invalidating on
					// connect failure would hammer remotelookup with one query per
					// delivery attempt for the whole duration of a backend outage.
					// Routing is revalidated via positive-TTL expiry instead (see
					// integration_tests/lmtpproxy/backend_rejection_cache_test.go).
					s.sendResponse("451 4.4.1 Backend connection failed")
					// Do not return, continue loop to handle RSET or QUIT
					continue
				}
				// Register connection
				if err := s.registerConnection(); err != nil {
					s.InfoLog("rejected connection registration", "error", err)
				}
			} else {
				// Verify if the current backend connection is compatible with this recipient
				// Since we are reusing the connection, we must ensure this user routes to the same backend
				routeResult, err := proxy.DetermineRoute(proxy.RouteParams{
					Ctx:                   s.ctx,
					Username:              s.originalAddress,
					Protocol:              "lmtp",
					IsRemoteLookupAccount: s.isRemoteLookupAccount,
					RoutingInfo:           s.routingInfo,
					ConnManager:           s.server.connManager,
					EnableAffinity:        s.server.enableAffinity,
					ProxyName:             "LMTP Proxy",
				})

				if err == nil {
					targetAddr := routeResult.PreferredAddr
					// If a specific backend is required (targetAddr not empty) and it differs from
					// the currently connected backend, we must reject this recipient.
					// The client should retry this recipient in a separate transaction.
					if targetAddr != "" && targetAddr != s.serverAddr {
						s.InfoLog("rejecting recipient - routing mismatch (requires different backend)",
							"to", s.to,
							"current_backend", s.serverAddr,
							"target_backend", targetAddr,
							"method", routeResult.RoutingMethod)
						s.sendResponse("451 4.3.0 Recipient requires different backend server, start new transaction")
						continue
					}
				}
			}

			// Forward RCPT TO to backend
			if s.backendConn != nil {
				s.DebugLog("Forwarding RCPT TO to backend", "to", s.to, "account_id", s.accountID)
				s.forwardRCPT(line)
			} else {
				s.WarnLog("Cannot forward RCPT - no backend connection", "to", s.to)
				s.sendResponse("451 4.4.1 Backend connection failed")
			}
			// Continue loop to handle subsequent RCPT TOs or DATA

		case "DATA":
			if s.backendConn == nil {
				s.sendResponse("503 5.5.1 Bad sequence of commands (not connected to backend)")
				continue
			}

			// Send DATA to backend
			_, err := s.backendWriter.WriteString("DATA\r\n")
			if err != nil {
				s.DebugLog("Failed to send DATA to backend", "error", err)
				s.sendResponse("451 4.4.2 Backend error")
				// Connection likely dead, close it?
				s.backendConn.Close()
				s.backendConn = nil
				continue
			}
			s.backendWriter.Flush()

			// Read DATA response (bounded, with read deadline so a hung backend
			// cannot block the session forever)
			response, err := s.readBackendLine()
			if err != nil {
				s.DebugLog("Failed to read DATA response", "error", err)
				s.sendResponse("451 4.4.2 Backend error")
				s.backendConn.Close()
				s.backendConn = nil
				continue
			}

			// Check response
			if !strings.HasPrefix(response, "354") {
				// Backend rejected DATA
				s.clientWriter.WriteString(response)
				s.clientWriter.Flush()
				continue
			}

			// Backend accepted DATA (354), forward to client
			s.clientWriter.WriteString(response)
			s.clientWriter.Flush()

			// Enter pipe mode for data transfer
			s.DebugLog("Entering pipe mode for DATA transfer")
			s.enterPipeMode()
			return

		case "STARTTLS":
			// Check if STARTTLS is enabled
			if !s.server.tls || !s.server.tlsUseStartTLS {
				s.sendResponse("502 5.5.1 STARTTLS not available")
				continue
			}

			// Check if already using TLS
			if _, ok := s.clientConn.(*tls.Conn); ok {
				s.sendResponse("454 4.3.0 TLS not available: Already using TLS")
				continue
			}

			// Send OK response
			if err := s.sendResponse("220 2.0.0 Ready to start TLS"); err != nil {
				s.DebugLog("Failed to send STARTTLS response", "error", err)
				return
			}

			// Load TLS config: Use global TLS manager config if available, otherwise load from files
			var tlsConfig *tls.Config
			if s.server.tlsConfig != nil {
				// Use global TLS manager (e.g., Let's Encrypt autocert)
				tlsConfig = s.server.tlsConfig
			} else if s.server.tlsCertFile != "" && s.server.tlsKeyFile != "" {
				// Load from cert files
				cert, err := tls.LoadX509KeyPair(s.server.tlsCertFile, s.server.tlsKeyFile)
				if err != nil {
					s.DebugLog("Failed to load TLS certificate", "error", err)
					return
				}

				tlsConfig = &tls.Config{
					MinVersion:    tls.VersionTLS12,
					Certificates:  []tls.Certificate{cert},
					ClientAuth:    tls.NoClientCert,
					Renegotiation: tls.RenegotiateNever,
				}
				if s.server.tlsVerify {
					tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
				}
			} else {
				s.DebugLog("STARTTLS config error")
				s.sendResponse("454 4.3.0 TLS not available due to configuration error")
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

			s.DebugLog("STARTTLS negotiation successful")

			// Client must send EHLO/LHLO again after STARTTLS (RFC 3207)
			// Continue to next iteration to wait for new EHLO/LHLO

		case "RSET":
			s.sender = ""
			s.to = ""
			s.mailFromReceived = false
			s.sendResponse("250 2.0.0 Ok")

		case "NOOP":
			s.sendResponse("250 2.0.0 Ok")

		case "QUIT":
			s.sendResponse("221 2.0.0 Bye")
			return

		default:
			s.sendResponse("502 5.5.2 Command not implemented")
		}
	}
}

// sendGreeting sends the LMTP greeting.
func (s *Session) sendGreeting() error {
	greeting := fmt.Sprintf("220 %s LMTP Service Ready\r\n", s.server.hostname)
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

// Log logs a client command if debug is enabled.
// This is for debug output only, not session logging.
func (s *Session) Log(format string, args ...any) {
	if s.server.debugWriter != nil {
		message := fmt.Sprintf(format, args...)
		s.server.debugWriter.Write([]byte(message))
	}
}

// getLogger returns a ProxySessionLogger for this session
func (s *Session) getLogger() *server.ProxySessionLogger {
	return &server.ProxySessionLogger{
		Protocol:   "lmtp_proxy",
		ServerName: s.server.name,
		ClientConn: s.clientConn,
		Username:   s.username,
		AccountID:  s.accountID,
		SessionID:  s.sessionID,
		Debug:      s.server.debug,
	}
}

// InfoLog logs at INFO level with session context
func (s *Session) InfoLog(msg string, keyvals ...any) {
	s.getLogger().InfoLog(msg, keyvals...)
}

// DebugLog logs at DEBUG level with session context
func (s *Session) DebugLog(msg string, keyvals ...any) {
	s.getLogger().DebugLog(msg, keyvals...)
}

// WarnLog logs at WARN level with session context
func (s *Session) WarnLog(msg string, keyvals ...any) {
	s.getLogger().WarnLog(msg, keyvals...)
}

// ErrorLog logs at ERROR level with session context
func (s *Session) ErrorLog(msg string, keyvals ...any) {
	s.getLogger().ErrorLog(msg, keyvals...)
}

// stripUnsupportedRCPTParameters removes ESMTP parameters from RCPT TO commands that
// are not commonly supported by LMTP servers. This uses an allowlist approach - only
// explicitly allowed parameters are kept, everything else is stripped.
//
// Allowed RCPT TO parameters for LMTP:
//   - XRCPTFORWARD: Dovecot-specific forwarding information (original recipient)
//
// Stripped parameters (SMTP-only, not supported by typical LMTP servers):
//   - NOTIFY, ORCPT, RET, ENVID: DSN extensions (RFC 3461)
//   - Any other unknown ESMTP parameters
//
// Examples:
//   - "RCPT TO:<user@example.com> NOTIFY=NEVER" -> "RCPT TO:<user@example.com>"
//   - "RCPT TO:<user@example.com> NOTIFY=NEVER XRCPTFORWARD=fwd@example.com" -> "RCPT TO:<user@example.com> XRCPTFORWARD=fwd@example.com"
//   - "RCPT TO:<user@example.com> UNKNOWN=value" -> "RCPT TO:<user@example.com>"
func stripUnsupportedRCPTParameters(command string) string {
	// Only process RCPT TO commands
	if !strings.HasPrefix(strings.ToUpper(command), "RCPT TO") {
		return command
	}

	// Find the recipient address (between < and >)
	startIdx := strings.Index(command, "<")
	if startIdx == -1 {
		return command // No angle bracket, return as-is
	}

	endIdx := strings.Index(command[startIdx:], ">")
	if endIdx == -1 {
		return command // No closing bracket, return as-is
	}
	endIdx += startIdx // Adjust to absolute position

	// Extract the RCPT TO prefix and the address
	// Everything before and including the closing > bracket
	cleanCommand := command[:endIdx+1]

	// Check if there are any parameters after the address
	remainder := strings.TrimSpace(command[endIdx+1:])
	if remainder == "" {
		return cleanCommand // No parameters, already clean
	}

	// Allowlist of RCPT TO parameters supported by LMTP servers
	// Using a map for O(1) lookup
	allowedParams := map[string]bool{
		"XRCPTFORWARD": true, // Dovecot-specific: original recipient for forwarding
		// Add more LMTP-supported parameters here if needed
	}

	// Parse parameters and keep only allowed ones
	params := strings.Fields(remainder)
	var keptParams []string

	for _, param := range params {
		// Extract parameter name (before '=')
		parts := strings.SplitN(param, "=", 2)
		if len(parts) == 0 {
			continue // Malformed parameter
		}

		paramName := strings.ToUpper(parts[0])

		// Keep only if in allowlist
		if allowedParams[paramName] {
			keptParams = append(keptParams, param)
		}
		// Silently drop everything else (DSN parameters, unknown parameters, etc.)
	}

	// Reconstruct command with kept parameters
	if len(keptParams) > 0 {
		return cleanCommand + " " + strings.Join(keptParams, " ")
	}

	return cleanCommand
}

// extractAddress extracts email address from MAIL FROM or RCPT TO parameter.
// This handles ESMTP parameters that may follow the address, such as:
//   - MAIL FROM:<user@example.com> SIZE=1234
//   - RCPT TO:<user@example.com> NOTIFY=NEVER ORCPT=rfc822;user@example.com
func (s *Session) extractAddress(param string) string {
	// The parameter value might be quoted, so unquote it first.
	param = server.UnquoteString(strings.TrimSpace(param))

	if len(param) < 2 {
		return ""
	}

	// Handle <address> format with or without additional ESMTP parameters
	// Extract everything between < and > (the address), ignoring anything after >
	if param[0] == '<' {
		endIdx := strings.Index(param, ">")
		if endIdx > 0 {
			// Found closing bracket - extract address between < and >
			return param[1:endIdx]
		}
		// No closing bracket found - invalid format
		return ""
	}

	// Some clients might not use angle brackets (non-standard but handle it)
	// In this case, stop at the first space (which would separate address from parameters)
	if idx := strings.Index(param, " "); idx > 0 {
		return param[:idx]
	}

	return param
}

// handleRecipient looks up the recipient, determines routing, and sets session state.
func (s *Session) handleRecipient(to string, lookupStart time.Time) error {
	address, err := server.NewAddress(to)
	if err != nil {
		s.InfoLog("rejecting recipient - invalid address format",
			"to", to,
			"error", err.Error())
		return fmt.Errorf("%w: %w", server.ErrInvalidAddress, err)
	}

	s.to = to
	s.toAddress = &address // Store parsed address with detail
	s.username = address.BaseAddress()

	// Store original submitted address for cache operations
	// Cache key must always be the original address, not resolved address
	originalAddress := s.username
	s.originalAddress = originalAddress // Store in session for cache invalidation later

	// Set username on client connection for timeout logging
	if soraConn, ok := s.clientConn.(interface{ SetUsername(string) }); ok {
		soraConn.SetUsername(s.username)
	}

	// Check cache first (for routing info - no password validation needed)
	if cached, found := s.server.lookupCache.Get(s.server.name, originalAddress); found {
		if cached.IsNegative {
			// User previously not found - return cached failure
			// Note: Do NOT refresh negative entries - let them expire naturally so we can
			// re-check the database in case the user was created since last check
			metrics.CacheOperationsTotal.WithLabelValues("get", "hit_negative").Inc()

			// Single consolidated log for lookup failure
			duration := time.Since(lookupStart)
			s.InfoLog("account lookup failed",
				"address", s.username,
				"reason", "user_not_found",
				"cached", true,
				"method", "cache",
				"duration", fmt.Sprintf("%.3fs", duration.Seconds()))

			return server.ErrUserNotFound
		} else {
			// User found - use cached routing info
			metrics.CacheOperationsTotal.WithLabelValues("get", "hit").Inc()

			s.accountID = cached.AccountID
			s.isRemoteLookupAccount = cached.FromRemoteLookup
			s.routingInfo = &proxy.UserRoutingInfo{
				AccountID:              cached.AccountID,
				ServerAddress:          cached.ServerAddress,
				IsRemoteLookupAccount:  cached.FromRemoteLookup, // CRITICAL: Prevents fallback to other backends
				RemoteTLS:              cached.RemoteTLS,
				RemoteTLSUseStartTLS:   cached.RemoteTLSUseStartTLS,
				RemoteTLSVerify:        cached.RemoteTLSVerify,
				RemoteUseProxyProtocol: cached.RemoteUseProxyProtocol,
				RemoteUseXCLIENT:       cached.RemoteUseXCLIENT,
			}

			if cached.ActualEmail != "" {
				s.username = cached.ActualEmail
			}

			// NOTE: We intentionally do NOT call Refresh() for routing cache.
			// Routing entries should expire after positive_ttl to allow periodic
			// revalidation via remotelookup. This ensures that when a domain moves
			// backends, active users eventually pick up the new backend.
			// See: integration_tests/lmtpproxy/routing_cache_expiration_test.go

			// Single consolidated log for lookup success
			duration := time.Since(lookupStart)
			s.InfoLog("account lookup successful",
				"address", s.username,
				"cached", true,
				"method", "cache",
				"duration", fmt.Sprintf("%.3fs", duration.Seconds()))

			return nil
		}
	}

	// 1. Try remotelookup first
	hasRouting := s.server.connManager.HasRouting()

	if hasRouting {
		// Call remotelookup API
		routingTimeout := s.server.connManager.GetRemoteLookupTimeout()
		routingCtx, routingCancel := context.WithTimeout(s.ctx, routingTimeout)
		defer routingCancel()

		remoteLookupStart := time.Now()
		routingInfo, lookupErr := s.server.connManager.LookupUserRoute(routingCtx, s.username)
		remoteLookupDuration := time.Since(remoteLookupStart).Seconds()

		if lookupErr != nil {
			s.InfoLog("remotelookup failed", "username", s.username, "error", lookupErr, "cache", "miss")

			// Check if error is due to context cancellation (server shutdown)
			if errors.Is(lookupErr, server.ErrServerShuttingDown) {
				s.InfoLog("remotelookup cancelled due to server shutdown")
				metrics.RemoteLookupResult.WithLabelValues("lmtp", "shutdown").Inc()
				metrics.RemoteLookupDuration.WithLabelValues("lmtp", "shutdown").Observe(remoteLookupDuration)
				return server.ErrServerShuttingDown
			}

			// Transient errors (network, 5xx, circuit breaker) - NEVER fallback to DB
			// These are service availability issues, not "user not found" cases
			// Return ErrAuthServiceUnavailable so caller can send 451 (temporary) instead of 550 (permanent)
			duration := time.Since(lookupStart)
			s.InfoLog("remotelookup transient error - service unavailable, rejecting recipient",
				"username", s.username,
				"error", lookupErr.Error(),
				"duration", fmt.Sprintf("%.3fs", duration.Seconds()))
			metrics.RemoteLookupResult.WithLabelValues("lmtp", "transient_error_rejected").Inc()
			metrics.RemoteLookupDuration.WithLabelValues("lmtp", "transient_error").Observe(remoteLookupDuration)
			return server.ErrAuthServiceUnavailable
		} else if routingInfo != nil {
			// RemoteLookup succeeded - may or may not have ServerAddress
			// If no ServerAddress, backend selection will use consistent hash/round-robin
			metrics.RemoteLookupResult.WithLabelValues("lmtp", "success").Inc()
			metrics.RemoteLookupDuration.WithLabelValues("lmtp", "success").Observe(remoteLookupDuration)
			s.routingInfo = routingInfo
			s.isRemoteLookupAccount = true
			s.accountID = routingInfo.AccountID // May be 0, that's fine

			// Use ActualEmail from remotelookup if available (for token resolution)
			var resolvedEmail string
			if routingInfo.ActualEmail != "" {
				resolvedEmail = routingInfo.ActualEmail
				s.username = resolvedEmail // Update username with resolved email
			} else {
				resolvedEmail = s.username // Use already-set username (BaseAddress)
			}

			// Cache positive result (routing info found)
			// Cache key is originalAddress (BaseAddress of submitted recipient)
			// Store ActualEmail if remotelookup resolved to a different address
			s.server.lookupCache.Set(s.server.name, originalAddress, &lookupcache.CacheEntry{
				AccountID:              routingInfo.AccountID,
				ActualEmail:            resolvedEmail, // Store resolved email for cache hits
				ServerAddress:          routingInfo.ServerAddress,
				RemoteTLS:              routingInfo.RemoteTLS,
				RemoteTLSUseStartTLS:   routingInfo.RemoteTLSUseStartTLS,
				RemoteTLSVerify:        routingInfo.RemoteTLSVerify,
				RemoteUseProxyProtocol: routingInfo.RemoteUseProxyProtocol,
				RemoteUseXCLIENT:       routingInfo.RemoteUseXCLIENT,
				Result:                 lookupcache.AuthSuccess,
				FromRemoteLookup:       true,
			})

			// Single consolidated log for lookup success
			duration := time.Since(lookupStart)
			s.InfoLog("account lookup successful",
				"address", s.username,
				"cached", false,
				"method", "remotelookup",
				"duration", fmt.Sprintf("%.3fs", duration.Seconds()))

			return nil
		} else {
			// User not found in remotelookup (404/3xx or empty response).
			duration := time.Since(lookupStart)
			metrics.RemoteLookupDuration.WithLabelValues("lmtp", "user_not_found").Observe(remoteLookupDuration)
			if s.server.remotelookupConfig != nil && s.server.remotelookupConfig.ShouldLookupLocalUsers() {
				s.InfoLog("user not found in remote lookup, local lookup enabled - attempting main DB",
					"username", s.username,
					"duration", fmt.Sprintf("%.3fs", duration.Seconds()))
				metrics.RemoteLookupResult.WithLabelValues("lmtp", "user_not_found_fallback").Inc()
				// Fallthrough to main DB
			} else {
				// User not found and no database fallback - use configured response
				response := "reject" // default
				if s.server.remotelookupConfig != nil {
					response = s.server.remotelookupConfig.GetUserNotFoundResponse()
				}

				s.InfoLog("user not found in remote lookup, fallback disabled",
					"username", s.username,
					"duration", fmt.Sprintf("%.3fs", duration.Seconds()),
					"response", response)
				metrics.RemoteLookupResult.WithLabelValues("lmtp", "user_not_found_"+response).Inc()

				// Cache negative result to protect remotelookup
				s.server.lookupCache.Set(s.server.name, originalAddress, &lookupcache.CacheEntry{
					Result:     lookupcache.AuthUserNotFound,
					IsNegative: true,
				})

				// Return appropriate error based on configuration
				if response == "tempfail" {
					return server.ErrUserNotFoundTempFail
				}
				return server.ErrUserNotFound
			}
		}
	} else {
		s.InfoLog("remotelookup not available - HasRouting returned false", "username", s.username)
	}

	// 2. Fallback to main DB to get account ID for affinity
	s.isRemoteLookupAccount = false

	// Skip database lookup if database is not available (proxy-only mode)
	if s.server.rdb == nil {
		return fmt.Errorf("database not available for account lookup in proxy-only mode")
	}

	// Use configured database query timeout instead of hardcoded value
	queryTimeout := s.server.rdb.GetQueryTimeout()
	dbCtx, dbCancel := context.WithTimeout(s.ctx, queryTimeout)
	defer dbCancel()

	// Use GetActiveAccountIDByAddressWithRetry which properly handles ErrUserNotFound
	// as a business logic error (not a circuit breaker failure)
	accountID, err := s.server.rdb.GetActiveAccountIDByAddressWithRetry(dbCtx, s.username)
	if err != nil {
		// Check if error is due to session context cancellation (server shutdown)
		// Note: Must check s.ctx.Err(), not just the query error, because the query context
		// can timeout (DeadlineExceeded) independently from server shutdown
		if s.ctx.Err() != nil {
			s.InfoLog("database lookup cancelled due to server shutdown")
			return server.ErrServerShuttingDown
		}

		// Check if user was not found (business logic error, not a system failure)
		if errors.Is(err, consts.ErrUserNotFound) {
			// IMPORTANT: Before permanently rejecting (550), check if backends are healthy.
			// If all backends are down, we can't verify if user exists on backends, so return tempfail.
			// This prevents wrongly bouncing messages when:
			//  - Proxy has a separate/lagging database instance
			//  - User exists on backends but not on proxy's database
			//  - Backends are temporarily unavailable
			if !s.server.connManager.HasHealthyPoolBackends() {
				s.WarnLog("user not found in proxy database, but all backends unhealthy - returning tempfail to allow retry",
					"address", s.username)
				return server.ErrUserNotFoundTempFail
			}

			// Cache negative result (user not found)
			// We reached here so user is not in remotelookup (if enabled) AND not in DB.
			s.server.lookupCache.Set(s.server.name, originalAddress, &lookupcache.CacheEntry{
				Result:     lookupcache.AuthUserNotFound,
				IsNegative: true,
			})

			// Single consolidated log for lookup failure
			duration := time.Since(lookupStart)
			s.InfoLog("account lookup failed",
				"address", s.username,
				"reason", "user_not_found",
				"cached", false,
				"method", "main_db",
				"negative_cache_skipped", false,
				"duration", fmt.Sprintf("%.3fs", duration.Seconds()))

			return server.ErrUserNotFound
		}

		// Other database errors (timeouts, connection failures, etc.)
		s.WarnLog("database lookup error", "address", s.username, "error", err)
		return fmt.Errorf("database lookup error: %w", err)
	}

	s.accountID = accountID

	// Set routing info so connectToBackend doesn't call remotelookup again
	// Preserve global proxy settings (XCLIENT support) since we're not using remotelookup routing
	s.routingInfo = &proxy.UserRoutingInfo{
		AccountID:        s.accountID,
		RemoteUseXCLIENT: s.server.remoteUseXCLIENT,
	}

	// Cache positive result (routing info from DB)
	s.server.lookupCache.Set(s.server.name, originalAddress, &lookupcache.CacheEntry{
		AccountID:        s.accountID,
		RemoteUseXCLIENT: s.server.remoteUseXCLIENT,
		Result:           lookupcache.AuthSuccess,
		FromRemoteLookup: false,
	})

	// Single consolidated log for lookup success
	duration := time.Since(lookupStart)
	s.InfoLog("account lookup successful",
		"address", s.username,
		"cached", false,
		"method", "main_db",
		"duration", float64(int(duration.Seconds()*1000))/1000)

	return nil
}

// connectToBackend establishes a connection to the backend server.
func (s *Session) connectToBackend() error {
	routeResult, err := proxy.DetermineRoute(proxy.RouteParams{
		Ctx:                   s.ctx,
		Username:              s.originalAddress, // Use original address (not resolved address) for route/affinity consistency
		Protocol:              "lmtp",
		IsRemoteLookupAccount: s.isRemoteLookupAccount,
		RoutingInfo:           s.routingInfo,
		ConnManager:           s.server.connManager,
		EnableAffinity:        s.server.enableAffinity,
		ProxyName:             "LMTP Proxy",
	})
	if err != nil {
		s.DebugLog("Error determining route", "error", err)
	}

	// Update session routing info if it was fetched by DetermineRoute
	s.routingInfo = routeResult.RoutingInfo
	s.routingMethod = routeResult.RoutingMethod
	preferredAddr := routeResult.PreferredAddr
	isRemoteLookupRoute := routeResult.IsRemoteLookupRoute

	s.DebugLog("Routing", "method", routeResult.RoutingMethod, "preferred_addr", preferredAddr, "is_remotelookup", isRemoteLookupRoute)
	if s.routingInfo != nil {
		s.DebugLog("Routing info", "server", s.routingInfo.ServerAddress, "tls", s.routingInfo.RemoteTLS, "starttls", s.routingInfo.RemoteTLSUseStartTLS, "tls_verify", s.routingInfo.RemoteTLSVerify, "xclient", s.routingInfo.RemoteUseXCLIENT)
	}

	// 4. Connect using the determined address (or round-robin if empty)
	// Track which routing method was used for this connection.
	metrics.ProxyRoutingMethod.WithLabelValues("lmtp", routeResult.RoutingMethod).Inc()

	clientHost, clientPort := server.GetHostPortFromAddr(s.clientConn.RemoteAddr())
	serverHost, serverPort := server.GetHostPortFromAddr(s.clientConn.LocalAddr())
	backendConn, actualAddr, err := s.server.connManager.ConnectWithProxy(
		s.ctx,
		preferredAddr,
		clientHost, clientPort, serverHost, serverPort, s.routingInfo,
	)
	if err != nil {
		// Track backend connection failure
		metrics.ProxyBackendConnections.WithLabelValues("lmtp", "failure").Inc()
		return fmt.Errorf("failed to connect to backend: %w", err)
	}

	if isRemoteLookupRoute && actualAddr != preferredAddr {
		// The remotelookup route specified a server, but we connected to a different one.
		// This means the preferred server failed and the connection manager fell back.
		// For remotelookup routes, this is a hard failure.
		backendConn.Close()
		metrics.ProxyBackendConnections.WithLabelValues("lmtp", "failure").Inc()
		return fmt.Errorf("remotelookup route to %s failed, and fallback is disabled for remotelookup routes", preferredAddr)
	}

	// Track backend connection success
	metrics.ProxyBackendConnections.WithLabelValues("lmtp", "success").Inc()
	s.backendConn = backendConn
	s.serverAddr = actualAddr
	s.backendReader = bufio.NewReader(s.backendConn)
	s.backendWriter = bufio.NewWriter(s.backendConn)

	// Enable TCP keepalive on backend connection to detect dead connections
	// This helps detect network partitions and stale connections without waiting for read timeout
	if tcpConn, ok := backendConn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			s.DebugLog("Failed to enable TCP keepalive on backend", "error", err)
		} else if err := tcpConn.SetKeepAlivePeriod(2 * time.Minute); err != nil {
			s.DebugLog("Failed to set TCP keepalive period on backend", "error", err)
		}
	}

	// Record successful connection for future affinity
	// Auth-only remotelookup users (IsRemoteLookupAccount=true but ServerAddress="") should get affinity
	// Use s.originalAddress for affinity key to ensure stability across resolutions
	if s.server.enableAffinity && actualAddr != "" {
		proxy.UpdateAffinityAfterConnection(proxy.RouteParams{
			Username:              s.originalAddress,
			Protocol:              "lmtp",
			IsRemoteLookupAccount: s.isRemoteLookupAccount,
			RoutingInfo:           s.routingInfo, // Pass routing info so UpdateAffinity can check ServerAddress
			ConnManager:           s.server.connManager,
			EnableAffinity:        s.server.enableAffinity,
			ProxyName:             "LMTP Proxy",
		}, actualAddr, routeResult.RoutingMethod == "affinity")
	}

	// Read greeting from backend (bounded, with read deadline: a backend that
	// accepts TCP but never sends its greeting must not hang the session)
	greeting, err := s.readBackendLine()
	if err != nil {
		s.backendConn.Close()
		return fmt.Errorf("failed to read backend greeting: %w", err)
	}
	if !strings.HasPrefix(greeting, "220") {
		s.backendConn.Close()
		return fmt.Errorf("unexpected backend greeting: %q", strings.TrimSpace(greeting))
	}

	// Send LHLO to backend
	lhloCmd := fmt.Sprintf("LHLO %s\r\n", s.server.hostname)
	_, err = s.backendWriter.WriteString(lhloCmd)
	if err != nil {
		s.backendConn.Close()
		return fmt.Errorf("failed to send LHLO: %w", err)
	}
	s.backendWriter.Flush()

	// Read LHLO response (bounded lines and line count so a misbehaving backend
	// cannot keep us in this loop or grow memory without limit)
	for lines := 0; ; lines++ {
		if lines >= maxLHLOResponseLines {
			s.backendConn.Close()
			return fmt.Errorf("backend LHLO response exceeded %d lines", maxLHLOResponseLines)
		}
		response, err := s.readBackendLine()
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("failed to read LHLO response: %w", err)
		}

		s.DebugLog("Backend LHLO response", "response", strings.TrimRight(response, "\r"))

		// Check if this is the last line (no hyphen after status code)
		if len(response) >= 4 && response[3] != '-' {
			if !strings.HasPrefix(response, "250") {
				s.backendConn.Close()
				return fmt.Errorf("backend LHLO failed: %s", response)
			}
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

	// Set ServerName so tls.Client verifies the backend certificate hostname. Without it,
	// DNSName is empty and Go verifies only the chain (not the host), so remote_tls_verify=true
	// would still let any CA-valid cert MITM the proxy->backend leg. Derive it from the address
	// we actually connected to (the configured backend hostname; both tls.Config values here are
	// per-connection, safe to mutate).
	if tlsConfig != nil && tlsConfig.ServerName == "" {
		if host, _, splitErr := net.SplitHostPort(actualAddr); splitErr == nil && host != "" {
			tlsConfig.ServerName = host
		}
	}

	if shouldUseStartTLS && tlsConfig != nil {
		s.DebugLog("Negotiating StartTLS with backend", "backend", actualAddr, "insecure_skip_verify", tlsConfig.InsecureSkipVerify)

		// Send STARTTLS command
		_, err := s.backendWriter.WriteString("STARTTLS\r\n")
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("failed to send STARTTLS command: %w", err)
		}
		s.backendWriter.Flush()

		// Read STARTTLS response (bounded, with read deadline)
		response, err := s.readBackendLine()
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("failed to read STARTTLS response: %w", err)
		}

		if !strings.HasPrefix(strings.TrimSpace(response), "220") {
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

		s.DebugLog("StartTLS negotiation successful with backend", "backend", actualAddr)
		s.backendConn = tlsConn
		s.backendReader = bufio.NewReader(tlsConn)
		s.backendWriter = bufio.NewWriter(tlsConn)

		// After STARTTLS, we need to send LHLO again
		lhloCmd := fmt.Sprintf("LHLO %s\r\n", s.server.hostname)
		_, err = s.backendWriter.WriteString(lhloCmd)
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("failed to send LHLO after STARTTLS: %w", err)
		}
		s.backendWriter.Flush()

		// Read LHLO response again (bounded lines and line count)
		for lines := 0; ; lines++ {
			if lines >= maxLHLOResponseLines {
				s.backendConn.Close()
				return fmt.Errorf("backend LHLO response after STARTTLS exceeded %d lines", maxLHLOResponseLines)
			}
			response, err := s.readBackendLine()
			if err != nil {
				s.backendConn.Close()
				return fmt.Errorf("failed to read LHLO response after STARTTLS: %w", err)
			}

			s.DebugLog("Backend LHLO response after STARTTLS", "response", strings.TrimRight(response, "\r"))

			// Check if this is the last line
			if len(response) >= 4 && response[3] != '-' {
				if !strings.HasPrefix(response, "250") {
					s.backendConn.Close()
					return fmt.Errorf("backend LHLO after STARTTLS failed: %s", response)
				}
				break
			}
		}
	}

	// Send forwarding parameters via XCLIENT if enabled
	useXCLIENT := s.server.remoteUseXCLIENT
	// Override with routing-specific setting if available
	if s.routingInfo != nil {
		useXCLIENT = s.routingInfo.RemoteUseXCLIENT
	}
	// The proxy's role is to forward the original client's information if enabled.
	// It is the backend server's responsibility to verify if the connection
	// (from this proxy) is from a trusted IP before processing forwarded parameters.
	// The `isFromTrustedProxy()` check is for proxy-chaining, where a backend
	// needs to validate if the client connecting to it is another trusted proxy.
	if useXCLIENT {
		if err := s.sendForwardingParametersToBackend(s.backendWriter, s.backendReader); err != nil {
			s.WarnLog("Failed to send XCLIENT to backend - continuing without forwarding parameters", "backend", s.serverAddr, "error", err)
			// Continue without forwarding parameters rather than failing
			// Note: If XCLIENT is rejected, this may indicate backend is not configured
			// to accept XCLIENT from this proxy IP (check backend's trusted_networks)
		}
	}

	// Send MAIL FROM to backend
	if s.mailFromReceived {
		mailCmd := fmt.Sprintf("MAIL FROM:<%s>\r\n", s.sender)
		_, err = s.backendWriter.WriteString(mailCmd)
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("failed to send MAIL FROM: %w", err)
		}
		s.backendWriter.Flush()

		// Read MAIL FROM response (bounded, with read deadline)
		response, err := s.readBackendLine()
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("failed to read MAIL FROM response: %w", err)
		}

		if !strings.HasPrefix(response, "250") {
			s.backendConn.Close()
			return fmt.Errorf("backend MAIL FROM failed: %s", response)
		}

		s.DebugLog("Backend MAIL FROM accepted")
	}

	return nil
}

// backendResponseLineMax bounds a single backend response line during the
// handshake and per-command phases. RFC 5321 reply lines are far below this.
const backendResponseLineMax = 4096

// maxLHLOResponseLines bounds multiline LHLO responses so a misbehaving
// backend cannot keep the proxy in the reply loop forever.
const maxLHLOResponseLines = 64

// readBackendLine reads one bounded response line from the backend with a
// read deadline (the backend connect timeout). The deadline is cleared after
// the read so later phases (the relay loop manages its own deadlines) are
// unaffected. Without this, a backend that accepted the connection but then
// went silent kept the session goroutine blocked forever.
func (s *Session) readBackendLine() (string, error) {
	timeout := s.server.connManager.GetConnectTimeout()
	if timeout > 0 {
		if err := s.backendConn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return "", fmt.Errorf("failed to set backend read deadline: %w", err)
		}
		defer func() {
			if err := s.backendConn.SetReadDeadline(time.Time{}); err != nil {
				s.DebugLog("failed to clear backend read deadline", "error", err)
			}
		}()
	}
	return server.ReadBoundedLine(s.backendReader, backendResponseLineMax)
}

// invalidateLookupCache removes the cached routing entry for the originally
// submitted recipient address. The cache key must be the SUBMITTED address
// (s.originalAddress), not the resolved one (s.username), because that is the
// key handleRecipient used for Set.
func (s *Session) invalidateLookupCache(reason string) {
	if s.server.lookupCache == nil || s.originalAddress == "" {
		return
	}
	s.server.lookupCache.InvalidateUser(s.server.name, s.originalAddress)
	s.InfoLog("invalidated lookup cache entry", "reason", reason, "address", s.originalAddress, "backend", s.serverAddr)
}

// forwardRCPT sends the RCPT TO command to backend and handles response interception
func (s *Session) forwardRCPT(command string) {
	// Strip unsupported ESMTP parameters from RCPT TO before forwarding to backend
	// Most ESMTP extensions (especially DSN) are SMTP-specific and not supported by LMTP
	cleanedCommand := stripUnsupportedRCPTParameters(command)
	if cleanedCommand != command {
		s.DebugLog("Stripped unsupported ESMTP parameters from RCPT TO", "original", command, "cleaned", cleanedCommand)
	}

	// IMPORTANT: If remotelookup resolved the recipient to a different email (ActualEmail),
	// we must rewrite the RCPT TO command to use the resolved email, not the original.
	// This handles cases where remotelookup returns a token-based or aliased address.
	// However, we must preserve the detail part (e.g., +test) from the original address.
	backendCommand := cleanedCommand
	if s.username != s.toAddress.BaseAddress() {
		// Username was resolved to a different email - rewrite RCPT TO
		// Extract any ESMTP parameters from cleaned command (after the address)
		params := ""
		if idx := strings.Index(cleanedCommand, ">"); idx != -1 && idx+1 < len(cleanedCommand) {
			params = strings.TrimSpace(cleanedCommand[idx+1:])
		}

		// Reconstruct resolved email with detail if present
		var resolvedRecipient string
		if s.toAddress.Detail() != "" {
			// Preserve detail part from original address
			resolvedAddr, parseErr := server.NewAddress(s.username)
			if parseErr == nil {
				resolvedRecipient = fmt.Sprintf("%s+%s@%s", resolvedAddr.LocalPart(), s.toAddress.Detail(), resolvedAddr.Domain())
			} else {
				// Fallback: use resolved username as-is if parsing fails
				s.WarnLog("Failed to parse resolved username for detail preservation", "username", s.username, "error", parseErr)
				resolvedRecipient = s.username
			}
		} else {
			resolvedRecipient = s.username
		}

		// Reconstruct RCPT TO with resolved email (with detail if present)
		if params != "" {
			backendCommand = fmt.Sprintf("RCPT TO:<%s> %s", resolvedRecipient, params)
		} else {
			backendCommand = fmt.Sprintf("RCPT TO:<%s>", resolvedRecipient)
		}
		s.DebugLog("Rewrote RCPT TO for backend", "original_recipient", s.to, "resolved_recipient", resolvedRecipient, "backend_command", backendCommand)
	}

	// Send the RCPT TO command
	s.DebugLog("Sending RCPT TO to backend", "command", backendCommand)
	_, err := s.backendWriter.WriteString(backendCommand + "\r\n")
	if err != nil {
		s.DebugLog("Failed to send RCPT TO", "error", err)
		s.sendResponse("451 4.4.2 Backend error")
		// Connection issues should probably close the backend connection but let client decide next step
		s.backendConn.Close()
		s.backendConn = nil
		return
	}
	s.backendWriter.Flush()

	// Read the backend's response to RCPT TO (bounded, with read deadline)
	response, err := s.readBackendLine()
	if err != nil {
		s.DebugLog("Failed to read RCPT TO response", "error", err)
		s.sendResponse("451 4.4.2 Backend error")
		s.backendConn.Close()
		s.backendConn = nil
		return
	}
	s.DebugLog("Backend RCPT TO response", "response", strings.TrimSpace(response))

	// Check if backend rejected the recipient BEFORE forwarding to client
	trimmedResponse := strings.TrimSpace(response)
	if strings.HasPrefix(trimmedResponse, "5") {
		// Backend rejected with permanent error (5xx)
		// This should NOT happen if remotelookup/cache said the user exists on this backend
		// This indicates a data consistency problem between remotelookup and backend, not a legitimate user-not-found
		// Return 4xx (temporary failure) instead of forwarding 5xx so sender can retry
		// This gives operators time to fix the data inconsistency without causing message loss
		s.WarnLog("backend rejected recipient - data inconsistency detected, returning temporary failure",
			"backend", s.serverAddr,
			"method", s.routingMethod,
			"from", s.sender,
			"to", s.to,
			"backend_response", trimmedResponse,
			"returned_to_client", "451 4.3.0",
			"issue", "remotelookup returned this backend but backend rejected user - check data consistency")

		// Invalidate cache entry to force fresh lookup on next attempt.
		// This prevents repeated routing to the wrong backend. InvalidateUser
		// derives the key exactly like Get/Set did (submitted address), so the
		// key formats can never drift apart.
		s.invalidateLookupCache("backend rejected recipient")

		// Override the backend's 5xx response with our own 4xx to allow retry
		s.sendResponse("451 4.3.0 Backend configuration issue, please try again later")
		return
	} else if strings.HasPrefix(trimmedResponse, "4") {
		// Backend rejected with temporary error (4xx) - forward as-is
		s.InfoLog("backend temporarily rejected recipient", "backend", s.serverAddr, "method", s.routingMethod, "from", s.sender, "to", s.to, "response", trimmedResponse)
		s.clientWriter.WriteString(response)
		s.clientWriter.Flush()
		return
	}

	// Backend accepted (2xx) - forward response to client
	s.clientWriter.WriteString(response)
	s.clientWriter.Flush()

	// Log routing decision at INFO level with sender, recipient, and routing method
	s.InfoLog("routing to backend", "backend", s.serverAddr, "method", s.routingMethod, "from", s.sender, "to", s.to)
}

// enterPipeMode enters the data piping mode for transfer of message content.
func (s *Session) enterPipeMode() {
	if s.backendConn == nil {
		s.DebugLog("Backend connection not established, cannot enter pipe mode")
		return
	}

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
		// We use half-close (CloseWrite) to signal EOF to the backend while allowing the backend
		// to finish sending its response. This prevents "broken pipe" errors on QUIT.
		// The backend-to-client goroutine will fully close the connection when it's done reading.
		defer func() {
			// Try to half-close the connection (shutdown writes, keep reads open)
			// This works for both *net.TCPConn and *tls.Conn (Go 1.23+)
			if closeWriter, ok := s.backendConn.(interface{ CloseWrite() error }); ok {
				if err := closeWriter.CloseWrite(); err != nil {
					s.DebugLog("Failed to half-close backend connection", "error", err)
				}
			} else {
				// Fallback for connections that don't support half-close
				s.backendConn.Close()
			}
		}()
		s.proxyClientToBackend()
		s.DebugLog("Client-to-backend copy goroutine exiting")
	}()

	// Backend to client
	wg.Add(1)
	s.DebugLog("Starting backend-to-client copy goroutine")
	go func() {
		defer wg.Done()
		// If this copy returns, it means the backend has closed the connection or there was an error.
		// We close the client connection to unblock the client-to-backend copy operation.
		// The backend connection is NOT closed here — it is closed after wg.Wait() to avoid
		// racing with the client-to-backend goroutine's CloseWrite (which would cause "broken pipe"
		// on the storage backend). The full backendConn.Close() happens after both goroutines exit.
		defer func() {
			s.mu.Lock()
			if !s.gracefulShutdown {
				s.clientConn.Close()
			}
			s.mu.Unlock()
		}()
		var bytesOut int64
		var err error
		// Use the buffered reader from authentication phase to avoid losing buffered data
		if s.backendReader != nil {
			// Copy from buffered reader with deadline protection
			bytesOut, err = s.copyBufferedReaderToConn(s.clientConn, s.backendReader)
		} else {
			// Fallback to direct copy if no buffered reader (shouldn't happen in normal flow)
			bytesOut, err = server.CopyWithDeadline(s.ctx, s.clientConn, s.backendConn, "backend-to-client")
		}
		metrics.BytesThroughput.WithLabelValues("lmtp_proxy", "out").Add(float64(bytesOut))
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
	wg.Wait()
	// Full close of backend connection after both goroutines have exited.
	// This ensures the client-to-backend goroutine's CloseWrite() has time to signal
	// EOF to the backend before the connection is fully torn down, preventing
	// "broken pipe" errors on the storage backend.
	s.backendConn.Close()
	s.DebugLog("Copy goroutines finished - enterPipeMode() returning")
}

// proxyClientToBackend handles copying data from the client to the backend,
// applying an idle timeout between commands.
func (s *Session) proxyClientToBackend() {
	var totalBytesIn int64
	defer func() {
		// Record total bytes when the copy loop exits
		metrics.BytesThroughput.WithLabelValues("lmtp_proxy", "in").Add(float64(totalBytesIn))
	}()
	// Best-effort: never exit with forwarded-but-unflushed bytes in the writer.
	defer s.backendWriter.Flush()

	for {
		// Set a read deadline to prevent idle connections between commands.
		// Only when the next ReadSlice will actually hit the connection:
		// buffered data is served without blocking, and SetReadDeadline can
		// fail once the connection is torn down, which must not discard data
		// we already received from the client.
		if s.server.authIdleTimeout > 0 && s.clientReader.Buffered() == 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.authIdleTimeout)); err != nil {
				s.DebugLog("Failed to set read deadline", "error", err)
				return
			}
		}

		// ReadSlice (not ReadString) so an oversized line - e.g. a huge DATA
		// line without CRLF - is forwarded in buffer-sized chunks instead of
		// being accumulated in memory in its entirety.
		line, err := s.clientReader.ReadSlice('\n')
		if len(line) > 0 {
			// Forward the chunk to the backend
			n, werr := s.backendWriter.Write(line)
			totalBytesIn += int64(n)
			if werr != nil {
				if !isClosingError(werr) {
					s.DebugLog("Error writing to backend", "error", werr)
				}
				return
			}
			// Flush only once the client buffer is drained: this forwards
			// promptly but avoids one syscall per message line during DATA.
			if s.clientReader.Buffered() == 0 {
				if ferr := s.backendWriter.Flush(); ferr != nil {
					if !isClosingError(ferr) {
						s.DebugLog("Error flushing to backend", "error", ferr)
					}
					return
				}
			}
		}
		if err != nil {
			if err == bufio.ErrBufferFull {
				// Long line: the chunk was already forwarded above; keep reading.
				continue
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.DebugLog("Idle timeout - closing connection")
				return
			}
			if !isClosingError(err) {
				s.DebugLog("Error reading from client", "error", err)
			}
			return
		}
	}
}

// close closes all connections.
func (s *Session) close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Release connection limiter slot IMMEDIATELY (don't wait for goroutine to exit)
	if s.releaseConn != nil {
		s.releaseConn()
		s.releaseConn = nil // Prevent double-release
	}

	// Log disconnection at INFO level
	duration := time.Since(s.startTime).Round(time.Second)
	s.InfoLog("disconnected", "from", s.sender, "to", s.to, "duration", duration, "backend", s.serverAddr)

	// Unregister connection SYNCHRONOUSLY to prevent leak
	// CRITICAL: Must be synchronous to ensure unregister completes before session goroutine exits
	// Background goroutine was causing leaks when server shutdown or high load prevented execution
	if s.server.connTracker != nil {
		// Use a new background context for this final operation, as s.ctx is likely already cancelled.
		// UnregisterConnection is fast (in-memory only), so this won't block for long
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		// Unregister all account IDs that we actually registered during this LMTP session.
		// LMTP sessions can contain multiple RCPTs; s.accountID is overwritten per RCPT.
		// If we were to unregister only s.accountID (the *last* RCPT), we would leak the
		// original registered user forever.
		// IMPORTANT: only unregister what we actually registered. There is
		// deliberately NO fallback to s.accountID here: handleRecipient sets
		// s.accountID even when registerConnection was never called (e.g. the
		// backend connect failed) or was rejected by a limit. Unregistering an
		// account that was never registered decrements connection counts owned
		// by the user's OTHER live sessions, eroding per-user limits.
		accountIDs := make([]int64, 0, len(s.registeredAccountIDs))
		for id := range s.registeredAccountIDs {
			accountIDs = append(accountIDs, id)
		}

		for _, id := range accountIDs {
			// Use cached client address to avoid race with connection close
			if err := s.server.connTracker.UnregisterConnection(ctx, id, "LMTP", s.clientAddr); err != nil {
				// Connection tracking is non-critical monitoring data, so log but continue
				s.WarnLog("Failed to unregister connection", "error", err, "account_id", id)
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
	// registerConnection is an in-memory tracking operation, but we still bound it with a timeout.
	// In production we use the configured DB query timeout as a convenient knob.
	// In unit tests (or misconfiguration), s.server.rdb can be nil, so fall back safely.
	queryTimeout := 1 * time.Second
	if s.server != nil && s.server.rdb != nil {
		queryTimeout = s.server.rdb.GetQueryTimeout()
	}
	ctx, cancel := context.WithTimeout(s.ctx, queryTimeout)
	defer cancel()

	// Use cached client address (real IP) to match UnregisterConnection in close()
	if s.server.connTracker != nil {
		err := s.server.connTracker.RegisterConnection(ctx, s.accountID, s.username, "LMTP", s.clientAddr)
		if err != nil {
			return err
		}
		// Remember which account we registered so close() can unregister the same one,
		// even if s.accountID later changes due to additional RCPT TOs.
		if s.registeredAccountIDs == nil {
			s.registeredAccountIDs = make(map[int64]struct{})
		}
		s.registeredAccountIDs[s.accountID] = struct{}{}
		return nil
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
	const readDeadline = 5 * time.Minute // Detect stale backend connections during data transfer
	var totalBytes int64
	buf := make([]byte, 32*1024)
	nextDeadline := time.Now()

	// Get the underlying connection to set read deadline
	// The buffered reader wraps s.backendConn, but we need to access the conn itself
	var srcConn net.Conn
	if s.backendConn != nil {
		srcConn = s.backendConn
	}

	for {
		select {
		case <-s.ctx.Done():
			return totalBytes, s.ctx.Err()
		default:
		}

		// Set read deadline on backend connection to detect stale connections
		// This prevents goroutines from hanging indefinitely when backend stops responding
		// 5 minutes is generous for LMTP data transfer while still detecting hung connections
		if srcConn != nil {
			if err := srcConn.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
				s.DebugLog("Failed to set read deadline on backend", "error", err)
				// Continue anyway - this is not fatal
			}
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
			// Check if this is a read timeout error (stale backend connection)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.InfoLog("Backend read timeout during data transfer - connection appears stale", "duration", readDeadline)
				return totalBytes, fmt.Errorf("backend read timeout after %v: %w", readDeadline, err)
			}
			if err != io.EOF {
				return totalBytes, err
			}
			return totalBytes, nil
		}
	}
}

func isClosingError(err error) bool {
	return server.IsConnectionError(err)
}

// findParameter searches for a parameter with a given prefix in a list of arguments.
// It is case-insensitive and supports prefixes like "FROM:" or "TO:".
// It handles both "KEY:value" and "KEY: value" formats.
func findParameter(args []string, prefix string) (string, bool) {
	for i, arg := range args {
		// Handle "KEY: value" format where KEY: is a standalone token.
		if strings.ToUpper(arg) == prefix {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false // Found prefix but no value.
		}

		// Handle "KEY:value" format where it's a single token.
		if strings.HasPrefix(strings.ToUpper(arg), prefix) {
			return arg[len(prefix):], true
		}
	}
	return "", false
}
