package lmtpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
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
	username              string
	isRemoteLookupAccount bool
	routingInfo           *proxy.UserRoutingInfo
	accountID             int64
	serverAddr            string
	routingMethod         string
	clientAddr            string // Cached client address to avoid race with connection close
	releaseConn           func() // Connection limiter cleanup function
	mu                    sync.Mutex
	ctx                   context.Context
	cancel                context.CancelFunc
	startTime             time.Time
	proxyInfo             *server.ProxyProtocolInfo
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
		server:       s,
		clientConn:   conn,
		clientReader: bufio.NewReader(conn),
		clientWriter: bufio.NewWriter(conn),
		clientAddr:   clientAddr, // Use real client IP from PROXY protocol or connection
		ctx:          sessionCtx,
		cancel:       sessionCancel,
		startTime:    time.Now(),
		proxyInfo:    proxyInfo,
	}
}

// handleConnection handles the proxy session.
func (s *Session) handleConnection() {
	defer s.cancel()
	defer s.close()
	defer s.server.unregisterSession(s)
	defer metrics.ConnectionsCurrent.WithLabelValues("lmtp_proxy").Dec()

	// Log connection at INFO level
	s.InfoLog("connected")

	// Register this session for graceful shutdown tracking
	s.server.registerSession(s)

	// Perform TLS handshake if this is a TLS connection
	if tlsConn, ok := s.clientConn.(interface{ PerformHandshake() error }); ok {
		if err := tlsConn.PerformHandshake(); err != nil {
			s.DebugLog("TLS handshake failed", "error", err)
			return
		}
	}

	// Send greeting
	if err := s.sendGreeting(); err != nil {
		s.DebugLog("Failed to send greeting", "error", err)
		return
	}

	// Handle commands until we get RCPT TO
	for {
		// Set a read deadline for the client command to prevent idle connections.
		if s.server.authIdleTimeout > 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.authIdleTimeout)); err != nil {
				s.DebugLog("Failed to set read deadline", "error", err)
				return
			}
		}

		// Read command from client
		line, err := s.clientReader.ReadString('\n')
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
				s.sendResponse("501 5.5.4 Syntax error in RCPT command (missing TO)")
				continue
			}

			// Extract the recipient address (first part before any parameters)
			// toParam may contain the address and additional ESMTP parameters
			// Example: "<user@example.com> NOTIFY=NEVER ORCPT=rfc822;user@example.com"
			to := s.extractAddress(toParam)
			if to == "" {
				s.sendResponse("501 5.1.3 Bad recipient address syntax")
				continue
			}

			lookupStart := time.Now() // Start account lookup timing
			if err := s.handleRecipient(to, lookupStart); err != nil {
				s.DebugLog("Recipient rejected", "recipient", to, "error", err)
				// Check if error is due to server shutdown
				if errors.Is(err, server.ErrServerShuttingDown) {
					s.InfoLog("Recipient lookup failed due to server shutdown", "recipient", to)
					s.sendResponse("421 4.3.2 Service shutting down, please try again later")
					return
				}
				s.sendResponse("550 5.1.1 User unknown")
				continue
			}

			// Clear the read deadline before connecting to the backend and starting the proxy.
			// The proxy loop will manage its own deadlines.
			if s.server.authIdleTimeout > 0 {
				if err := s.clientConn.SetReadDeadline(time.Time{}); err != nil {
					s.DebugLog("Failed to clear read deadline", "error", err)
				}
			}
			// Now connect to backend
			if err := s.connectToBackend(); err != nil {
				s.InfoLog("backend connection failed", "recipient", s.to, "error", err)
				s.sendResponse("451 4.4.1 Backend connection failed")
				return
			}

			// Register connection
			if err := s.registerConnection(); err != nil {
				s.InfoLog("rejected connection registration", "error", err)
			}

			// Start proxying only if backend connection was successful
			if s.backendConn != nil {
				s.DebugLog("Starting proxy", "recipient", s.to, "account_id", s.accountID)
				s.startProxy(line)
			} else {
				s.WarnLog("Cannot start proxy - no backend connection", "recipient", s.to)
			}
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
		return fmt.Errorf("invalid address format: %w", err)
	}

	s.to = to
	s.username = address.BaseAddress()

	// Set username on client connection for timeout logging
	if soraConn, ok := s.clientConn.(interface{ SetUsername(string) }); ok {
		soraConn.SetUsername(s.username)
	}

	// Check cache first (for routing info - no password validation needed)
	if cached, found := s.server.lookupCache.Get(s.server.name, s.username); found {
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

			return fmt.Errorf("user not found")
		} else {
			// User found - use cached routing info
			metrics.CacheOperationsTotal.WithLabelValues("get", "hit").Inc()

			s.accountID = cached.AccountID
			s.isRemoteLookupAccount = cached.FromRemoteLookup
			s.routingInfo = &proxy.UserRoutingInfo{
				AccountID:              cached.AccountID,
				ServerAddress:          cached.ServerAddress,
				RemoteTLS:              cached.RemoteTLS,
				RemoteTLSUseStartTLS:   cached.RemoteTLSUseStartTLS,
				RemoteTLSVerify:        cached.RemoteTLSVerify,
				RemoteUseProxyProtocol: cached.RemoteUseProxyProtocol,
				RemoteUseXCLIENT:       cached.RemoteUseXCLIENT,
			}

			if cached.ActualEmail != "" {
				s.username = cached.ActualEmail
			}

			s.server.lookupCache.Refresh(s.server.name, s.username)

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

		routingInfo, lookupErr := s.server.connManager.LookupUserRoute(routingCtx, s.username)
		if lookupErr != nil {
			s.InfoLog("remotelookup failed", "username", s.username, "error", lookupErr, "cache", "miss")

			// Check if error is due to context cancellation (server shutdown)
			if errors.Is(lookupErr, server.ErrServerShuttingDown) {
				s.InfoLog("remotelookup cancelled due to server shutdown")
				metrics.RemoteLookupResult.WithLabelValues("lmtp", "shutdown").Inc()
				return server.ErrServerShuttingDown
			}

			// Only check fallback setting for transient errors (network, 5xx, circuit breaker)
			// User not found (404) always falls through to support partitioning scenarios
			if s.server.remotelookupConfig != nil && !s.server.remotelookupConfig.FallbackToDB {
				s.InfoLog("remotelookup transient error and fallback_to_db=false - rejecting recipient", "username", s.username)
				metrics.RemoteLookupResult.WithLabelValues("lmtp", "transient_error_rejected").Inc()
				return fmt.Errorf("remotelookup failed and fallback disabled: %w", lookupErr)
			}
			s.InfoLog("remotelookup transient error - fallback_to_db=true, falling back to main DB", "username", s.username)
			metrics.RemoteLookupResult.WithLabelValues("lmtp", "transient_error_fallback").Inc()
		} else if routingInfo != nil {
			// RemoteLookup succeeded - may or may not have ServerAddress
			// If no ServerAddress, backend selection will use consistent hash/round-robin
			metrics.RemoteLookupResult.WithLabelValues("lmtp", "success").Inc()
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
			// Cache key is s.username (BaseAddress of submitted recipient)
			// Store ActualEmail if remotelookup resolved to a different address
			s.server.lookupCache.Set(s.server.name, s.username, &lookupcache.CacheEntry{
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
			// User not found in remotelookup (404 or empty response).
			if s.server.remotelookupConfig != nil && s.server.remotelookupConfig.FallbackToDB {
				s.InfoLog("user not found in remotelookup, fallback enabled - attempting main DB", "username", s.username)
				metrics.RemoteLookupResult.WithLabelValues("lmtp", "user_not_found_fallback").Inc()
				// Fallthrough to main DB
			} else {
				s.InfoLog("user not found in remotelookup, fallback disabled - rejecting", "username", s.username)
				metrics.RemoteLookupResult.WithLabelValues("lmtp", "user_not_found_rejected").Inc()
				return fmt.Errorf("user not found in remotelookup")
			}
		}
	} else {
		s.InfoLog("remotelookup not available - HasRouting returned false", "username", s.username)
	}

	// 2. Fallback to main DB to get account ID for affinity
	s.isRemoteLookupAccount = false
	// Use configured database query timeout instead of hardcoded value
	queryTimeout := s.server.rdb.GetQueryTimeout()
	dbCtx, dbCancel := context.WithTimeout(s.ctx, queryTimeout)
	defer dbCancel()

	row := s.server.rdb.QueryRowWithRetry(dbCtx, "SELECT c.account_id FROM credentials c JOIN accounts a ON c.account_id = a.id WHERE c.address = $1 AND a.deleted_at IS NULL", s.username)
	if err := row.Scan(&s.accountID); err != nil {
		// Check if error is due to context cancellation (server shutdown)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			s.InfoLog("database lookup cancelled due to server shutdown")
			return server.ErrServerShuttingDown
		}

		// Cache negative result (user not found)
		s.server.lookupCache.Set(s.server.name, s.username, &lookupcache.CacheEntry{
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
			"duration", fmt.Sprintf("%.3fs", duration.Seconds()))

		return fmt.Errorf("user not found in main database: %w", err)
	}

	// Set routing info so connectToBackend doesn't call remotelookup again
	// Preserve global proxy settings (XCLIENT support) since we're not using remotelookup routing
	s.routingInfo = &proxy.UserRoutingInfo{
		AccountID:        s.accountID,
		RemoteUseXCLIENT: s.server.remoteUseXCLIENT,
	}

	// Cache positive result (routing info from DB)
	s.server.lookupCache.Set(s.server.name, s.username, &lookupcache.CacheEntry{
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
		Username:              s.username,
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

	// Record successful connection for future affinity
	// Auth-only remotelookup users (IsRemoteLookupAccount=true but ServerAddress="") should get affinity
	if s.server.enableAffinity && actualAddr != "" {
		proxy.UpdateAffinityAfterConnection(proxy.RouteParams{
			Username:              s.username,
			Protocol:              "lmtp",
			IsRemoteLookupAccount: s.isRemoteLookupAccount,
			RoutingInfo:           s.routingInfo, // Pass routing info so UpdateAffinity can check ServerAddress
			ConnManager:           s.server.connManager,
			EnableAffinity:        s.server.enableAffinity,
			ProxyName:             "LMTP Proxy",
		}, actualAddr, routeResult.RoutingMethod == "affinity")
	}

	// Read greeting from backend
	_, err = s.backendReader.ReadString('\n')
	if err != nil {
		s.backendConn.Close()
		return fmt.Errorf("failed to read backend greeting: %w", err)
	}

	// Send LHLO to backend
	lhloCmd := fmt.Sprintf("LHLO %s\r\n", s.server.hostname)
	_, err = s.backendWriter.WriteString(lhloCmd)
	if err != nil {
		s.backendConn.Close()
		return fmt.Errorf("failed to send LHLO: %w", err)
	}
	s.backendWriter.Flush()

	// Read LHLO response
	for {
		response, err := s.backendReader.ReadString('\n')
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

	if shouldUseStartTLS && tlsConfig != nil {
		s.DebugLog("Negotiating StartTLS with backend", "backend", actualAddr, "insecure_skip_verify", tlsConfig.InsecureSkipVerify)

		// Send STARTTLS command
		_, err := s.backendWriter.WriteString("STARTTLS\r\n")
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("failed to send STARTTLS command: %w", err)
		}
		s.backendWriter.Flush()

		// Read STARTTLS response
		response, err := s.backendReader.ReadString('\n')
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

		// Read LHLO response again
		for {
			response, err := s.backendReader.ReadString('\n')
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
			s.DebugLog("Failed to send forwarding parameters", "error", err)
			// Continue without forwarding parameters rather than failing
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

		// Read MAIL FROM response
		response, err := s.backendReader.ReadString('\n')
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

// startProxy starts bidirectional proxying between client and backend.
// initialCommand is the RCPT TO command that triggered the proxy.
func (s *Session) startProxy(initialCommand string) {
	if s.backendConn == nil {
		s.DebugLog("Backend connection not established")
		s.sendResponse("451 4.4.2 Backend connection not available")
		return
	}

	s.DebugLog("startProxy() called")

	// First, send the RCPT TO command that triggered proxying
	_, err := s.backendWriter.WriteString(initialCommand + "\r\n")
	if err != nil {
		s.DebugLog("Failed to send initial RCPT TO", "error", err)
		s.sendResponse("451 4.4.2 Backend error")
		return
	}
	s.backendWriter.Flush()

	// Read and forward the response
	response, err := s.backendReader.ReadString('\n')
	if err != nil {
		s.DebugLog("Failed to read RCPT TO response", "error", err)
		s.sendResponse("451 4.4.2 Backend error")
		return
	}
	s.clientWriter.WriteString(response)
	s.clientWriter.Flush()

	// Log routing decision at INFO level with sender, recipient, and routing method
	s.InfoLog("routing to backend", "backend", s.serverAddr, "method", s.routingMethod, "sender", s.sender, "recipient", s.to)

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
		defer s.backendConn.Close()
		s.proxyClientToBackend()
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
	s.DebugLog("Copy goroutines finished - startProxy() returning")
}

// proxyClientToBackend handles copying data from the client to the backend,
// applying an idle timeout between commands.
func (s *Session) proxyClientToBackend() {
	var totalBytesIn int64
	defer func() {
		// Record total bytes when the copy loop exits
		metrics.BytesThroughput.WithLabelValues("lmtp_proxy", "in").Add(float64(totalBytesIn))
	}()

	for {
		// Set a read deadline to prevent idle connections between commands.
		if s.server.authIdleTimeout > 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.authIdleTimeout)); err != nil {
				s.DebugLog("Failed to set read deadline", "error", err)
				return
			}
		}

		line, err := s.clientReader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.DebugLog("Idle timeout - closing connection")
				return
			}
			if !isClosingError(err) {
				s.DebugLog("Error reading from client", "error", err)
			}
			return
		}

		// Forward the command to backend
		n, err := s.backendWriter.WriteString(line)
		totalBytesIn += int64(n)
		if err != nil {
			if !isClosingError(err) {
				s.DebugLog("Error writing to backend", "error", err)
			}
			return
		}
		if err := s.backendWriter.Flush(); err != nil {
			if !isClosingError(err) {
				s.DebugLog("Error flushing to backend", "error", err)
			}
			return
		}

		// If this was a DATA command, switch to raw data proxying for the message body.
		cmd, _, _, _ := server.ParseLine(strings.TrimSpace(line), false)
		if cmd == "DATA" {
			// The backend's "354" response will be handled by the other goroutine.
			// We must now proxy the message body until ".\r\n".
			// The idle timeout is suspended during active data transfer.
			if s.server.authIdleTimeout > 0 {
				if err := s.clientConn.SetReadDeadline(time.Time{}); err != nil {
					s.DebugLog("Failed to clear read deadline for DATA transfer", "error", err)
				}
			}

			// Use a DotReader to correctly handle the message body, including dot-stuffing.
			tp := textproto.NewReader(s.clientReader)
			dr := tp.DotReader()

			// Copy the message body directly.
			bytesCopied, err := io.Copy(s.backendWriter, dr)
			totalBytesIn += bytesCopied
			if err != nil {
				s.DebugLog("Error proxying DATA content", "error", err)
				return
			}
			if err := s.backendWriter.Flush(); err != nil {
				s.DebugLog("Error flushing after DATA content", "error", err)
				return
			}
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
	s.InfoLog("disconnected", "duration", duration, "backend", s.serverAddr)

	// Unregister connection SYNCHRONOUSLY to prevent leak
	// CRITICAL: Must be synchronous to ensure unregister completes before session goroutine exits
	// Background goroutine was causing leaks when server shutdown or high load prevented execution
	if s.accountID > 0 && s.server.connTracker != nil {
		// Use a new background context for this final operation, as s.ctx is likely already cancelled.
		// UnregisterConnection is fast (in-memory only), so this won't block for long
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		// Use cached client address to avoid race with connection close
		if err := s.server.connTracker.UnregisterConnection(ctx, s.accountID, "LMTP", s.clientAddr); err != nil {
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
	queryTimeout := s.server.rdb.GetQueryTimeout()
	ctx, cancel := context.WithTimeout(s.ctx, queryTimeout)
	defer cancel()

	clientAddr := server.GetAddrString(s.clientConn.RemoteAddr())

	if s.server.connTracker != nil {
		return s.server.connTracker.RegisterConnection(ctx, s.accountID, s.username, "LMTP", clientAddr)
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
