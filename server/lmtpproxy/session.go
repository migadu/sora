package lmtpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// Session represents an LMTP proxy session.
type Session struct {
	server             *Server
	clientConn         net.Conn
	backendConn        net.Conn
	backendReader      *bufio.Reader
	backendWriter      *bufio.Writer
	clientReader       *bufio.Reader
	clientWriter       *bufio.Writer
	sender             string
	mailFromReceived   bool
	to                 string
	username           string
	isPrelookupAccount bool
	routingInfo        *proxy.UserRoutingInfo
	accountID          int64
	serverAddr         string
	mu                 sync.Mutex
	ctx                context.Context
	cancel             context.CancelFunc
}

// newSession creates a new LMTP proxy session.
func newSession(server *Server, conn net.Conn) *Session {
	sessionCtx, sessionCancel := context.WithCancel(server.ctx)
	return &Session{
		server:       server,
		clientConn:   conn,
		clientReader: bufio.NewReader(conn),
		clientWriter: bufio.NewWriter(conn),
		ctx:          sessionCtx,
		cancel:       sessionCancel,
	}
}

// handleConnection handles the proxy session.
func (s *Session) handleConnection() {
	defer s.cancel()
	defer s.close()
	defer metrics.ConnectionsCurrent.WithLabelValues("lmtp_proxy").Dec()

	clientAddr := s.clientConn.RemoteAddr().String()
	log.Printf("LMTP Proxy [%s] New connection from %s", s.server.name, clientAddr)

	// Perform TLS handshake if this is a TLS connection
	if tlsConn, ok := s.clientConn.(interface{ PerformHandshake() error }); ok {
		if err := tlsConn.PerformHandshake(); err != nil {
			log.Printf("LMTP Proxy [%s] TLS handshake failed for %s: %v", s.server.name, clientAddr, err)
			return
		}
	}

	// Send greeting
	if err := s.sendGreeting(); err != nil {
		log.Printf("LMTP Proxy [%s] Failed to send greeting to %s: %v", s.server.name, clientAddr, err)
		return
	}

	// Handle commands until we get RCPT TO
	for {
		// Set a read deadline for the client command to prevent idle connections.
		if s.server.sessionTimeout > 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.sessionTimeout)); err != nil {
				log.Printf("LMTP Proxy [%s] Failed to set read deadline for %s: %v", s.server.name, clientAddr, err)
				return
			}
		}

		// Read command from client
		line, err := s.clientReader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("LMTP Proxy [%s] Client %s timed out waiting for command", s.server.name, clientAddr)
				s.sendResponse("421 4.4.2 Idle timeout, closing connection")
				return
			}
			if !isClosingError(err) {
				log.Printf("LMTP Proxy [%s] Error reading from client %s: %v", s.server.name, clientAddr, err)
			}
			return
		}

		line = strings.TrimRight(line, "\r\n")
		log.Printf("LMTP Proxy [%s] Client %s: %s", s.server.name, clientAddr, line)

		// Log client command if debug is enabled
		s.Log("C: %s\r\n", line)

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
			to := s.extractAddress(toParam)
			if to == "" {
				s.sendResponse("501 5.1.3 Bad recipient address syntax")
				continue
			}

			if err := s.handleRecipient(to); err != nil {
				log.Printf("LMTP Proxy [%s] Recipient %s rejected: %v", s.server.name, to, err)
				s.sendResponse("550 5.1.1 User unknown")
				continue
			}

			// Clear the read deadline before connecting to the backend and starting the proxy.
			// The proxy loop will manage its own deadlines.
			if s.server.sessionTimeout > 0 {
				if err := s.clientConn.SetReadDeadline(time.Time{}); err != nil {
					log.Printf("LMTP Proxy [%s] Warning: failed to clear read deadline for %s: %v", s.server.name, clientAddr, err)
				}
			}
			// Now connect to backend
			if err := s.connectToBackend(); err != nil {
				log.Printf("LMTP Proxy [%s] Failed to connect to backend for %s: %v", s.server.name, s.username, err)
				s.sendResponse("451 4.4.1 Backend connection failed")
				return
			}

			// Register connection
			if err := s.registerConnection(); err != nil {
				log.Printf("LMTP Proxy [%s] Failed to register connection for %s: %v", s.server.name, s.username, err)
			}

			// Start proxying only if backend connection was successful
			if s.backendConn != nil {
				log.Printf("LMTP Proxy [%s] Starting proxy for recipient %s (account ID: %d)", s.server.name, s.to, s.accountID)
				s.startProxy(line)
			} else {
				log.Printf("LMTP Proxy [%s] Cannot start proxy for recipient %s: no backend connection", s.server.name, s.to)
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
				log.Printf("LMTP Proxy [%s] Failed to send STARTTLS response: %v", s.server.name, err)
				return
			}

			// Load TLS config
			cert, err := tls.LoadX509KeyPair(s.server.tlsCertFile, s.server.tlsKeyFile)
			if err != nil {
				log.Printf("LMTP Proxy [%s] Failed to load TLS certificate: %v", s.server.name, err)
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
				log.Printf("LMTP Proxy [%s] TLS handshake failed: %v", s.server.name, err)
				return
			}

			// Update session with TLS connection
			s.clientConn = tlsConn
			s.clientReader = bufio.NewReader(tlsConn)
			s.clientWriter = bufio.NewWriter(tlsConn)

			log.Printf("LMTP Proxy [%s] STARTTLS negotiation successful for %s", s.server.name, clientAddr)

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
func (s *Session) Log(format string, args ...interface{}) {
	if s.server.debugWriter != nil {
		message := fmt.Sprintf(format, args...)
		s.server.debugWriter.Write([]byte(message))
	}
}

// extractAddress extracts email address from MAIL FROM or RCPT TO parameter.
func (s *Session) extractAddress(param string) string {
	// The parameter value might be quoted, so unquote it first.
	param = server.UnquoteString(strings.TrimSpace(param))

	if len(param) < 2 {
		return ""
	}

	// Handle <address> format, which is the most common.
	if param[0] == '<' && param[len(param)-1] == '>' {
		return param[1 : len(param)-1]
	}

	// Handle <address> with additional parameters
	if idx := strings.Index(param, ">"); idx > 0 && param[0] == '<' {
		return param[1:idx]
	}

	// Some clients might not use angle brackets
	if idx := strings.Index(param, " "); idx > 0 {
		return param[:idx]
	}

	return param
}

// handleRecipient looks up the recipient, determines routing, and sets session state.
func (s *Session) handleRecipient(to string) error {
	address, err := server.NewAddress(to)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	s.to = to
	s.username = address.BaseAddress()

	// 1. Try prelookup first
	if s.server.connManager.HasRouting() {
		routingCtx, routingCancel := context.WithTimeout(s.ctx, 5*time.Second)
		defer routingCancel()

		routingInfo, lookupErr := s.server.connManager.LookupUserRoute(routingCtx, s.username)
		if lookupErr != nil {
			log.Printf("LMTP Proxy [%s] Prelookup for %s failed: %v. Falling back to main DB for affinity check.", s.server.name, s.username, lookupErr)
		} else if routingInfo != nil && routingInfo.ServerAddress != "" {
			log.Printf("LMTP Proxy [%s] Routing %s to %s via prelookup", s.server.name, s.username, routingInfo.ServerAddress)
			s.routingInfo = routingInfo
			s.isPrelookupAccount = true
			s.accountID = routingInfo.AccountID // May be 0, that's fine
			return nil
		}
	}

	// 2. Fallback to main DB to get account ID for affinity
	s.isPrelookupAccount = false
	dbCtx, dbCancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer dbCancel()

	row := s.server.rdb.QueryRowWithRetry(dbCtx, "SELECT c.account_id FROM credentials c JOIN accounts a ON c.account_id = a.id WHERE c.address = $1 AND a.deleted_at IS NULL", s.username)
	if err := row.Scan(&s.accountID); err != nil {
		return fmt.Errorf("user not found in main database: %w", err)
	}
	return nil
}

// connectToBackend establishes a connection to the backend server.
func (s *Session) connectToBackend() error {
	routeResult, err := proxy.DetermineRoute(proxy.RouteParams{
		Ctx:                s.ctx,
		Username:           s.username,
		Protocol:           "lmtp",
		IsPrelookupAccount: s.isPrelookupAccount,
		RoutingInfo:        s.routingInfo,
		ConnManager:        s.server.connManager,
		EnableAffinity:     s.server.enableAffinity,
		ProxyName:          "LMTP Proxy",
	})
	if err != nil {
		log.Printf("LMTP Proxy [%s] Error determining route for %s: %v", s.server.name, s.username, err)
	}

	// Update session routing info if it was fetched by DetermineRoute
	s.routingInfo = routeResult.RoutingInfo
	preferredAddr := routeResult.PreferredAddr
	isPrelookupRoute := routeResult.IsPrelookupRoute

	if s.server.debugWriter != nil {
		log.Printf("LMTP Proxy [%s] [DEBUG] Routing for %s: method=%s, preferredAddr=%s, isPrelookup=%t",
			s.server.name, s.username, routeResult.RoutingMethod, preferredAddr, isPrelookupRoute)
		if s.routingInfo != nil {
			log.Printf("LMTP Proxy [%s] [DEBUG] Routing info: server=%s, TLS=%t, StartTLS=%t, TLSVerify=%t, XCLIENT=%t",
				s.server.name, s.routingInfo.ServerAddress, s.routingInfo.RemoteTLS, s.routingInfo.RemoteTLSUseStartTLS,
				s.routingInfo.RemoteTLSVerify, s.routingInfo.RemoteUseXCLIENT)
		}
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

	if isPrelookupRoute && actualAddr != preferredAddr {
		// The prelookup route specified a server, but we connected to a different one.
		// This means the preferred server failed and the connection manager fell back.
		// For prelookup routes, this is a hard failure.
		backendConn.Close()
		metrics.ProxyBackendConnections.WithLabelValues("lmtp", "failure").Inc()
		return fmt.Errorf("prelookup route to %s failed, and fallback is disabled for prelookup routes", preferredAddr)
	}

	// Track backend connection success
	metrics.ProxyBackendConnections.WithLabelValues("lmtp", "success").Inc()
	s.backendConn = backendConn
	s.serverAddr = actualAddr
	s.backendReader = bufio.NewReader(s.backendConn)
	s.backendWriter = bufio.NewWriter(s.backendConn)

	// Record successful connection for future affinity
	if s.server.enableAffinity && !s.isPrelookupAccount && actualAddr != "" {
		proxy.UpdateAffinityAfterConnection(proxy.RouteParams{
			Username:           s.username,
			Protocol:           "lmtp",
			IsPrelookupAccount: s.isPrelookupAccount,
			ConnManager:        s.server.connManager,
			EnableAffinity:     s.server.enableAffinity,
			ProxyName:          "LMTP Proxy",
		}, actualAddr, routeResult.RoutingMethod == "affinity")
	}

	// Read greeting from backend
	greeting, err := s.backendReader.ReadString('\n')
	if err != nil {
		s.backendConn.Close()
		return fmt.Errorf("failed to read backend greeting: %w", err)
	}

	if s.server.debugWriter != nil {
		log.Printf("LMTP Proxy [%s] Backend greeting: %s", s.server.name, strings.TrimRight(greeting, "\r"))
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

		if s.server.debugWriter != nil {
			log.Printf("LMTP Proxy [%s] Backend LHLO response: %s", s.server.name, strings.TrimRight(response, "\r"))
		}

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
	// This happens when prelookup (or global config) specifies remote_tls_use_starttls
	shouldUseStartTLS := false
	var tlsConfig *tls.Config

	if s.routingInfo != nil && s.routingInfo.RemoteTLSUseStartTLS {
		// Prelookup routing specified StartTLS
		shouldUseStartTLS = true
		tlsConfig = &tls.Config{
			InsecureSkipVerify: !s.routingInfo.RemoteTLSVerify,
		}
		log.Printf("LMTP Proxy [%s] Using prelookup StartTLS settings for backend: remoteTLSVerify=%t",
			s.server.name, s.routingInfo.RemoteTLSVerify)
	} else if s.server.connManager.IsRemoteStartTLS() {
		// Global proxy config specified StartTLS
		shouldUseStartTLS = true
		tlsConfig = s.server.connManager.GetTLSConfig()
		log.Printf("LMTP Proxy [%s] Using global StartTLS settings for backend", s.server.name)
	}

	if shouldUseStartTLS && tlsConfig != nil {
		if s.server.debugWriter != nil {
			log.Printf("LMTP Proxy [%s] [DEBUG] Negotiating StartTLS with backend %s (InsecureSkipVerify=%t)",
				s.server.name, actualAddr, tlsConfig.InsecureSkipVerify)
		} else {
			log.Printf("LMTP Proxy [%s] Negotiating StartTLS with backend %s", s.server.name, actualAddr)
		}

		// Send STARTTLS command
		_, err := s.backendWriter.WriteString("STARTTLS\r\n")
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("failed to send STARTTLS command: %w", err)
		}
		s.backendWriter.Flush()

		if s.server.debugWriter != nil {
			log.Printf("LMTP Proxy [%s] [DEBUG] Sent STARTTLS command to backend", s.server.name)
		}

		// Read STARTTLS response
		response, err := s.backendReader.ReadString('\n')
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("failed to read STARTTLS response: %w", err)
		}

		if s.server.debugWriter != nil {
			log.Printf("LMTP Proxy [%s] [DEBUG] Backend STARTTLS response: %s", s.server.name, strings.TrimSpace(response))
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

		log.Printf("LMTP Proxy [%s] StartTLS negotiation successful with backend %s", s.server.name, actualAddr)
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

			if s.server.debugWriter != nil {
				log.Printf("LMTP Proxy [%s] Backend LHLO response after STARTTLS: %s", s.server.name, strings.TrimRight(response, "\r"))
			}

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
			log.Printf("LMTP Proxy [%s] Failed to send forwarding parameters for %s: %v", s.server.name, s.username, err)
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

		log.Printf("LMTP Proxy [%s] Backend MAIL FROM accepted", s.server.name)
	}

	return nil
}

// startProxy starts bidirectional proxying between client and backend.
// initialCommand is the RCPT TO command that triggered the proxy.
func (s *Session) startProxy(initialCommand string) {
	if s.backendConn == nil {
		log.Printf("LMTP Proxy [%s] backend connection not established for %s", s.server.name, s.username)
		s.sendResponse("451 4.4.2 Backend connection not available")
		return
	}

	// First, send the RCPT TO command that triggered proxying
	_, err := s.backendWriter.WriteString(initialCommand + "\r\n")
	if err != nil {
		log.Printf("LMTP Proxy [%s] Failed to send initial RCPT TO: %v", s.server.name, err)
		s.sendResponse("451 4.4.2 Backend error")
		return
	}
	s.backendWriter.Flush()

	// Read and forward the response
	response, err := s.backendReader.ReadString('\n')
	if err != nil {
		log.Printf("LMTP Proxy [%s] Failed to read RCPT TO response: %v", s.server.name, err)
		s.sendResponse("451 4.4.2 Backend error")
		return
	}
	s.clientWriter.WriteString(response)
	s.clientWriter.Flush()

	var wg sync.WaitGroup

	// Start activity updater
	activityCtx, activityCancel := context.WithCancel(s.ctx)
	defer activityCancel()
	go s.updateActivityPeriodically(activityCtx)

	// Client to backend
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer s.backendConn.Close()
		s.proxyClientToBackend()
	}()

	// Backend to client
	wg.Add(1)
	go func() {
		defer wg.Done()
		// If this copy returns, it means the backend has closed the connection or there was an error.
		// We must close the client connection to unblock the other copy operation.
		defer s.clientConn.Close()
		bytesOut, err := io.Copy(s.clientConn, s.backendConn)
		metrics.BytesThroughput.WithLabelValues("lmtp_proxy", "out").Add(float64(bytesOut))
		if err != nil && !isClosingError(err) {
			log.Printf("LMTP Proxy [%s] Error copying from backend to client: %v", s.server.name, err)
		}
	}()

	go func() {
		<-s.ctx.Done()
		s.clientConn.Close()
		s.backendConn.Close()
	}()

	wg.Wait()
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
		if s.server.sessionTimeout > 0 {
			if err := s.clientConn.SetReadDeadline(time.Now().Add(s.server.sessionTimeout)); err != nil {
				log.Printf("LMTP Proxy [%s] Failed to set read deadline for %s: %v", s.server.name, s.username, err)
				return
			}
		}

		line, err := s.clientReader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("LMTP Proxy [%s] Idle timeout for user %s, closing connection.", s.server.name, s.username)
				return
			}
			if !isClosingError(err) {
				log.Printf("LMTP Proxy [%s] Error reading from client for %s: %v", s.server.name, s.username, err)
			}
			return
		}

		// Forward the command to backend
		n, err := s.backendWriter.WriteString(line)
		totalBytesIn += int64(n)
		if err != nil {
			if !isClosingError(err) {
				log.Printf("LMTP Proxy [%s] Error writing to backend for %s: %v", s.server.name, s.username, err)
			}
			return
		}
		if err := s.backendWriter.Flush(); err != nil {
			if !isClosingError(err) {
				log.Printf("LMTP Proxy [%s] Error flushing to backend for %s: %v", s.server.name, s.username, err)
			}
			return
		}

		// If this was a DATA command, switch to raw data proxying for the message body.
		cmd, _, _, _ := server.ParseLine(strings.TrimSpace(line), false)
		if cmd == "DATA" {
			// The backend's "354" response will be handled by the other goroutine.
			// We must now proxy the message body until ".\r\n".
			// The idle timeout is suspended during active data transfer.
			if s.server.sessionTimeout > 0 {
				if err := s.clientConn.SetReadDeadline(time.Time{}); err != nil {
					log.Printf("LMTP Proxy [%s] Warning: failed to clear read deadline for DATA transfer: %v", s.server.name, err)
				}
			}

			// Use a DotReader to correctly handle the message body, including dot-stuffing.
			tp := textproto.NewReader(s.clientReader)
			dr := tp.DotReader()

			// Copy the message body directly.
			bytesCopied, err := io.Copy(s.backendWriter, dr)
			totalBytesIn += bytesCopied
			if err != nil {
				log.Printf("LMTP Proxy [%s] Error proxying DATA content for %s: %v", s.server.name, s.username, err)
				return
			}
			if err := s.backendWriter.Flush(); err != nil {
				log.Printf("LMTP Proxy [%s] Error flushing after DATA content for %s: %v", s.server.name, s.username, err)
				return
			}
		}
	}
}

// close closes all connections.
func (s *Session) close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Unregister connection
	if s.accountID > 0 {
		// Use a new background context for this final operation, as s.ctx is likely already cancelled.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		clientAddr := s.clientConn.RemoteAddr().String()

		if s.server.connTracker != nil && s.server.connTracker.IsEnabled() {
			if err := s.server.connTracker.UnregisterConnection(ctx, s.accountID, "LMTP", clientAddr); err != nil {
				log.Printf("LMTP Proxy [%s] Failed to unregister connection for %s: %v", s.server.name, s.username, err)
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
		return s.server.connTracker.RegisterConnection(ctx, s.accountID, "LMTP", clientAddr, s.serverAddr)
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

		shouldTerminate, err := s.server.connTracker.CheckTermination(checkCtx, s.accountID, "LMTP", clientAddr)
		if err != nil {
			log.Printf("LMTP Proxy [%s] Failed to check termination for %s: %v", s.server.name, s.username, err)
			return false
		}
		if shouldTerminate {
			log.Printf("LMTP Proxy [%s] Connection kicked - disconnecting user: %s (client: %s, backend: %s)", s.server.name, s.username, clientAddr, s.serverAddr)
			s.clientConn.Close()
			s.backendConn.Close()
			return true
		}
		return false
	}

	for {
		select {
		case <-kickChan:
			log.Printf("LMTP Proxy [%s] Received kick notification for %s", s.server.name, s.username)
			if checkAndTerminate() {
				return
			}
		case <-activityTicker.C:
			updateCtx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
			if err := s.server.connTracker.UpdateActivity(updateCtx, s.accountID, "LMTP", clientAddr); err != nil {
				log.Printf("LMTP Proxy [%s] Failed to update activity for %s: %v", s.server.name, s.username, err)
			}
			cancel()
		case <-ctx.Done():
			return
		}
	}
}

func isClosingError(err error) bool {
	if err == io.EOF || errors.Is(err, net.ErrClosed) {
		return true
	}
	// Check for the specific string net.OpError produces on a closed connection
	return strings.Contains(err.Error(), "use of closed network connection")
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
