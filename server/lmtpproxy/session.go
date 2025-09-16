package lmtpproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/consts"
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
	log.Printf("[LMTP Proxy] New connection from %s", clientAddr)

	// Send greeting
	if err := s.sendGreeting(); err != nil {
		log.Printf("[LMTP Proxy] Failed to send greeting to %s: %v", clientAddr, err)
		return
	}

	// Handle commands until we get RCPT TO
	for {
		// Read command from client
		line, err := s.clientReader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("[LMTP Proxy] Error reading from client %s: %v", clientAddr, err)
			}
			return
		}

		line = strings.TrimRight(line, "\r\n")
		log.Printf("[LMTP Proxy] Client %s: %s", clientAddr, line)

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
				s.sendResponse("250-PIPELINING")
				s.sendResponse("250-SIZE 52428800") // 50MB
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
				log.Printf("[LMTP Proxy] Recipient %s rejected: %v", to, err)
				s.sendResponse("550 5.1.1 User unknown")
				continue
			}

			// Now connect to backend
			if err := s.connectToBackend(); err != nil {
				log.Printf("[LMTP Proxy] Failed to connect to backend for %s: %v", s.username, err)
				s.sendResponse("451 4.4.1 Backend connection failed")
				return
			}

			// Register connection
			if err := s.registerConnection(); err != nil {
				log.Printf("[LMTP Proxy] Failed to register connection for %s: %v", s.username, err)
			}

			// Start proxying only if backend connection was successful
			if s.backendConn != nil {
				log.Printf("[LMTP Proxy] Starting proxy for recipient %s (account ID: %d)", s.to, s.accountID)
				s.startProxy(line)
			} else {
				log.Printf("[LMTP Proxy] Cannot start proxy for recipient %s: no backend connection", s.to)
			}
			return

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
			log.Printf("[LMTP Proxy] Prelookup for %s failed: %v. Falling back to main DB for affinity check.", s.username, lookupErr)
		} else if routingInfo != nil && routingInfo.ServerAddress != "" {
			log.Printf("[LMTP Proxy] Routing %s to %s via prelookup", s.username, routingInfo.ServerAddress)
			s.routingInfo = routingInfo
			s.isPrelookupAccount = true
			s.accountID = routingInfo.AccountID // May be 0, that's fine
			return nil
		}
	}

	// 2. Fallback to main DB to get account ID for affinity
	s.isPrelookupAccount = false
	row := s.server.rdb.QueryRowWithRetry(s.ctx, "SELECT c.account_id FROM credentials c JOIN accounts a ON c.account_id = a.id WHERE c.address = $1 AND a.deleted_at IS NULL", s.username)
	if err := row.Scan(&s.accountID); err != nil {
		return fmt.Errorf("user not found in main database: %w", err)
	}
	return nil
}

// getPreferredBackend fetches the preferred backend server for the user based on affinity.
func (s *Session) getPreferredBackend() (string, error) {
	if !s.server.enableAffinity || s.isPrelookupAccount {
		return "", nil
	}

	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	defer cancel()

	lastAddr, lastTime, err := s.server.rdb.GetLastServerAddressWithRetry(ctx, s.accountID)
	if err != nil {
		// Don't log ErrDBNotFound as an error, it's an expected case.
		if errors.Is(err, consts.ErrNoServerAffinity) {
			return "", nil
		}
		return "", err
	}

	if lastAddr != "" && time.Since(lastTime) < s.server.affinityValidity {
		return lastAddr, nil
	}

	return "", nil
}

// connectToBackend establishes a connection to the backend server.
func (s *Session) connectToBackend() error {
	var preferredAddr string
	var err error
	routingMethod := "roundrobin" // Default to round-robin
	isPrelookupRoute := false
	routingInfo := s.routingInfo

	// 1. Use prelookup result if available
	if routingInfo != nil && routingInfo.ServerAddress != "" {
		isPrelookupRoute = true
		routingMethod = "prelookup"
		address := routingInfo.ServerAddress
		// If the address from prelookup doesn't contain a port,
		// use the new RemotePort field if it's available.
		_, _, splitErr := net.SplitHostPort(address)
		remotePort, portErr := s.server.prelookupConfig.GetRemotePort()
		if portErr != nil {
			log.Printf("[LMTP Proxy] Invalid remote_port in prelookup config: %v", portErr)
		}
		if splitErr != nil && remotePort > 0 {
			address = net.JoinHostPort(address, fmt.Sprintf("%d", remotePort))
		}
		preferredAddr = address
	} else {
		// 2. If no prelookup route, try affinity
		preferredAddr, err = s.getPreferredBackend()
		if err != nil {
			log.Printf("[LMTP Proxy] Could not get preferred backend for %s: %v", s.username, err)
		}
		if preferredAddr != "" {
			routingMethod = "affinity"
			log.Printf("[LMTP Proxy] Using server affinity for %s: %s", s.username, preferredAddr)
		}
	}

	// 3. Apply stickiness to affinity address ONLY. Prelookup routes are absolute.
	if preferredAddr != "" && !isPrelookupRoute && s.server.affinityStickiness < 1.0 {
		if rand.Float64() > s.server.affinityStickiness {
			log.Printf("[LMTP Proxy] Ignoring affinity for %s due to stickiness factor (%.2f), falling back to round-robin", s.username, s.server.affinityStickiness)
			preferredAddr = "" // This will cause the connection manager to use round-robin
			routingMethod = "roundrobin"
		}
	}

	// 4. Connect using the determined address (or round-robin if empty)
	// Track which routing method was used for this connection.
	metrics.ProxyRoutingMethod.WithLabelValues("lmtp", routingMethod).Inc()

	clientHost, clientPort := server.GetHostPortFromAddr(s.clientConn.RemoteAddr())
	serverHost, serverPort := server.GetHostPortFromAddr(s.clientConn.LocalAddr())
	backendConn, actualAddr, err := s.server.connManager.ConnectWithProxy(
		s.ctx,
		preferredAddr,
		clientHost, clientPort, serverHost, serverPort, routingInfo,
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
		updateCtx, updateCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer updateCancel()
		if err = s.server.rdb.UpdateLastServerAddressWithRetry(updateCtx, s.accountID, actualAddr); err != nil {
			log.Printf("[LMTP Proxy] Failed to update server affinity for %s: %v", s.username, err)
		} else {
			log.Printf("[LMTP Proxy] Updated server affinity for %s to %s", s.username, actualAddr)
		}
	}

	// Read greeting from backend
	greeting, err := s.backendReader.ReadString('\n')
	if err != nil {
		s.backendConn.Close()
		return fmt.Errorf("failed to read backend greeting: %w", err)
	}

	log.Printf("[LMTP Proxy] Backend greeting: %s", strings.TrimRight(greeting, "\r\n"))

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

		log.Printf("[LMTP Proxy] Backend LHLO response: %s", strings.TrimRight(response, "\r\n"))

		// Check if this is the last line (no hyphen after status code)
		if len(response) >= 4 && response[3] != '-' {
			if !strings.HasPrefix(response, "250") {
				s.backendConn.Close()
				return fmt.Errorf("backend LHLO failed: %s", response)
			}
			break
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
			log.Printf("[LMTP Proxy] Failed to send forwarding parameters for %s: %v", s.username, err)
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

		log.Printf("[LMTP Proxy] Backend MAIL FROM accepted")
	}

	return nil
}

// startProxy starts bidirectional proxying between client and backend.
// initialCommand is the RCPT TO command that triggered the proxy.
func (s *Session) startProxy(initialCommand string) {
	if s.backendConn == nil {
		log.Printf("[LMTP Proxy] backend connection not established for %s", s.username)
		s.sendResponse("451 4.4.2 Backend connection not available")
		return
	}

	// First, send the RCPT TO command that triggered proxying
	_, err := s.backendWriter.WriteString(initialCommand + "\r\n")
	if err != nil {
		log.Printf("[LMTP Proxy] Failed to send initial RCPT TO: %v", err)
		s.sendResponse("451 4.4.2 Backend error")
		return
	}
	s.backendWriter.Flush()

	// Read and forward the response
	response, err := s.backendReader.ReadString('\n')
	if err != nil {
		log.Printf("[LMTP Proxy] Failed to read RCPT TO response: %v", err)
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
		// If this copy returns, it means the client has closed the connection or there was an error.
		// We must close the backend connection to unblock the other copy operation.
		defer s.backendConn.Close()
		bytesIn, err := io.Copy(s.backendConn, s.clientConn)
		metrics.BytesThroughput.WithLabelValues("lmtp_proxy", "in").Add(float64(bytesIn))
		if err != nil && !isClosingError(err) {
			log.Printf("[LMTP Proxy] Error copying from client to backend: %v", err)
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
		metrics.BytesThroughput.WithLabelValues("lmtp_proxy", "out").Add(float64(bytesOut))
		if err != nil && !isClosingError(err) {
			log.Printf("[LMTP Proxy] Error copying from backend to client: %v", err)
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

	// Unregister connection
	if s.accountID > 0 {
		// Use a new background context for this final operation, as s.ctx is likely already cancelled.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		clientAddr := s.clientConn.RemoteAddr().String()

		if s.server.connTracker != nil && s.server.connTracker.IsEnabled() {
			if err := s.server.connTracker.UnregisterConnection(ctx, s.accountID, "LMTP", clientAddr); err != nil {
				log.Printf("[LMTP Proxy] Failed to unregister connection for %s: %v", s.username, err)
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
			log.Printf("[LMTP Proxy] Failed to check termination for %s: %v", s.username, err)
			return false
		}
		if shouldTerminate {
			log.Printf("[LMTP Proxy] Connection kicked - disconnecting user: %s (client: %s, backend: %s)", s.username, clientAddr, s.serverAddr)
			s.clientConn.Close()
			s.backendConn.Close()
			return true
		}
		return false
	}

	for {
		select {
		case <-kickChan:
			log.Printf("[LMTP Proxy] Received kick notification for %s", s.username)
			if checkAndTerminate() {
				return
			}
		case <-activityTicker.C:
			updateCtx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
			if err := s.server.connTracker.UpdateActivity(updateCtx, s.accountID, "LMTP", clientAddr); err != nil {
				log.Printf("[LMTP Proxy] Failed to update activity for %s: %v", s.username, err)
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
