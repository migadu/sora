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

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
)

// Session represents an LMTP proxy session.
type Session struct {
	server        *Server
	clientConn    net.Conn
	backendConn   net.Conn
	backendReader *bufio.Reader
	backendWriter *bufio.Writer
	clientReader  *bufio.Reader
	clientWriter  *bufio.Writer
	from          string
	to            string
	username      string
	accountID     int64
	serverAddr    string
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
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

		// Parse command
		parts := strings.Fields(strings.ToUpper(line))
		if len(parts) == 0 {
			s.sendResponse("500 5.5.2 Syntax error")
			continue
		}

		command := parts[0]

		switch command {
		case "HELO", "EHLO", "LHLO":
			// LHLO is LMTP-specific greeting
			if len(parts) < 2 {
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
			// MAIL FROM:<sender>
			if len(line) < 10 || !strings.HasPrefix(strings.ToUpper(line), "MAIL FROM:") {
				s.sendResponse("501 5.5.4 Syntax error in MAIL command")
				continue
			}
			from := s.extractAddress(line[10:])
			if from == "" {
				s.sendResponse("501 5.1.7 Bad sender address syntax")
				continue
			}
			s.from = from
			s.sendResponse("250 2.1.0 Ok")

		case "RCPT":
			// RCPT TO:<recipient>
			if len(line) < 8 || !strings.HasPrefix(strings.ToUpper(line), "RCPT TO:") {
				s.sendResponse("501 5.5.4 Syntax error in RCPT command")
				continue
			}
			to := s.extractAddress(line[8:])
			if to == "" {
				s.sendResponse("501 5.1.3 Bad recipient address syntax")
				continue
			}

			// Look up user by email address
			address, err := server.NewAddress(to)
			if err != nil {
				log.Printf("[LMTP Proxy] Invalid address format: %v", err)
				s.sendResponse("550 5.1.1 User unknown")
				continue
			}

			// Use base address (without detail part) for lookup
			lookupAddress := address.BaseAddress()
			accountID, err := s.server.db.GetAccountIDByAddress(s.ctx, lookupAddress)
			if err != nil {
				log.Printf("[LMTP Proxy] User not found for %s: %v", lookupAddress, err)
				s.sendResponse("550 5.1.1 User unknown")
				continue
			}

			s.to = to
			s.username = lookupAddress
			s.accountID = accountID

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

			// Start proxying
			log.Printf("[LMTP Proxy] Starting proxy for recipient %s (account ID: %d)", s.to, s.accountID)
			s.startProxy(line)
			return

		case "RSET":
			s.from = ""
			s.to = ""
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
	param = strings.TrimSpace(param)
	if len(param) < 2 {
		return ""
	}

	// Handle <address> format
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

// getPreferredBackend fetches the preferred backend server for the user based on affinity.
func (s *Session) getPreferredBackend() (string, error) {
	if !s.server.enableAffinity {
		return "", nil
	}

	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	defer cancel()

	lastAddr, lastTime, err := s.server.db.GetLastServerAddress(ctx, s.accountID)
	if err != nil {
		// Don't log ErrDBNotFound as an error, it's an expected case.
		if errors.Is(err, db.ErrNoServerAffinity) {
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
	// Get preferred backend from affinity
	preferredAddr, err := s.getPreferredBackend()
	if err != nil {
		log.Printf("[LMTP Proxy] Could not get preferred backend for %s: %v", s.username, err)
	}

	// Probabilistically ignore affinity to improve load balancing
	if preferredAddr != "" && s.server.affinityStickiness < 1.0 {
		if rand.Float64() > s.server.affinityStickiness {
			log.Printf("[LMTP Proxy] Ignoring affinity for %s due to stickiness factor (%.2f), falling back to round-robin", s.username, s.server.affinityStickiness)
			preferredAddr = "" // This will cause the connection manager to use round-robin
		}
	}

	if preferredAddr != "" {
		log.Printf("[LMTP Proxy] Using server affinity for %s: %s", s.username, preferredAddr)
	}

	// Connect using the connection manager with user routing and PROXY protocol
	// Note: For LMTP, we need a recipient email for routing, but we'll use the sender for now
	routingCtx, routingCancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer routingCancel()

	var actualAddr string
	clientHost, clientPort := server.GetHostPortFromAddr(s.clientConn.RemoteAddr())
	serverHost, serverPort := server.GetHostPortFromAddr(s.clientConn.LocalAddr())
	backendConn, actualAddr, err := s.server.connManager.ConnectForUserWithProxy(
		routingCtx,
		s.from, // Use sender email for routing lookup (could be enhanced to use recipient)
		clientHost, clientPort, serverHost, serverPort,
	)
	if err != nil {
		// Track backend connection failure
		metrics.ProxyBackendConnections.WithLabelValues("lmtp", "failure").Inc()
		return fmt.Errorf("failed to connect to backend: %w", err)
	}

	// Track backend connection success
	metrics.ProxyBackendConnections.WithLabelValues("lmtp", "success").Inc()
	s.backendConn = backendConn
	s.serverAddr = actualAddr
	s.backendReader = bufio.NewReader(s.backendConn)
	s.backendWriter = bufio.NewWriter(s.backendConn)

	// Record successful connection for future affinity
	if s.server.enableAffinity && actualAddr != "" {
		// Use a new, short-lived context for this update to avoid issues with the parent context's timeout.
		updateCtx, updateCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer updateCancel()
		if err = s.server.db.UpdateLastServerAddress(updateCtx, s.accountID, actualAddr); err != nil {
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

	// Send MAIL FROM to backend
	if s.from != "" {
		mailCmd := fmt.Sprintf("MAIL FROM:<%s>\r\n", s.from)
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
		if _, err := io.Copy(s.backendConn, s.clientConn); err != nil && !isClosingError(err) {
			log.Printf("[LMTP Proxy] Error copying from client to backend: %v", err)
		}
		s.backendConn.Close()
		s.clientConn.Close()
	}()

	// Backend to client
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(s.clientConn, s.backendConn); err != nil && !isClosingError(err) {
			log.Printf("[LMTP Proxy] Error copying from backend to client: %v", err)
		}
		s.clientConn.Close()
		s.backendConn.Close()
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

		if s.server.connTracker != nil {
			if err := s.server.connTracker.UnregisterConnection(ctx, s.accountID, "LMTP", clientAddr); err != nil {
				log.Printf("[LMTP Proxy] Failed to unregister connection for %s: %v", s.username, err)
			}
		} else {
			if err := s.server.db.UnregisterConnection(ctx, s.accountID, "LMTP", clientAddr); err != nil {
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

	if s.server.connTracker == nil {
		return s.server.db.RegisterConnection(ctx, s.accountID, "LMTP", clientAddr, s.serverAddr, s.server.hostname)
	}

	return s.server.connTracker.RegisterConnection(ctx, s.accountID, "LMTP", clientAddr, s.serverAddr)
}

// updateActivityPeriodically updates the connection activity in the database.
func (s *Session) updateActivityPeriodically(ctx context.Context) {
	clientAddr := s.clientConn.RemoteAddr().String()

	// If connection tracking is disabled, fall back to the old polling mechanism.
	if s.server.connTracker == nil || !s.server.connTracker.IsEnabled() {
		s.pollDatabaseDirectly(ctx)
		return
	}

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
			log.Printf("[LMTP Proxy] Connection marked for termination, disconnecting: %s", s.username)
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

// pollDatabaseDirectly is the legacy behavior for when connection tracking is disabled.
func (s *Session) pollDatabaseDirectly(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	clientAddr := s.clientConn.RemoteAddr().String()

	for {
		select {
		case <-ticker.C:
			updateCtx, cancel := context.WithTimeout(s.ctx, 5*time.Second)

			if err := s.server.db.UpdateConnectionActivity(updateCtx, s.accountID, "LMTP", clientAddr); err != nil {
				log.Printf("[LMTP Proxy] Failed to update activity for %s: %v", s.username, err)
			}

			shouldTerminate, err := s.server.db.CheckConnectionTermination(updateCtx, s.accountID, "LMTP", clientAddr)
			if err != nil {
				log.Printf("[LMTP Proxy] Failed to check termination for %s: %v", s.username, err)
			} else if shouldTerminate {
				log.Printf("[LMTP Proxy] Connection marked for termination, disconnecting: %s", s.username)
				cancel()
				s.clientConn.Close()
				s.backendConn.Close()
				return
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
