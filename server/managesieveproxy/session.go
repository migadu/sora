package managesieveproxy

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

	"github.com/migadu/sora/db"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
)

// Session represents a ManageSieve proxy session.
type Session struct {
	server       *Server
	clientConn   net.Conn
	backendConn  net.Conn
	clientReader *bufio.Reader
	clientWriter *bufio.Writer
	username     string
	accountID    int64
	serverAddr   string
	mu           sync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
}

// newSession creates a new ManageSieve proxy session.
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

	clientAddr := s.clientConn.RemoteAddr().String()
	log.Printf("[ManageSieve Proxy] New connection from %s", clientAddr)

	// Send initial greeting with capabilities
	s.sendGreeting()

	// Handle authentication phase
	authenticated := false
	for !authenticated {
		// Read command from client
		line, err := s.clientReader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("[ManageSieve Proxy] Error reading from client %s: %v", clientAddr, err)
			}
			return
		}

		line = strings.TrimRight(line, "\r\n")
		log.Printf("[ManageSieve Proxy] Client %s: %s", clientAddr, line)

		// Parse command
		parts := strings.Fields(line)
		if len(parts) < 1 {
			s.sendResponse(`NO "Invalid command"`)
			continue
		}

		command := strings.ToUpper(parts[0])

		switch command {
		case "AUTHENTICATE":
			if len(parts) < 2 || strings.ToUpper(parts[1]) != "PLAIN" {
				s.sendResponse(`NO "AUTHENTICATE PLAIN is the only supported mechanism"`)
				continue
			}

			// Check if initial response is included
			var saslLine string
			if len(parts) >= 3 {
				// Initial response provided
				saslLine = parts[2]
			} else {
				// Send continuation and wait for response
				s.sendContinuation()

				// Read SASL response
				saslLine, err = s.clientReader.ReadString('\n')
				if err != nil {
					log.Printf("[ManageSieve Proxy] Error reading SASL response: %v", err)
					return
				}
				saslLine = strings.TrimRight(saslLine, "\r\n")
			}

			// Handle cancellation
			if saslLine == "*" {
				s.sendResponse(`NO "Authentication cancelled"`)
				continue
			}

			// Decode SASL PLAIN
			decoded, err := base64.StdEncoding.DecodeString(saslLine)
			if err != nil {
				s.sendResponse(`NO "Invalid base64 encoding"`)
				continue
			}

			parts := strings.Split(string(decoded), "\x00")
			if len(parts) != 3 {
				s.sendResponse(`NO "Invalid SASL PLAIN response"`)
				continue
			}

			// authzID := parts[0] // Not used in proxy
			authnID := parts[1]
			password := parts[2]

			if err := s.authenticateUser(authnID, password); err != nil {
				log.Printf("[ManageSieve Proxy] Authentication failed for %s: %v", authnID, err)
				s.sendResponse(`NO "Authentication failed"`)
				continue
			}

			s.username = authnID

			// Connect to backend and authenticate
			if err := s.connectToBackendAndAuth(); err != nil {
				log.Printf("[ManageSieve Proxy] Backend connection/auth failed for %s: %v", authnID, err)
				s.sendResponse(`NO "Backend server temporarily unavailable"`)
				continue
			}

			// Register connection
			if err := s.registerConnection(); err != nil {
				log.Printf("[ManageSieve Proxy] Failed to register connection for %s: %v", authnID, err)
			}

			s.sendResponse(`OK "Authenticated"`)
			authenticated = true

		case "LOGOUT":
			s.sendResponse(`OK "Bye"`)
			return

		case "NOOP":
			s.sendResponse(`OK "NOOP completed"`)

		case "CAPABILITY":
			// We already sent capabilities in the greeting
			s.sendResponse(`OK "CAPABILITY completed"`)

		default:
			s.sendResponse(`NO "Command not supported before authentication"`)
		}
	}

	// Start proxying
	log.Printf("[ManageSieve Proxy] Starting proxy for user %s", s.username)
	s.startProxy()
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

// authenticateUser authenticates the user against the database.
func (s *Session) authenticateUser(username, password string) error {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	remoteAddr := s.clientConn.RemoteAddr()

	// Check if the authentication attempt is allowed by the rate limiter.
	if err := s.server.authLimiter.CanAttemptAuth(s.ctx, remoteAddr, username); err != nil {
		// Record the failed attempt before returning the error.
		s.server.authLimiter.RecordAuthAttempt(s.ctx, remoteAddr, username, false)
		metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", "failure").Inc()
		return err
	}

	address, err := server.NewAddress(username)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	accountID, err := s.server.db.Authenticate(ctx, address.FullAddress(), password)
	if err != nil {
		s.server.authLimiter.RecordAuthAttempt(s.ctx, remoteAddr, username, false)
		metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", "failure").Inc()
		return fmt.Errorf("authentication failed: %w", err)
	}

	s.server.authLimiter.RecordAuthAttempt(s.ctx, remoteAddr, username, true)
	s.accountID = accountID

	// Track successful authentication.
	metrics.AuthenticationAttempts.WithLabelValues("managesieve_proxy", "success").Inc()

	// Track domain and user connection activity for the login event.
	metrics.TrackDomainConnection("managesieve_proxy", address.Domain())
	metrics.TrackUserActivity("managesieve_proxy", address.FullAddress(), "connection", 1)

	return nil
}

// sendGreeting sends the initial ManageSieve greeting with capabilities.
func (s *Session) sendGreeting() {
	// Send a minimal set of capabilities for the proxy
	s.clientWriter.WriteString(`"IMPLEMENTATION" "Sora ManageSieve Proxy"` + "\r\n")
	s.clientWriter.WriteString(`"SASL" "PLAIN"` + "\r\n")
	s.clientWriter.WriteString(`"VERSION" "1.0"` + "\r\n")
	s.clientWriter.WriteString(`OK "ManageSieve proxy ready"` + "\r\n")
	s.clientWriter.Flush()
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

// connectToBackendAndAuth connects to backend and authenticates.
func (s *Session) connectToBackendAndAuth() error {
	var preferredAddr string
	var err error

	// 1. Try routing lookup first
	if s.server.connManager.HasRouting() {
		routingCtx, routingCancel := context.WithTimeout(s.ctx, 5*time.Second)
		routingInfo, lookupErr := s.server.connManager.LookupUserRoute(routingCtx, s.username)
		routingCancel()
		if lookupErr != nil {
			log.Printf("[ManageSieve Proxy] Routing lookup failed for %s: %v, falling back to affinity", s.username, lookupErr)
		} else if routingInfo != nil && routingInfo.ServerAddress != "" {
			preferredAddr = routingInfo.ServerAddress
			log.Printf("[ManageSieve Proxy] Using routing lookup for %s: %s", s.username, preferredAddr)
		}
	}

	// 2. If no routing info, try affinity
	if preferredAddr == "" {
		preferredAddr, err = s.getPreferredBackend()
		if err != nil {
			log.Printf("[ManageSieve Proxy] Could not get preferred backend for %s: %v", s.username, err)
		}
		if preferredAddr != "" {
			log.Printf("[ManageSieve Proxy] Using server affinity for %s: %s", s.username, preferredAddr)
		}
	}

	// 3. Apply stickiness to affinity/routing address
	if preferredAddr != "" && s.server.affinityStickiness < 1.0 {
		if rand.Float64() > s.server.affinityStickiness {
			log.Printf("[ManageSieve Proxy] Ignoring affinity/routing for %s due to stickiness factor (%.2f), falling back to round-robin", s.username, s.server.affinityStickiness)
			preferredAddr = "" // This will cause the connection manager to use round-robin
		}
	}

	// 4. Connect using the determined address (or round-robin if empty)
	connectCtx, connectCancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer connectCancel()

	clientHost, clientPort := server.GetHostPortFromAddr(s.clientConn.RemoteAddr())
	serverHost, serverPort := server.GetHostPortFromAddr(s.clientConn.LocalAddr())
	conn, actualAddr, err := s.server.connManager.ConnectWithProxy(
		connectCtx,
		preferredAddr,
		clientHost, clientPort, serverHost, serverPort,
	)
	if err != nil {
		return fmt.Errorf("failed to connect to backend: %w", err)
	}
	s.backendConn = conn
	s.serverAddr = actualAddr

	// Record successful connection for future affinity
	if s.server.enableAffinity && actualAddr != "" {
		updateCtx, updateCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer updateCancel()
		if err := s.server.db.UpdateLastServerAddress(updateCtx, s.accountID, actualAddr); err != nil {
			log.Printf("[ManageSieve Proxy] Failed to update server affinity for %s: %v", s.username, err)
		} else {
			log.Printf("[ManageSieve Proxy] Updated server affinity for %s to %s", s.username, actualAddr)
		}
	}

	// Read backend greeting and capabilities
	backendReader := bufio.NewReader(s.backendConn)
	for {
		line, err := backendReader.ReadString('\n')
		if err != nil {
			s.backendConn.Close()
			return fmt.Errorf("failed to read backend greeting: %w", err)
		}

		// Just consume the backend greeting, don't forward it (we already sent our own)
		// Check if this is the OK line (end of capabilities)
		if strings.HasPrefix(strings.TrimSpace(line), "OK") {
			break
		}
	}

	// Now authenticate to backend
	return s.authenticateToBackend()
}

// authenticateToBackend authenticates to the backend using master credentials.
func (s *Session) authenticateToBackend() error {
	backendWriter := bufio.NewWriter(s.backendConn)
	backendReader := bufio.NewReader(s.backendConn)

	// Send AUTHENTICATE PLAIN command with impersonation
	authString := fmt.Sprintf("%s\x00%s\x00%s", s.username, string(s.server.masterSASLUsername), string(s.server.masterSASLPassword))
	encoded := base64.StdEncoding.EncodeToString([]byte(authString))

	_, err := backendWriter.WriteString(fmt.Sprintf("AUTHENTICATE PLAIN %s\r\n", encoded))
	if err != nil {
		return fmt.Errorf("failed to send AUTHENTICATE command: %w", err)
	}
	backendWriter.Flush()

	// Read authentication response
	response, err := backendReader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if !strings.HasPrefix(response, "OK") {
		return fmt.Errorf("backend authentication failed: %s", response)
	}

	log.Printf("[ManageSieve Proxy] Backend authentication successful for user %s", s.username)

	return nil
}

// startProxy starts bidirectional proxying between client and backend.
func (s *Session) startProxy() {
	var wg sync.WaitGroup

	// Start activity updater
	activityCtx, activityCancel := context.WithCancel(s.ctx)
	defer activityCancel()
	go s.updateActivityPeriodically(activityCtx)

	// Client to backend
	wg.Add(1)
	go func() {
		defer wg.Done()
		bytesIn, err := io.Copy(s.backendConn, s.clientConn)
		metrics.BytesThroughput.WithLabelValues("managesieve_proxy", "in").Add(float64(bytesIn))
		if err != nil && !isClosingError(err) {
			log.Printf("[ManageSieve Proxy] Error copying from client to backend: %v", err)
		}
		s.backendConn.Close() // Close backend to unblock the other io.Copy
		s.clientConn.Close()
	}()

	// Backend to client
	wg.Add(1)
	go func() {
		defer wg.Done()
		bytesOut, err := io.Copy(s.clientConn, s.backendConn)
		metrics.BytesThroughput.WithLabelValues("managesieve_proxy", "out").Add(float64(bytesOut))
		if err != nil && !isClosingError(err) {
			log.Printf("[ManageSieve Proxy] Error copying from backend to client: %v", err)
		}
		s.clientConn.Close() // Close client to unblock the other io.Copy
		s.backendConn.Close()
	}()

	go func() {
		<-s.ctx.Done()
		s.clientConn.Close()
		s.backendConn.Close()
	}()

	wg.Wait() // Wait for both copy operations to finish
}

// close closes all connections.
func (s *Session) close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Decrement current connections metric
	metrics.ConnectionsCurrent.WithLabelValues("managesieve_proxy").Dec()

	// Unregister connection
	if s.accountID > 0 {
		// Use a new background context for this final operation, as s.ctx is likely already cancelled.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		clientAddr := s.clientConn.RemoteAddr().String()

		if s.server.connTracker != nil && s.server.connTracker.IsEnabled() {
			if err := s.server.connTracker.UnregisterConnection(ctx, s.accountID, "ManageSieve", clientAddr); err != nil {
				log.Printf("[ManageSieve Proxy] Failed to unregister connection for %s: %v", s.username, err)
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
		return s.server.connTracker.RegisterConnection(ctx, s.accountID, "ManageSieve", clientAddr, s.serverAddr)
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
	activityTicker := time.NewTicker(30 * time.Second)
	defer activityTicker.Stop()
	kickChan := s.server.connTracker.KickChannel()

	checkAndTerminate := func() (terminated bool) {
		checkCtx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
		defer cancel()

		shouldTerminate, err := s.server.connTracker.CheckTermination(checkCtx, s.accountID, "ManageSieve", clientAddr)
		if err != nil {
			log.Printf("[ManageSieve Proxy] Failed to check termination for %s: %v", s.username, err)
			return false
		}
		if shouldTerminate {
			log.Printf("[ManageSieve Proxy] Connection marked for termination, disconnecting: %s", s.username)
			s.clientConn.Close()
			s.backendConn.Close()
			return true
		}
		return false
	}

	for {
		select {
		case <-kickChan:
			log.Printf("[ManageSieve Proxy] Received kick notification for %s", s.username)
			if checkAndTerminate() {
				return
			}
		case <-activityTicker.C:
			updateCtx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
			if err := s.server.connTracker.UpdateActivity(updateCtx, s.accountID, "ManageSieve", clientAddr); err != nil {
				log.Printf("[ManageSieve Proxy] Failed to update activity for %s: %v", s.username, err)
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
