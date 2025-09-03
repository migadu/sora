package pop3proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
)

type POP3ProxySession struct {
	server        *POP3ProxyServer
	clientConn    net.Conn
	backendConn   net.Conn
	ctx           context.Context
	cancel        context.CancelFunc
	RemoteIP      string
	username      string
	accountID     int64
	serverAddr    string
	authenticated bool
	mutex         sync.Mutex
}

func (s *POP3ProxySession) handleConnection() {
	defer s.cancel()
	defer s.server.wg.Done()
	defer s.close()

	// Send initial greeting to client
	writer := bufio.NewWriter(s.clientConn)
	writer.WriteString("+OK POP3 proxy ready\r\n")
	writer.Flush()

	reader := bufio.NewReader(s.clientConn)

	for {
		// Set read deadline
		s.clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				log.Printf("[POP3PROXY %s] client dropped connection", s.RemoteIP)
			} else {
				log.Printf("[POP3PROXY %s] read error: %v", s.RemoteIP, err)
			}
			return
		}

		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, " ", 2)
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
				writer.WriteString("-ERR Missing username\r\n")
				writer.Flush()
				continue
			}
			s.username = parts[1]
			writer.WriteString("+OK User accepted\r\n")
			writer.Flush()

		case "PASS":
			if s.username == "" {
				writer.WriteString("-ERR Must provide USER first\r\n")
				writer.Flush()
				continue
			}
			if len(parts) < 2 {
				writer.WriteString("-ERR Missing password\r\n")
				writer.Flush()
				continue
			}
			password := parts[1]

			if err := s.authenticate(s.username, password); err != nil {
				writer.WriteString("-ERR Authentication failed\r\n")
				writer.Flush()
				log.Printf("[POP3PROXY %s] authentication failed for %s: %v", s.RemoteIP, s.username, err)
				continue
			}

			writer.WriteString("+OK Authentication successful\r\n")
			writer.Flush()

			// Register connection
			if err := s.registerConnection(); err != nil {
				log.Printf("[POP3PROXY %s] Failed to register connection for %s: %v", s.RemoteIP, s.username, err)
			}

			// Start proxying
			s.startProxying()
			return

		case "AUTH":
			if len(parts) < 2 {
				writer.WriteString("-ERR Missing authentication mechanism\r\n")
				writer.Flush()
				continue
			}

			mechanism := strings.ToUpper(parts[1])
			if mechanism != "PLAIN" {
				writer.WriteString("-ERR Unsupported authentication mechanism\r\n")
				writer.Flush()
				continue
			}

			var authData string
			if len(parts) > 2 {
				// Initial response provided
				authData = parts[2]
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
				writer.WriteString("-ERR Invalid authentication data\r\n")
				writer.Flush()
				continue
			}

			// Parse SASL PLAIN format: [authz-id] \0 authn-id \0 password
			authParts := strings.Split(string(decoded), "\x00")
			if len(authParts) != 3 {
				writer.WriteString("-ERR Invalid authentication format\r\n")
				writer.Flush()
				continue
			}

			authzID := authParts[0]
			authnID := authParts[1]
			password := authParts[2]

			// For proxy, we expect authzID to be empty or same as authnID
			if authzID != "" && authzID != authnID {
				writer.WriteString("-ERR Proxy authentication not supported\r\n")
				writer.Flush()
				continue
			}

			if err := s.authenticate(authnID, password); err != nil {
				writer.WriteString("-ERR Authentication failed\r\n")
				writer.Flush()
				log.Printf("[POP3PROXY %s] SASL authentication failed for %s: %v", s.RemoteIP, authnID, err)
				continue
			}

			writer.WriteString("+OK Authentication successful\r\n")
			writer.Flush()

			// Register connection
			if err := s.registerConnection(); err != nil {
				log.Printf("[POP3PROXY %s] Failed to register connection for %s: %v", s.RemoteIP, authnID, err)
			}

			// Start proxying
			s.startProxying()
			return

		case "QUIT":
			writer.WriteString("+OK Goodbye\r\n")
			writer.Flush()
			return

		default:
			writer.WriteString("-ERR Command not available before authentication\r\n")
			writer.Flush()
		}
	}
}

func (s *POP3ProxySession) authenticate(username, password string) error {
	remoteAddr := s.clientConn.RemoteAddr()

	// Check if the authentication attempt is allowed by the rate limiter.
	if err := s.server.authLimiter.CanAttemptAuth(s.ctx, remoteAddr, username); err != nil {
		s.server.authLimiter.RecordAuthAttempt(s.ctx, remoteAddr, username, false)
		metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "failure").Inc()
		return err
	}

	// Authenticate against the database
	address, err := server.NewAddress(username)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	accountID, err := s.server.db.Authenticate(s.ctx, address.FullAddress(), password)
	if err != nil {
		s.server.authLimiter.RecordAuthAttempt(s.ctx, remoteAddr, username, false)
		metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "failure").Inc()
		return fmt.Errorf("authentication failed: %w", err)
	}

	s.server.authLimiter.RecordAuthAttempt(s.ctx, remoteAddr, username, true)
	// Store user details on the session
	s.mutex.Lock()

	// Track successful authentication.
	metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "success").Inc()

	// Track domain and user connection activity for the login event.
	metrics.TrackDomainConnection("pop3_proxy", address.Domain())
	metrics.TrackUserActivity("pop3_proxy", address.FullAddress(), "connection", 1)

	s.authenticated = true
	s.username = address.FullAddress()
	s.accountID = accountID
	s.mutex.Unlock()

	// Connect to backend
	if err := s.connectToBackend(); err != nil {
		return fmt.Errorf("failed to connect to backend: %w", err)
	}

	return nil
}

// getPreferredBackend fetches the preferred backend server for the user based on affinity.
func (s *POP3ProxySession) getPreferredBackend() (string, error) {
	if !s.server.enableAffinity {
		return "", nil
	}

	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	defer cancel()

	lastAddr, lastTime, err := s.server.db.GetLastServerAddress(ctx, s.accountID)
	if err != nil {
		// Don't log ErrDBNotFound as an error, it's an expected case.
		if err.Error() == "no server affinity found" {
			return "", nil
		}
		return "", err
	}

	if lastAddr != "" && time.Since(lastTime) < s.server.affinityValidity {
		return lastAddr, nil
	}

	return "", nil
}

func (s *POP3ProxySession) connectToBackend() error {
	// Get preferred backend from affinity
	preferredAddr, err := s.getPreferredBackend()
	if err != nil {
		log.Printf("[POP3PROXY %s] Could not get preferred backend for %s: %v", s.RemoteIP, s.username, err)
	}

	// Probabilistically ignore affinity to improve load balancing
	if preferredAddr != "" && s.server.affinityStickiness < 1.0 {
		if rand.Float64() > s.server.affinityStickiness {
			log.Printf("[POP3PROXY %s] Ignoring affinity for %s due to stickiness factor (%.2f), falling back to round-robin", s.RemoteIP, s.username, s.server.affinityStickiness)
			preferredAddr = "" // This will cause the connection manager to use round-robin
		}
	}

	if preferredAddr != "" {
		log.Printf("[POP3PROXY %s] Using server affinity for %s: %s", s.RemoteIP, s.username, preferredAddr)
	}

	// Extract client connection information for PROXY protocol
	clientHost, clientPortStr, err := net.SplitHostPort(s.clientConn.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("failed to parse client address: %w", err)
	}
	clientPort, err := strconv.Atoi(clientPortStr)
	if err != nil {
		return fmt.Errorf("failed to parse client port: %w", err)
	}

	// Extract server connection information for PROXY protocol
	serverHost, serverPortStr, err := net.SplitHostPort(s.clientConn.LocalAddr().String())
	if err != nil {
		return fmt.Errorf("failed to parse server address: %w", err)
	}
	serverPort, err := strconv.Atoi(serverPortStr)
	if err != nil {
		return fmt.Errorf("failed to parse server port: %w", err)
	}

	// Connect using the connection manager with PROXY protocol
	var actualAddr string
	backendConn, actualAddr, err := s.server.connManager.ConnectWithProxy(preferredAddr, clientHost, clientPort, serverHost, serverPort)
	if err != nil {
		return fmt.Errorf("failed to connect to backend: %w", err)
	}
	s.backendConn = backendConn
	s.serverAddr = actualAddr

	// Record successful connection for future affinity
	if s.server.enableAffinity && actualAddr != "" {
		// Use a new, short-lived context for this update to avoid issues with the parent context's timeout.
		updateCtx, updateCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer updateCancel()
		if err := s.server.db.UpdateLastServerAddress(updateCtx, s.accountID, actualAddr); err != nil {
			log.Printf("[POP3PROXY %s] Failed to update server affinity for %s: %v", s.RemoteIP, s.username, err)
		} else {
			log.Printf("[POP3PROXY %s] Updated server affinity for %s to %s", s.RemoteIP, s.username, actualAddr)
		}
	}

	// Read backend greeting
	backendReader := bufio.NewReader(s.backendConn)
	greeting, err := backendReader.ReadString('\n')
	if err != nil {
		s.backendConn.Close()
		return fmt.Errorf("failed to read backend greeting: %w", err)
	}

	if !strings.HasPrefix(greeting, "+OK") {
		s.backendConn.Close()
		return fmt.Errorf("unexpected backend greeting: %s", greeting)
	}

	// Authenticate to backend using master SASL credentials
	backendWriter := bufio.NewWriter(s.backendConn)

	// Use AUTH PLAIN with master credentials
	authString := fmt.Sprintf("%s\x00%s\x00%s", s.username, s.server.masterSASLUsername, s.server.masterSASLPassword)
	encoded := base64.StdEncoding.EncodeToString([]byte(authString))

	backendWriter.WriteString(fmt.Sprintf("AUTH PLAIN %s\r\n", encoded))
	backendWriter.Flush()

	// Read auth response
	authResp, err := backendReader.ReadString('\n')
	if err != nil {
		s.backendConn.Close()
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if !strings.HasPrefix(authResp, "+OK") {
		s.backendConn.Close()
		return fmt.Errorf("backend authentication failed: %s", authResp)
	}

	log.Printf("[POP3PROXY %s] authenticated to backend as %s", s.RemoteIP, s.username)
	return nil
}

func (s *POP3ProxySession) startProxying() {
	if s.backendConn == nil {
		log.Printf("[POP3PROXY %s] backend connection not established", s.RemoteIP)
		return
	}

	defer s.backendConn.Close()

	log.Printf("[POP3PROXY %s] starting bidirectional proxy for %s", s.RemoteIP, s.username)

	var wg sync.WaitGroup

	// Start activity updater
	activityCtx, activityCancel := context.WithCancel(s.ctx)
	defer activityCancel()
	go s.updateActivityPeriodically(activityCtx)

	// Copy from client to backend with command filtering
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.filteredCopyClientToBackend()
		s.backendConn.Close() // Close backend to unblock the other io.Copy
		s.clientConn.Close()
	}()

	// Copy from backend to client
	wg.Add(1)
	go func() {
		defer wg.Done()
		bytesOut, err := io.Copy(s.clientConn, s.backendConn)
		metrics.BytesThroughput.WithLabelValues("pop3_proxy", "out").Add(float64(bytesOut))
		if err != nil && !isClosingError(err) {
			log.Printf("[POP3PROXY %s] error copying backend to client: %v", s.RemoteIP, err)
		}
		s.clientConn.Close() // Close client to unblock the other io.Copy
		s.backendConn.Close()
	}()

	// This goroutine will unblock the io.Copy operations when the session context is cancelled.
	go func() {
		<-s.ctx.Done()
		s.clientConn.Close()
		s.backendConn.Close()
	}()

	wg.Wait() // Wait for both copy operations to finish
	log.Printf("[POP3PROXY %s] proxy session ended for %s", s.RemoteIP, s.username)
}

// close closes all connections and unregisters from tracking.
func (s *POP3ProxySession) close() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Decrement current connections metric
	metrics.ConnectionsCurrent.WithLabelValues("pop3_proxy").Dec()

	// Unregister connection
	if s.accountID > 0 {
		// Use a new background context for this final operation, as s.ctx is likely already cancelled.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if s.server.connTracker != nil {
			if err := s.server.connTracker.UnregisterConnection(ctx, s.accountID, "POP3", s.RemoteIP); err != nil {
				log.Printf("[POP3PROXY %s] Failed to unregister connection for %s: %v", s.RemoteIP, s.username, err)
			}
		} else {
			if err := s.server.db.UnregisterConnection(ctx, s.accountID, "POP3", s.RemoteIP); err != nil {
				log.Printf("[POP3PROXY %s] Failed to unregister connection for %s: %v", s.RemoteIP, s.username, err)
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
func (s *POP3ProxySession) registerConnection() error {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	if s.server.connTracker == nil {
		// If no connection tracker, use direct database call
		return s.server.db.RegisterConnection(ctx, s.accountID, "POP3", s.RemoteIP, s.serverAddr, s.server.hostname)
	}

	return s.server.connTracker.RegisterConnection(ctx, s.accountID, "POP3", s.RemoteIP, s.serverAddr)
}

// updateActivityPeriodically updates the connection activity in the database.
func (s *POP3ProxySession) updateActivityPeriodically(ctx context.Context) {
	// If connection tracking is disabled, fall back to the old polling mechanism.
	if s.server.connTracker == nil || !s.server.connTracker.IsEnabled() {
		s.pollDatabaseDirectly(ctx)
		return
	}

	// New mechanism: listen for kick notifications and only update activity periodically.
	activityTicker := time.NewTicker(30 * time.Second)
	defer activityTicker.Stop()

	kickChan := s.server.connTracker.KickChannel()

	// This function only checks for termination and closes the connection if needed.
	checkAndTerminate := func() (terminated bool) {
		checkCtx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
		defer cancel()

		shouldTerminate, err := s.server.connTracker.CheckTermination(checkCtx, s.accountID, "POP3", s.RemoteIP)
		if err != nil {
			log.Printf("[POP3PROXY %s] Failed to check termination for %s: %v", s.RemoteIP, s.username, err)
			return false
		}
		if shouldTerminate {
			log.Printf("[POP3PROXY %s] Connection marked for termination, disconnecting: %s", s.RemoteIP, s.username)
			s.clientConn.Close()
			s.backendConn.Close()
			return true
		}
		return false
	}

	for {
		select {
		case <-kickChan:
			log.Printf("[POP3PROXY %s] Received kick notification for %s", s.RemoteIP, s.username)
			if checkAndTerminate() {
				return
			}
		case <-activityTicker.C:
			updateCtx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
			if err := s.server.connTracker.UpdateActivity(updateCtx, s.accountID, "POP3", s.RemoteIP); err != nil {
				log.Printf("[POP3PROXY %s] Failed to update activity for %s: %v", s.RemoteIP, s.username, err)
			}
			cancel()
		case <-ctx.Done():
			return
		}
	}
}

// pollDatabaseDirectly is the legacy behavior for when connection tracking is disabled.
func (s *POP3ProxySession) pollDatabaseDirectly(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			updateCtx, cancel := context.WithTimeout(s.ctx, 5*time.Second)

			// Update activity
			if err := s.server.db.UpdateConnectionActivity(updateCtx, s.accountID, "POP3", s.RemoteIP); err != nil {
				log.Printf("[POP3PROXY %s] Failed to update activity for %s: %v", s.RemoteIP, s.username, err)
			}

			// Check if connection should be terminated
			shouldTerminate, err := s.server.db.CheckConnectionTermination(updateCtx, s.accountID, "POP3", s.RemoteIP)
			if err != nil {
				log.Printf("[POP3PROXY %s] Failed to check termination for %s: %v", s.RemoteIP, s.username, err)
			} else if shouldTerminate {
				log.Printf("[POP3PROXY %s] Connection marked for termination, disconnecting: %s", s.RemoteIP, s.username)
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
	return err == io.EOF || strings.Contains(err.Error(), "use of closed network connection")
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

	for {
		// Set read deadline
		s.clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF && !isClosingError(err) {
				log.Printf("[POP3PROXY %s] error reading from client: %v", s.RemoteIP, err)
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

		// Forward the command to backend
		n, err := writer.WriteString(line)
		totalBytesIn += int64(n)
		if err != nil {
			if !isClosingError(err) {
				log.Printf("[POP3PROXY %s] error writing to backend: %v", s.RemoteIP, err)
			}
			return
		}

		if err := writer.Flush(); err != nil {
			if !isClosingError(err) {
				log.Printf("[POP3PROXY %s] error flushing to backend: %v", s.RemoteIP, err)
			}
			return
		}
	}
}
