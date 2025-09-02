package imapproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/server"
)

// Session represents an IMAP proxy session.
type Session struct {
	server        *Server
	clientConn    net.Conn
	backendConn   net.Conn
	backendReader *bufio.Reader
	backendWriter *bufio.Writer
	clientReader  *bufio.Reader
	clientWriter  *bufio.Writer
	username      string
	accountID     int64
	serverAddr    string
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
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
	}
}

// handleConnection handles the proxy session.
func (s *Session) handleConnection() {
	defer s.cancel()
	defer s.close()

	clientAddr := s.clientConn.RemoteAddr().String()
	log.Printf("[IMAP Proxy] New connection from %s", clientAddr)

	// Send greeting
	if err := s.sendGreeting(); err != nil {
		log.Printf("[IMAP Proxy] Failed to send greeting to %s: %v", clientAddr, err)
		return
	}

	// Handle authentication phase
	authenticated := false
	for !authenticated {
		// Read command from client
		line, err := s.clientReader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("[IMAP Proxy] Error reading from client %s: %v", clientAddr, err)
			}
			return
		}

		line = strings.TrimRight(line, "\r\n")
		log.Printf("[IMAP Proxy] Client %s: %s", clientAddr, line)

		// Parse command
		parts := strings.Fields(line)
		if len(parts) < 2 {
			s.sendResponse("* BAD Invalid command")
			continue
		}

		tag := parts[0]
		command := strings.ToUpper(parts[1])

		switch command {
		case "LOGIN":
			if len(parts) < 4 {
				s.sendResponse(fmt.Sprintf("%s NO LOGIN requires username and password", tag))
				continue
			}

			username := s.unquoteString(parts[2])
			password := s.unquoteString(parts[3])

			if err := s.authenticateUser(username, password); err != nil {
				log.Printf("[IMAP Proxy] Authentication failed for %s: %v", username, err)
				s.sendResponse(fmt.Sprintf("%s NO Authentication failed", tag))
				continue
			}

			s.username = username

			// Connect to backend
			if err := s.connectToBackend(); err != nil {
				log.Printf("[IMAP Proxy] Failed to connect to backend for %s: %v", username, err)
				s.sendResponse(fmt.Sprintf("%s NO Backend connection failed", tag))
				return
			}

			// Authenticate to backend with master credentials
			backendResponse, err := s.authenticateToBackend()
			if err != nil {
				log.Printf("[IMAP Proxy] Backend authentication failed for %s: %v", username, err)
				s.sendResponse(fmt.Sprintf("%s NO [AUTHENTICATIONFAILED] Backend authentication failed", tag))
				return
			}

			// Register connection
			if err := s.registerConnection(); err != nil {
				log.Printf("[IMAP Proxy] Failed to register connection for %s: %v", username, err)
			}

			// Forward the backend's success response, replacing the tag.
			responsePayload := strings.TrimPrefix(backendResponse, "A001 ")
			s.sendResponse(fmt.Sprintf("%s %s", tag, responsePayload))
			authenticated = true

		case "AUTHENTICATE":
			if len(parts) < 3 || strings.ToUpper(parts[2]) != "PLAIN" {
				s.sendResponse(fmt.Sprintf("%s NO AUTHENTICATE PLAIN is the only supported mechanism", tag))
				continue
			}

			var saslLine string
			if len(parts) > 3 {
				// Initial response was provided with the command
				saslLine = parts[3]
			} else {
				// No initial response, send continuation request
				s.sendResponse("+")

				// Read SASL response from client
				var err error
				saslLine, err = s.clientReader.ReadString('\n')
				if err != nil {
					log.Printf("[IMAP Proxy] Error reading SASL response: %v", err)
					return
				}
				saslLine = strings.TrimRight(saslLine, "\r\n")
			}

			if saslLine == "*" {
				s.sendResponse(fmt.Sprintf("%s BAD Authentication cancelled", tag))
				continue
			}

			// Decode SASL PLAIN
			decoded, err := base64.StdEncoding.DecodeString(saslLine)
			if err != nil {
				s.sendResponse(fmt.Sprintf("%s NO Invalid base64 encoding", tag))
				continue
			}

			parts := strings.Split(string(decoded), "\x00")
			if len(parts) != 3 {
				s.sendResponse(fmt.Sprintf("%s NO Invalid SASL PLAIN response", tag))
				continue
			}

			// authzID := parts[0] // Not used in proxy
			authnID := parts[1]
			password := parts[2]

			if err := s.authenticateUser(authnID, password); err != nil {
				log.Printf("[IMAP Proxy] Authentication failed for %s: %v", authnID, err)
				s.sendResponse(fmt.Sprintf("%s NO Authentication failed", tag))
				continue
			}

			s.username = authnID

			// Connect to backend
			if err := s.connectToBackend(); err != nil {
				log.Printf("[IMAP Proxy] Failed to connect to backend for %s: %v", authnID, err)
				s.sendResponse(fmt.Sprintf("%s NO Backend connection failed", tag))
				return
			}

			// Authenticate to backend with master credentials
			backendResponse, err := s.authenticateToBackend()
			if err != nil {
				log.Printf("[IMAP Proxy] Backend authentication failed for %s: %v", authnID, err)
				s.sendResponse(fmt.Sprintf("%s NO [AUTHENTICATIONFAILED] Backend authentication failed", tag))
				return
			}

			// Register connection
			if err := s.registerConnection(); err != nil {
				log.Printf("[IMAP Proxy] Failed to register connection for %s: %v", authnID, err)
			}

			// Forward the backend's success response, replacing the tag.
			responsePayload := strings.TrimPrefix(backendResponse, "A001 ")
			s.sendResponse(fmt.Sprintf("%s %s", tag, responsePayload))
			authenticated = true

		case "LOGOUT":
			s.sendResponse("* BYE Proxy logging out")
			s.sendResponse(fmt.Sprintf("%s OK LOGOUT completed", tag))
			return

		case "CAPABILITY":
			s.sendResponse("* CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN")
			s.sendResponse(fmt.Sprintf("%s OK CAPABILITY completed", tag))

		case "NOOP":
			s.sendResponse(fmt.Sprintf("%s OK NOOP completed", tag))

		default:
			s.sendResponse(fmt.Sprintf("%s NO Command not supported before authentication", tag))
		}
	}

	// Start proxying
	log.Printf("[IMAP Proxy] Starting proxy for user %s", s.username)
	s.startProxy()
}

// sendGreeting sends the IMAP greeting.
func (s *Session) sendGreeting() error {
	greeting := "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN] Proxy Ready\r\n"
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

// unquoteString removes quotes from a string if present.
func (s *Session) unquoteString(str string) string {
	if len(str) >= 2 && str[0] == '"' && str[len(str)-1] == '"' {
		return str[1 : len(str)-1]
	}
	return str
}

// authenticateUser authenticates the user against the database.
func (s *Session) authenticateUser(username, password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	address, err := server.NewAddress(username)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	accountID, err := s.server.db.Authenticate(ctx, address.FullAddress(), password)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	s.accountID = accountID
	return nil
}

// connectToBackend establishes a connection to the backend server.
func (s *Session) connectToBackend() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check for server affinity if enabled
	var preferredAddr string
	if s.server.enableAffinity {
		lastAddr, lastTime, err := s.server.db.GetLastServerAddress(ctx, s.accountID)
		if err == nil && lastAddr != "" {
			if time.Since(lastTime) < s.server.affinityValidity {
				preferredAddr = lastAddr
				log.Printf("[IMAP Proxy] Using server affinity for %s: %s", s.username, preferredAddr)
			}
		}
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
	s.backendReader = bufio.NewReader(s.backendConn)
	s.backendWriter = bufio.NewWriter(s.backendConn)

	// Record successful connection for future affinity
	if s.server.enableAffinity && actualAddr != "" {
		if err = s.server.db.UpdateLastServerAddress(ctx, s.accountID, actualAddr); err != nil {
			log.Printf("[IMAP Proxy] Failed to update server affinity for %s: %v", s.username, err)
		} else {
			log.Printf("[IMAP Proxy] Updated server affinity for %s to %s", s.username, actualAddr)
		}
	}

	// Read greeting from backend
	greeting, err := s.backendReader.ReadString('\n')
	if err != nil {
		s.backendConn.Close()
		return fmt.Errorf("failed to read backend greeting: %w", err)
	}

	log.Printf("[IMAP Proxy] Backend greeting: %s", strings.TrimRight(greeting, "\r\n"))

	return nil
}

// authenticateToBackend authenticates to the backend using master credentials.
func (s *Session) authenticateToBackend() (string, error) {
	// Authenticate to the backend using master credentials in a single step.
	// SASL PLAIN format: [authz-id]\0authn-id\0password
	authString := fmt.Sprintf("%s\x00%s\x00%s", s.username, string(s.server.masterSASLUsername), string(s.server.masterSASLPassword))
	encoded := base64.StdEncoding.EncodeToString([]byte(authString))

	// Send AUTHENTICATE PLAIN with initial response
	authCmd := fmt.Sprintf("A001 AUTHENTICATE PLAIN %s\r\n", encoded)
	_, err := s.backendWriter.WriteString(authCmd)
	if err != nil {
		return "", fmt.Errorf("failed to send AUTHENTICATE command: %w", err)
	}
	s.backendWriter.Flush()

	// Read authentication response
	response, err := s.backendReader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read auth response: %w", err)
	}

	if !strings.Contains(response, "A001 OK") {
		return "", fmt.Errorf("backend authentication failed: %s", response)
	}

	log.Printf("[IMAP Proxy] Backend authentication successful for user %s", s.username)

	return strings.TrimRight(response, "\r\n"), nil
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
		if _, err := io.Copy(s.backendConn, s.clientConn); err != nil && !isClosingError(err) {
			log.Printf("[IMAP Proxy] Error copying from client to backend: %v", err)
		}
		s.backendConn.Close()
		s.clientConn.Close()
	}()

	// Backend to client
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(s.clientConn, s.backendConn); err != nil && !isClosingError(err) {
			log.Printf("[IMAP Proxy] Error copying from backend to client: %v", err)
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
			if err := s.server.connTracker.UnregisterConnection(ctx, s.accountID, "IMAP", clientAddr); err != nil {
				log.Printf("[IMAP Proxy] Failed to unregister connection for %s: %v", s.username, err)
			}
		} else {
			if err := s.server.db.UnregisterConnection(ctx, s.accountID, "IMAP", clientAddr); err != nil {
				log.Printf("[IMAP Proxy] Failed to unregister connection for %s: %v", s.username, err)
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
		return s.server.db.RegisterConnection(ctx, s.accountID, "IMAP", clientAddr, s.serverAddr, s.server.hostname)
	}

	return s.server.connTracker.RegisterConnection(ctx, s.accountID, "IMAP", clientAddr, s.serverAddr)
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

		shouldTerminate, err := s.server.connTracker.CheckTermination(checkCtx, s.accountID, "IMAP", clientAddr)
		if err != nil {
			log.Printf("[IMAP Proxy] Failed to check termination for %s: %v", s.username, err)
			return false
		}
		if shouldTerminate {
			log.Printf("[IMAP Proxy] Connection marked for termination, disconnecting: %s", s.username)
			s.clientConn.Close()
			s.backendConn.Close()
			return true
		}
		return false
	}

	for {
		select {
		case <-kickChan:
			log.Printf("[IMAP Proxy] Received kick notification for %s", s.username)
			if checkAndTerminate() {
				return
			}
		case <-activityTicker.C:
			updateCtx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
			if err := s.server.connTracker.UpdateActivity(updateCtx, s.accountID, "IMAP", clientAddr); err != nil {
				log.Printf("[IMAP Proxy] Failed to update activity for %s: %v", s.username, err)
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

			if err := s.server.db.UpdateConnectionActivity(updateCtx, s.accountID, "IMAP", clientAddr); err != nil {
				log.Printf("[IMAP Proxy] Failed to update activity for %s: %v", s.username, err)
			}

			shouldTerminate, err := s.server.db.CheckConnectionTermination(updateCtx, s.accountID, "IMAP", clientAddr)
			if err != nil {
				log.Printf("[IMAP Proxy] Failed to check termination for %s: %v", s.username, err)
			} else if shouldTerminate {
				log.Printf("[IMAP Proxy] Connection marked for termination, disconnecting: %s", s.username)
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
