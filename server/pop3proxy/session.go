package pop3proxy

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

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

type POP3ProxySession struct {
	server             *POP3ProxyServer
	clientConn         net.Conn
	backendConn        net.Conn
	ctx                context.Context
	cancel             context.CancelFunc
	RemoteIP           string
	username           string
	accountID          int64
	isPrelookupAccount bool
	routingInfo        *proxy.UserRoutingInfo
	serverAddr         string
	authenticated      bool
	mutex              sync.Mutex
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
				log.Printf("[POP3 Proxy] client %s dropped connection", s.RemoteIP)
			} else {
				log.Printf("[POP3 Proxy] client %s read error: %v", s.RemoteIP, err)
			}
			return
		}

		line = strings.TrimSpace(line)
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
				log.Printf("[POP3 Proxy] authentication failed for user %s from %s: %v", s.username, s.RemoteIP, err)
				continue
			}

			writer.WriteString("+OK Authentication successful\r\n")
			writer.Flush()

			// Register connection
			if err := s.registerConnection(); err != nil {
				log.Printf("[POP3 Proxy] Failed to register connection for user %s from %s: %v", s.username, s.RemoteIP, err)
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
				log.Printf("[POP3 Proxy] SASL authentication failed for user %s from %s: %v", authnID, s.RemoteIP, err)
				continue
			}

			writer.WriteString("+OK Authentication successful\r\n")
			writer.Flush()

			// Register connection
			if err := s.registerConnection(); err != nil {
				log.Printf("[POP3 Proxy] Failed to register connection for user %s from %s: %v", authnID, s.RemoteIP, err)
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
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()

	remoteAddr := s.clientConn.RemoteAddr()

	// Check if the authentication attempt is allowed by the rate limiter.
	if err := s.server.authLimiter.CanAttemptAuth(ctx, remoteAddr, username); err != nil {
		s.server.authLimiter.RecordAuthAttempt(ctx, remoteAddr, username, false)
		metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "failure").Inc()
		return err
	}

	address, err := server.NewAddress(username)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	// Try prelookup authentication/routing first if configured
	if s.server.connManager.HasRouting() {
		log.Printf("[POP3 Proxy] Attempting authentication for user %s via prelookup", username)
		routingInfo, authResult, err := s.server.connManager.AuthenticateAndRoute(ctx, username, password)

		if err != nil {
			log.Printf("[POP3 Proxy] Prelookup authentication for '%s' failed with an error: %v. Falling back to main DB.", username, err)
			// Fallthrough to main DB auth
		} else {
			switch authResult {
			case proxy.AuthSuccess:
				// Prelookup auth was successful.
				log.Printf("[POP3 Proxy] Prelookup authentication successful for %s, AccountID: %d (prelookup)", username, routingInfo.AccountID)
				s.accountID = routingInfo.AccountID
				s.isPrelookupAccount = routingInfo.IsPrelookupAccount
				s.routingInfo = routingInfo
				s.username = address.FullAddress()
				s.authenticated = true
				s.server.authLimiter.RecordAuthAttempt(ctx, remoteAddr, username, true)
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "success").Inc()
				metrics.TrackDomainConnection("pop3_proxy", address.Domain())
				metrics.TrackUserActivity("pop3_proxy", address.FullAddress(), "connection", 1)

				// Connect to backend
				if err := s.connectToBackend(); err != nil {
					return fmt.Errorf("failed to connect to backend: %w", err)
				}
				return nil // Authentication complete

			case proxy.AuthFailed:
				// User found in prelookup, but password was wrong. Reject immediately.
				log.Printf("[POP3 Proxy] Prelookup authentication failed for user %s from %s (bad password)", username, s.RemoteIP)
				s.server.authLimiter.RecordAuthAttempt(ctx, remoteAddr, username, false)
				metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "failure").Inc()
				return fmt.Errorf("authentication failed")

			case proxy.AuthUserNotFound:
				// User not in prelookup DB. Fallthrough to main DB auth.
				log.Printf("[POP3 Proxy] User '%s' not found in prelookup. Falling back to main DB.", username)
			}
		}
	}

	// Fallback to main DB
	log.Printf("[POP3 Proxy] Authenticating user %s via main database", username)
	accountID, err := s.server.rdb.AuthenticateWithRetry(ctx, address.FullAddress(), password)
	if err != nil {
		s.server.authLimiter.RecordAuthAttempt(ctx, remoteAddr, username, false)
		metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "failure").Inc()
		return fmt.Errorf("authentication failed: %w", err)
	}

	s.server.authLimiter.RecordAuthAttempt(ctx, remoteAddr, username, true)

	// Track successful authentication.
	metrics.AuthenticationAttempts.WithLabelValues("pop3_proxy", "success").Inc()
	metrics.TrackDomainConnection("pop3_proxy", address.Domain())
	metrics.TrackUserActivity("pop3_proxy", address.FullAddress(), "connection", 1)

	// Store user details on the session
	s.authenticated = true
	s.username = address.FullAddress()
	s.accountID = accountID
	s.isPrelookupAccount = false // Authenticated against the main DB

	// Connect to backend
	if err := s.connectToBackend(); err != nil {
		return fmt.Errorf("failed to connect to backend: %w", err)
	}

	return nil
}

// getPreferredBackend fetches the preferred backend server for the user based on affinity.
func (s *POP3ProxySession) getPreferredBackend() (string, error) {
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

func (s *POP3ProxySession) connectToBackend() error {
	var preferredAddr string
	var err error
	// Use s.routingInfo directly. If it's nil from authentication,
	// we'll try to populate it here.
	isPrelookupRoute := false

	// 1. Try routing lookup first, only if not already available from auth
	if s.routingInfo == nil && s.server.connManager.HasRouting() {
		routingCtx, routingCancel := context.WithTimeout(s.ctx, 5*time.Second)
		var lookupErr error
		// Update the session's routingInfo so it's available for later steps.
		s.routingInfo, lookupErr = s.server.connManager.LookupUserRoute(routingCtx, s.username)
		routingCancel()
		if lookupErr != nil {
			log.Printf("[POP3 Proxy] Routing lookup failed for %s: %v, falling back to affinity", s.username, lookupErr)
		}
	}

	if s.routingInfo != nil && s.routingInfo.ServerAddress != "" {
		preferredAddr = s.routingInfo.ServerAddress
		isPrelookupRoute = true
		log.Printf("[POP3 Proxy] Using routing lookup for %s: %s", s.username, preferredAddr)
	}

	// 2. If no routing info, try affinity
	if preferredAddr == "" {
		preferredAddr, err = s.getPreferredBackend()
		if err != nil {
			log.Printf("[POP3 Proxy] Could not get preferred backend for %s: %v", s.username, err)
		}
		if preferredAddr != "" {
			log.Printf("[POP3 Proxy] Using server affinity for %s: %s", s.username, preferredAddr)
		}
	}

	// 3. Apply stickiness to affinity address ONLY. Prelookup routes are absolute.
	if preferredAddr != "" && !isPrelookupRoute && s.server.affinityStickiness < 1.0 {
		if rand.Float64() > s.server.affinityStickiness {
			log.Printf("[POP3 Proxy] Ignoring affinity for %s due to stickiness factor (%.2f), falling back to round-robin", s.username, s.server.affinityStickiness)
			preferredAddr = "" // This will cause the connection manager to use round-robin
		}
	}

	// 4. Connect using the determined address (or round-robin if empty)
	clientHost, clientPort := server.GetHostPortFromAddr(s.clientConn.RemoteAddr())
	serverHost, serverPort := server.GetHostPortFromAddr(s.clientConn.LocalAddr())
	backendConn, actualAddr, err := s.server.connManager.ConnectWithProxy(
		s.ctx,
		preferredAddr,
		clientHost, clientPort, serverHost, serverPort, s.routingInfo,
	)
	if err != nil {
		return fmt.Errorf("failed to connect to backend: %w", err)
	}
	s.backendConn = backendConn
	s.serverAddr = actualAddr

	// Record successful connection for future affinity if enabled
	if s.server.enableAffinity && !s.isPrelookupAccount && actualAddr != "" {
		updateCtx, updateCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer updateCancel()
		if err := s.server.rdb.UpdateLastServerAddressWithRetry(updateCtx, s.accountID, actualAddr); err != nil {
			log.Printf("[POP3 Proxy] Failed to update server affinity for %s: %v", s.username, err)
		} else {
			log.Printf("[POP3 Proxy] Updated server affinity for %s to %s", s.username, actualAddr)
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
			log.Printf("[POP3 Proxy] Failed to send forwarding parameters to backend: %v", err)
			// Continue anyway - forwarding parameters are not critical for functionality
		}
	}

	// Authenticate to backend using master SASL credentials via AUTH PLAIN
	authString := fmt.Sprintf("%s\x00%s\x00%s", s.username, s.server.masterSASLUsername, s.server.masterSASLPassword)
	encoded := base64.StdEncoding.EncodeToString([]byte(authString))

	if _, err := backendWriter.WriteString(fmt.Sprintf("AUTH PLAIN %s\r\n", encoded)); err != nil {
		s.backendConn.Close()
		return fmt.Errorf("failed to send AUTH PLAIN to backend: %w", err)
	}
	if err := backendWriter.Flush(); err != nil {
		s.backendConn.Close()
		return fmt.Errorf("failed to flush AUTH PLAIN to backend: %w", err)
	}

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

	log.Printf("[POP3 Proxy] authenticated to backend as %s", s.username)

	return nil
}

func (s *POP3ProxySession) startProxying() {
	if s.backendConn == nil {
		log.Printf("[POP3 Proxy] backend connection not established for %s", s.username)
		return
	}

	defer s.backendConn.Close()

	log.Printf("[POP3 Proxy] starting bidirectional proxy for %s", s.username)

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
			log.Printf("[POP3 Proxy] error copying backend to client for %s: %v", s.username, err)
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
	log.Printf("[POP3 Proxy] proxy session ended for %s", s.username)
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

		if s.server.connTracker != nil && s.server.connTracker.IsEnabled() {
			if err := s.server.connTracker.UnregisterConnection(ctx, s.accountID, "POP3", s.RemoteIP); err != nil {
				log.Printf("[POP3 Proxy] Failed to unregister connection for %s: %v", s.username, err)
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

	if s.server.connTracker != nil && s.server.connTracker.IsEnabled() {
		return s.server.connTracker.RegisterConnection(ctx, s.accountID, "POP3", s.RemoteIP, s.serverAddr)
	}
	return nil
}

// updateActivityPeriodically updates the connection activity in the database.
func (s *POP3ProxySession) updateActivityPeriodically(ctx context.Context) {
	// If connection tracking is disabled, do nothing and wait for session to end.
	if s.server.connTracker == nil || !s.server.connTracker.IsEnabled() {
		<-ctx.Done()
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
			log.Printf("[POP3 Proxy] Failed to check termination for %s: %v", s.username, err)
			return false
		}
		if shouldTerminate {
			log.Printf("[POP3 Proxy] Connection kicked - disconnecting user: %s (client: %s, backend: %s)", s.username, s.RemoteIP, s.serverAddr)
			s.clientConn.Close()
			s.backendConn.Close()
			return true
		}
		return false
	}

	for {
		select {
		case <-kickChan:
			log.Printf("[POP3 Proxy] Received kick notification for %s", s.username)
			if checkAndTerminate() {
				return
			}
		case <-activityTicker.C:
			updateCtx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
			if err := s.server.connTracker.UpdateActivity(updateCtx, s.accountID, "POP3", s.RemoteIP); err != nil {
				log.Printf("[POP3 Proxy] Failed to update activity for %s: %v", s.username, err)
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
				log.Printf("[POP3 Proxy] error reading from client for %s: %v", s.username, err)
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
				log.Printf("[POP3 Proxy] error writing to backend for %s: %v", s.username, err)
			}
			return
		}

		if err := writer.Flush(); err != nil {
			if !isClosingError(err) {
				log.Printf("[POP3 Proxy] error flushing to backend for %s: %v", s.username, err)
			}
			return
		}
	}
}
