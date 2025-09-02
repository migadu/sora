package managesieve

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/foxcpp/go-sieve"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/server"
)

type ManageSieveSession struct {
	server.Session
	mutex         sync.RWMutex
	mutexHelper   *server.MutexTimeoutHelper
	server        *ManageSieveServer
	conn          *net.Conn          // Connection to the client
	*server.User                     // User associated with the session
	authenticated bool               // Flag to indicate if the user has been authenticated
	ctx           context.Context    // Context for this session
	cancel        context.CancelFunc // Function to cancel the session's context

	reader      *bufio.Reader
	writer      *bufio.Writer
	isTLS       bool
	useMasterDB bool   // Pin session to master DB after a write to ensure consistency
	releaseConn func() // Function to release connection from limiter
}

func (s *ManageSieveSession) sendRawLine(line string) {
	s.writer.WriteString(line + "\r\n")
}

func (s *ManageSieveSession) sendCapabilities() {
	s.sendRawLine(fmt.Sprintf("\"IMPLEMENTATION\" \"%s\"", "ManageSieve"))
	s.sendRawLine("\"SIEVE\" \"fileinto vacation\"")

	if s.server.tlsConfig != nil && s.server.useStartTLS && !s.isTLS {
		s.sendRawLine("\"STARTTLS\"")
	}
	if !s.isTLS && s.server.insecureAuth {
		s.sendRawLine("\"AUTH=PLAIN\"")
	}
	if s.server.maxScriptSize > 0 {
		s.sendRawLine(fmt.Sprintf("\"MAXSCRIPTSIZE\" \"%d\"", s.server.maxScriptSize))
	}
}

func (s *ManageSieveSession) handleConnection() {
	defer s.Close()

	s.sendCapabilitiesGreeting()

	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				s.Log("client dropped connection")
			} else {
				s.Log("read error: %v", err)
			}
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 3)
		command := strings.ToUpper(parts[0])

		switch command {
		case "CAPABILITY":
			s.handleCapability()

		case "LOGIN":
			if len(parts) < 3 {
				s.sendResponse("NO Syntax: LOGIN address password\r\n")
				continue
			}
			userAddress := parts[1]
			password := parts[2]

			address, err := server.NewAddress(userAddress)
			if err != nil {
				s.Log("error: %v", err)
				s.sendResponse("NO Invalid address\r\n")
				continue
			}

			// Apply progressive authentication delay BEFORE any other checks
			remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
			server.ApplyAuthenticationDelay(s.ctx, s.server.authLimiter, remoteAddr, "MANAGESIEVE-LOGIN")

			// Check authentication rate limiting after delay
			if s.server.authLimiter != nil {
				if err := s.server.authLimiter.CanAttemptAuth(s.ctx, remoteAddr, address.FullAddress()); err != nil {
					s.Log("[LOGIN] rate limited: %v", err)
					s.sendResponse("NO Too many authentication attempts. Please try again later.\r\n")
					continue
				}
			}

			// Try master password authentication first
			authSuccess := false
			var userID int64
			if len(s.server.masterSASLUsername) > 0 && len(s.server.masterSASLPassword) > 0 {
				if address.FullAddress() == string(s.server.masterSASLUsername) && password == string(s.server.masterSASLPassword) {
					s.Log("[LOGIN] Master password authentication successful for '%s'", address.FullAddress())
					authSuccess = true
					// For master password, we need to get the user ID
					userID, err = s.server.db.GetAccountIDByAddress(s.ctx, address.FullAddress())
					if err != nil {
						s.Log("[LOGIN] Failed to get account ID for master user '%s': %v", address.FullAddress(), err)
						// Record failed attempt
						if s.server.authLimiter != nil {
							remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
							s.server.authLimiter.RecordAuthAttempt(s.ctx, remoteAddr, address.FullAddress(), false)
						}
						s.sendResponse("NO Authentication failed\r\n")
						continue
					}
				}
			}

			// If master password didn't work, try regular authentication
			if !authSuccess {
				userID, err = s.server.db.Authenticate(s.ctx, address.FullAddress(), password)
				if err != nil {
					// Record failed attempt
					if s.server.authLimiter != nil {
						remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
						s.server.authLimiter.RecordAuthAttempt(s.ctx, remoteAddr, address.FullAddress(), false)
					}
					s.sendResponse("NO Authentication failed\r\n")
					continue
				}
				authSuccess = true
			}

			// Record successful attempt
			if s.server.authLimiter != nil {
				remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
				s.server.authLimiter.RecordAuthAttempt(s.ctx, remoteAddr, address.FullAddress(), true)
			}

			// Acquire write lock for updating session authentication state
			acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
			defer cancel()
			if !acquired {
				s.Log("WARNING: failed to acquire write lock for Login command")
				s.sendResponse("NO Server busy, try again later\r\n")
				continue
			}

			s.authenticated = true
			s.User = server.NewUser(address, userID)
			s.mutex.Unlock()

			// Increment authenticated connections counter
			authCount := s.server.authenticatedConnections.Add(1)
			totalCount := s.server.totalConnections.Load()
			s.Log("user %s authenticated (connections: total=%d, authenticated=%d)",
				address.FullAddress(), totalCount, authCount)
			s.sendResponse("OK Authenticated\r\n")

		case "AUTHENTICATE":
			s.handleAuthenticate(parts)

		case "LISTSCRIPTS":
			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				continue
			}
			s.handleListScripts()

		case "GETSCRIPT":
			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				continue
			}
			if len(parts) < 2 {
				s.sendResponse("NO Syntax: GETSCRIPT scriptName\r\n")
				continue
			}
			scriptName := parts[1]
			s.handleGetScript(scriptName)

		case "PUTSCRIPT":
			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				continue
			}
			if len(parts) < 3 {
				s.sendResponse("NO Syntax: PUTSCRIPT scriptName scriptContent\r\n")
				continue
			}
			scriptName := parts[1]
			scriptContent := parts[2]
			s.handlePutScript(scriptName, scriptContent)

		case "SETACTIVE":
			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				continue
			}
			if len(parts) < 2 {
				s.sendResponse("NO Syntax: SETACTIVE scriptName\r\n")
				continue
			}
			scriptName := parts[1]
			s.handleSetActive(scriptName)

		case "DELETESCRIPT":
			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				continue
			}
			if len(parts) < 2 {
				s.sendResponse("NO Syntax: DELETESCRIPT scriptName\r\n")
				continue
			}
			scriptName := parts[1]
			s.handleDeleteScript(scriptName)

		case "STARTTLS":
			if !s.server.useStartTLS || s.server.tlsConfig == nil {
				s.sendResponse("NO STARTTLS not supported\r\n")
				continue
			}
			if s.isTLS {
				s.sendResponse("NO TLS already active\r\n")
				continue
			}
			s.sendResponse("OK Begin TLS negotiation\r\n")

			// Upgrade the connection to TLS
			tlsConn := tls.Server(*s.conn, s.server.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				s.Log("TLS handshake failed: %v", err)
				s.sendResponse("NO TLS handshake failed\r\n")
				continue
			}

			// Acquire write lock for updating connection state
			acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
			defer cancel()
			if !acquired {
				s.Log("failed to acquire write lock for STARTTLS command")
				s.sendResponse("NO Server busy, try again later\r\n")
				continue
			}

			// Replace the connection and readers/writers
			*s.conn = tlsConn
			s.reader = bufio.NewReader(tlsConn)
			s.writer = bufio.NewWriter(tlsConn)
			s.isTLS = true
			s.mutex.Unlock()

			s.Log("TLS negotiation successful")

		case "NOOP":
			s.sendResponse("OK\r\n")

		case "LOGOUT":
			s.sendResponse("OK Goodbye\r\n")
			s.Close()
			return

		default:
			s.sendResponse("NO Unknown command\r\n")
		}
	}
}

func (s *ManageSieveSession) sendCapabilitiesGreeting() {
	s.sendCapabilities()

	implementationName := "Sora"
	var okMessage string
	// Check if STARTTLS is supported and not yet active for the (STARTTLS) hint in OK response
	if s.server.tlsConfig != nil && s.server.useStartTLS && !s.isTLS {
		okMessage = fmt.Sprintf("OK (STARTTLS) \"%s\" ManageSieve server ready.", implementationName)
	} else {
		okMessage = fmt.Sprintf("OK \"%s\" ManageSieve server ready.", implementationName)
	}
	s.sendRawLine(okMessage)
	s.writer.Flush() // Flush all greeting lines
}

func (s *ManageSieveSession) sendResponse(response string) {
	s.writer.WriteString(response)
	s.writer.Flush()
}

func (s *ManageSieveSession) handleCapability() {
	s.sendCapabilities()
	s.sendRawLine("OK")
	s.writer.Flush()
}

func (s *ManageSieveSession) handleListScripts() {
	// Acquire a read lock only to get the necessary session state.
	// A write lock is not needed for a read-only command.
	acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.Log("WARNING: failed to acquire read lock for ListScripts command")
		s.sendResponse("NO Server busy, try again later\r\n")
		return
	}

	// Copy the necessary state under lock.
	userID := s.UserID()
	useMaster := s.useMasterDB

	// Release the lock before the database call.
	s.mutex.RUnlock()
	cancel()
	// Create a context for read operations that respects session pinning
	readCtx := s.ctx
	if useMaster {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	scripts, err := s.server.db.GetUserScripts(readCtx, userID)
	if err != nil {
		s.sendResponse("NO Internal server error\r\n")
		return
	}

	if len(scripts) == 0 {
		s.sendResponse("OK\r\n")
		return
	}

	for _, script := range scripts {
		line := fmt.Sprintf("\"%s\"", script.Name)
		if script.Active {
			line += " ACTIVE"
		}
		s.sendRawLine(line)
	}
	s.sendRawLine("OK")
	s.writer.Flush()
}

func (s *ManageSieveSession) handleGetScript(name string) {
	// Acquire a read lock only to get the necessary session state.
	acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.Log("WARNING: failed to acquire read lock for GetScript command")
		s.sendResponse("NO Server busy, try again later\r\n")
		return
	}

	// Copy the necessary state under lock.
	userID := s.UserID()
	useMaster := s.useMasterDB

	// Release the lock before the database call.
	s.mutex.RUnlock()
	cancel()

	// Create a context for read operations that respects session pinning
	readCtx := s.ctx
	if useMaster {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	script, err := s.server.db.GetScriptByName(readCtx, name, userID)
	if err != nil {
		s.sendResponse("NO No such script\r\n")
		return
	}
	s.writer.WriteString(fmt.Sprintf("{%d}\r\n", len(script.Script)))
	s.writer.WriteString(script.Script)
	s.writer.Flush()
	s.sendResponse("OK\r\n")
}

func (s *ManageSieveSession) handlePutScript(name, content string) {
	// Acquire write lock for accessing database
	acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
	defer cancel()
	if !acquired {
		s.Log("WARNING: failed to acquire write lock for PutScript command")
		s.sendResponse("NO Server busy, try again later\r\n")
		return
	}
	defer s.mutex.Unlock()

	if s.server.maxScriptSize > 0 && int64(len(content)) > s.server.maxScriptSize {
		s.sendResponse(fmt.Sprintf("NO (MAXSCRIPTSIZE) Script size %d exceeds maximum allowed size %d\r\n", len(content), s.server.maxScriptSize))
		return
	}

	scriptReader := strings.NewReader(content)
	options := sieve.DefaultOptions()
	_, err := sieve.Load(scriptReader, options)
	if err != nil {
		s.sendResponse(fmt.Sprintf("NO Script validation failed: %v\r\n", err))
		return
	}

	// Create a context for read operations that respects session pinning
	readCtx := s.ctx
	if s.useMasterDB {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	script, err := s.server.db.GetScriptByName(readCtx, name, s.UserID())
	if err != nil {
		if err != consts.ErrDBNotFound {
			s.sendResponse("NO Internal server error\r\n")
			return
		}
	}
	if script != nil {
		_, err := s.server.db.UpdateScript(s.ctx, script.ID, s.UserID(), name, content)
		if err != nil {
			s.sendResponse("NO Internal server error\r\n")
			return
		}
		// Pin this session to the master DB to ensure read-your-writes consistency
		s.useMasterDB = true
		s.sendResponse("OK Script updated\r\n")
		return
	}

	_, err = s.server.db.CreateScript(s.ctx, s.UserID(), name, content)
	if err != nil {
		s.sendResponse("NO Internal server error\r\n")
		return
	}
	// Pin this session to the master DB to ensure read-your-writes consistency
	s.useMasterDB = true
	s.sendResponse("OK Script stored\r\n")
}

func (s *ManageSieveSession) handleSetActive(name string) {
	// Acquire write lock for accessing database
	acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
	defer cancel()
	if !acquired {
		s.Log("WARNING: failed to acquire write lock for SetActive command")
		s.sendResponse("NO Server busy, try again later\r\n")
		return
	}
	defer s.mutex.Unlock()

	// Create a context for read operations that respects session pinning
	readCtx := s.ctx
	if s.useMasterDB {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	script, err := s.server.db.GetScriptByName(readCtx, name, s.UserID())
	if err != nil {
		if err == consts.ErrDBNotFound {
			s.sendResponse("NO No such script\r\n")
			return
		}
		s.sendResponse("NO Internal server error\r\n")
		return
	}

	// Validate the script before activating it
	scriptReader := strings.NewReader(script.Script)
	options := sieve.DefaultOptions()
	_, err = sieve.Load(scriptReader, options)
	if err != nil {
		s.sendResponse(fmt.Sprintf("NO Script validation failed: %v\r\n", err))
		return
	}

	err = s.server.db.SetScriptActive(s.ctx, script.ID, s.UserID(), true)
	if err != nil {
		s.sendResponse("NO Internal server error\r\n")
		return
	}

	// Pin this session to the master DB to ensure read-your-writes consistency
	s.useMasterDB = true
	s.sendResponse("OK Script activated\r\n")
}

func (s *ManageSieveSession) handleDeleteScript(name string) {
	// Acquire write lock for accessing database
	acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
	defer cancel()
	if !acquired {
		s.Log("WARNING: failed to acquire write lock for DeleteScript command")
		s.sendResponse("NO Server busy, try again later\r\n")
		return
	}
	defer s.mutex.Unlock()

	// Create a context for read operations that respects session pinning
	readCtx := s.ctx
	if s.useMasterDB {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	script, err := s.server.db.GetScriptByName(readCtx, name, s.UserID())
	if err != nil {
		if err == consts.ErrDBNotFound {
			s.sendResponse("NO No such script\r\n") // RFC uses NO for "No such script"
			return
		}
		s.sendResponse("NO Internal server error\r\n") // RFC uses NO for server errors
		return
	}

	err = s.server.db.DeleteScript(s.ctx, script.ID, s.UserID())
	if err != nil {
		s.sendResponse("NO Internal server error\r\n")
		return
	}
	// Pin this session to the master DB to ensure read-your-writes consistency
	s.useMasterDB = true
	s.sendResponse("OK Script deleted\r\n")
}

func (s *ManageSieveSession) Close() error {
	// Acquire write lock for cleanup
	acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
	defer cancel()
	if !acquired {
		s.Log("WARNING: failed to acquire write lock for Close operation")
		// Continue with close even if we can't get the lock
	} else {
		defer s.mutex.Unlock()
	}

	// Decrement connection counters
	totalCount := s.server.totalConnections.Add(-1)
	var authCount int64 = 0

	(*s.conn).Close()

	// Release connection from limiter
	if s.releaseConn != nil {
		s.releaseConn()
		s.releaseConn = nil // Prevent double release
	}

	if s.User != nil {
		// If authenticated, decrement the authenticated connections counter
		if s.authenticated {
			authCount = s.server.authenticatedConnections.Add(-1)
		} else {
			authCount = s.server.authenticatedConnections.Load()
		}
		s.Log("session closed (connections: total=%d, authenticated=%d)",
			totalCount, authCount)
		s.User = nil
		s.Id = ""
		s.authenticated = false
		if s.cancel != nil {
			s.cancel()
		}
	} else {
		authCount = s.server.authenticatedConnections.Load()
		s.Log("session closed unauthenticated (connections: total=%d, authenticated=%d)",
			totalCount, authCount)
	}
	return nil
}

func (s *ManageSieveSession) handleAuthenticate(parts []string) {
	if len(parts) < 2 {
		s.sendResponse("NO Syntax: AUTHENTICATE mechanism\r\n")
		return
	}

	mechanism := strings.ToUpper(parts[1])
	if mechanism != "PLAIN" {
		s.sendResponse("NO Unsupported authentication mechanism\r\n")
		return
	}

	// Check if initial response is provided
	var authData string
	if len(parts) > 2 {
		// Initial response provided - need to decode from base64
		authData = parts[2]
	} else {
		// No initial response, send continuation
		s.sendResponse("\"\"\r\n")

		// Read the authentication data
		authLine, err := s.reader.ReadString('\n')
		if err != nil {
			s.Log("error reading auth data: %v", err)
			s.sendResponse("NO Authentication failed\r\n")
			return
		}
		authData = strings.TrimSpace(authLine)

		// Check for cancellation
		if authData == "*" {
			s.sendResponse("NO Authentication cancelled\r\n")
			return
		}
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(authData)
	if err != nil {
		s.Log("error decoding auth data: %v", err)
		s.sendResponse("NO Invalid authentication data\r\n")
		return
	}

	// Parse SASL PLAIN format: [authz-id] \0 authn-id \0 password
	parts = strings.Split(string(decoded), "\x00")
	if len(parts) != 3 {
		s.Log("invalid SASL PLAIN format")
		s.sendResponse("NO Invalid authentication format\r\n")
		return
	}

	authzID := parts[0]  // Authorization identity (who to act as)
	authnID := parts[1]  // Authentication identity (who is authenticating)
	password := parts[2] // Password

	s.Log("[SASL PLAIN] AuthorizationID: '%s', AuthenticationID: '%s'", authzID, authnID)

	// Check for Master SASL Authentication
	var userID int64
	var impersonating bool
	var targetAddress *server.Address

	if len(s.server.masterSASLUsername) > 0 && len(s.server.masterSASLPassword) > 0 {
		// Check if this is a master SASL login
		if authnID == string(s.server.masterSASLUsername) && password == string(s.server.masterSASLPassword) {
			// Master SASL authentication successful
			if authzID == "" {
				s.Log("[AUTH] Master SASL authentication for '%s' successful, but no authorization identity provided.", authnID)
				s.sendResponse("NO Master SASL login requires an authorization identity.\r\n")
				return
			}

			s.Log("[AUTH] Master SASL user '%s' authenticated. Attempting to impersonate '%s'.", authnID, authzID)

			// Log in as the authzID without a password check
			address, err := server.NewAddress(authzID)
			if err != nil {
				s.Log("[AUTH] Failed to parse impersonation target user '%s': %v", authzID, err)
				s.sendResponse("NO Invalid impersonation target user format\r\n")
				return
			}

			userID, err = s.server.db.GetAccountIDByAddress(s.ctx, address.FullAddress())
			if err != nil {
				s.Log("[AUTH] Failed to get account ID for impersonation target user '%s': %v", authzID, err)
				s.sendResponse("NO Impersonation target user not found\r\n")
				return
			}

			targetAddress = &address
			impersonating = true
		}
	}

	// If not using master SASL, perform regular authentication
	if !impersonating {
		// For regular ManageSieve, we don't support proxy authentication
		if authzID != "" && authzID != authnID {
			s.Log("proxy authentication not supported: authz='%s', authn='%s'", authzID, authnID)
			s.sendResponse("NO Proxy authentication not supported\r\n")
			return
		}

		// Authenticate the user
		address, err := server.NewAddress(authnID)
		if err != nil {
			s.Log("invalid address format: %v", err)
			s.sendResponse("NO Invalid username format\r\n")
			return
		}

		s.Log("authentication attempt for %s", address.FullAddress())

		// Apply progressive authentication delay BEFORE any other checks
		remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
		server.ApplyAuthenticationDelay(s.ctx, s.server.authLimiter, remoteAddr, "MANAGESIEVE-SASL")

		// Check authentication rate limiting after delay
		if s.server.authLimiter != nil {
			if err := s.server.authLimiter.CanAttemptAuth(s.ctx, remoteAddr, address.FullAddress()); err != nil {
				s.Log("[SASL PLAIN] rate limited: %v", err)
				s.sendResponse("NO Too many authentication attempts. Please try again later.\r\n")
				return
			}
		}

		userID, err = s.server.db.Authenticate(s.ctx, address.FullAddress(), password)
		if err != nil {
			// Record failed attempt
			if s.server.authLimiter != nil {
				remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
				s.server.authLimiter.RecordAuthAttempt(s.ctx, remoteAddr, address.FullAddress(), false)
			}
			s.sendResponse("NO Authentication failed\r\n")
			s.Log("authentication failed")
			return
		}

		// Record successful attempt
		if s.server.authLimiter != nil {
			remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
			s.server.authLimiter.RecordAuthAttempt(s.ctx, remoteAddr, address.FullAddress(), true)
		}

		targetAddress = &address
	}

	// Acquire write lock for updating session authentication state
	acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
	defer cancel()
	if !acquired {
		s.Log("WARNING: failed to acquire write lock for Authenticate command")
		s.sendResponse("NO Server busy, try again later\r\n")
		return
	}

	s.authenticated = true
	s.User = server.NewUser(*targetAddress, userID)
	s.mutex.Unlock()

	// Increment authenticated connections counter
	authCount := s.server.authenticatedConnections.Add(1)
	totalCount := s.server.totalConnections.Load()
	if impersonating {
		s.Log("authenticated via Master SASL PLAIN as '%s' (connections: total=%d, authenticated=%d)",
			targetAddress.FullAddress(), totalCount, authCount)
	} else {
		s.Log("authenticated via SASL PLAIN (connections: total=%d, authenticated=%d)",
			totalCount, authCount)
	}

	s.sendResponse("OK Authenticated\r\n")
}
