package pop3

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
)

const Pop3MaxErrorsAllowed = 3          // Maximum number of errors tolerated before the connection is terminated
const Pop3ErrorDelay = 3 * time.Second  // Wait for this many seconds before allowing another command
const Pop3IdleTimeout = 5 * time.Minute // Maximum duration of inactivity before the connection is closed

type POP3Session struct {
	server.Session
	server         *POP3Server
	conn           *net.Conn    // Connection to the client
	mutex          sync.RWMutex // Mutex for protecting session state
	mutexHelper    *server.MutexTimeoutHelper
	authenticated  bool               // Flag to indicate if the user has been authenticated
	messages       []db.Message       // List of messages in the mailbox as returned by the LIST command
	deleted        map[int]bool       // Map of message IDs marked for deletion
	inboxMailboxID int64              // POP3 suppots only INBOX
	ctx            context.Context    // Context for this session
	cancel         context.CancelFunc // Function to cancel the session's context
	errorsCount    int                // Number of errors encountered during the session
	language       string             // Current language for responses (default "en")
	utf8Mode       bool               // UTF8 mode enabled for this session
	releaseConn    func()             // Function to release connection from limiter
	useMasterDB    bool               // Pin session to master DB after a write to ensure consistency
	startTime      time.Time
	memTracker     *server.SessionMemoryTracker // Memory usage tracker for this session
}

func (s *POP3Session) handleConnection() {
	defer s.cancel()

	defer s.Close()

	// Perform TLS handshake if this is a TLS connection
	if tlsConn, ok := (*s.conn).(interface{ PerformHandshake() error }); ok {
		if err := tlsConn.PerformHandshake(); err != nil {
			s.WarnLog("tls handshake failed", "error", err)
			return
		}
	}

	reader := bufio.NewReader(*s.conn)
	writer := bufio.NewWriter(*s.conn)

	writer.WriteString("+OK POP3 server ready\r\n")
	writer.Flush()

	s.InfoLog("connected")

	ctx := s.ctx
	var userAddress *server.Address

	for {
		// Set idle timeout for reading command
		// During pre-auth phase: use auth_idle_timeout (if configured), otherwise use command_timeout
		// After authentication: use command_timeout
		if !s.authenticated && s.server.authIdleTimeout > 0 {
			(*s.conn).SetReadDeadline(time.Now().Add(s.server.authIdleTimeout))
		} else if s.server.commandTimeout > 0 {
			(*s.conn).SetReadDeadline(time.Now().Add(s.server.commandTimeout))
		} else {
			(*s.conn).SetReadDeadline(time.Time{}) // No timeout
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				writer.WriteString("-ERR Connection timed out due to inactivity\r\n")
				writer.Flush()
				s.WarnLog("connection timed out without quit, messages not expunged")
			} else if err == io.EOF {
				// Client closed connection without QUIT
				s.WarnLog("client dropped connection without quit, messages not expunged")
			} else {
				s.DebugLog("read error", "error", err)
			}
			return
		}

		line = strings.TrimSpace(line)

		// Skip empty commands
		if line == "" {
			continue
		}

		parts := strings.Split(line, " ")
		cmd := strings.ToUpper(parts[0])

		s.DebugLog("client command", "command", helpers.MaskSensitive(line, cmd, "PASS", "AUTH"))

		// Set command execution deadline
		// Clear any previous deadline, then set command timeout
		commandDeadline := time.Time{} // Zero time means no deadline
		if s.server.commandTimeout > 0 {
			commandDeadline = time.Now().Add(s.server.commandTimeout)
		}
		(*s.conn).SetDeadline(commandDeadline)

		switch cmd {
		case "CAPA":
			start := time.Now()
			success := false
			defer func() {
				status := "failure"
				if success {
					status = "success"
				}
				metrics.CommandsTotal.WithLabelValues("pop3", "CAPA", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "CAPA").Observe(time.Since(start).Seconds())
			}()

			// CAPA command - list server capabilities
			writer.WriteString("+OK Capability list follows\r\n")
			writer.WriteString("TOP\r\n")
			writer.WriteString("UIDL\r\n")
			writer.WriteString("USER\r\n")
			writer.WriteString("RESP-CODES\r\n")
			writer.WriteString("EXPIRE NEVER\r\n")
			writer.WriteString(fmt.Sprintf("LOGIN-DELAY %d\r\n", int(Pop3ErrorDelay.Seconds())))
			writer.WriteString("AUTH-RESP-CODE\r\n")
			writer.WriteString("SASL PLAIN\r\n")
			writer.WriteString("LANG\r\n")
			writer.WriteString("UTF8\r\n")
			writer.WriteString("IMPLEMENTATION Sora-POP3-Server\r\n")
			writer.WriteString(".\r\n")
			success = true

		case "USER":
			start := time.Now()
			success := false
			defer func() {
				status := "failure"
				if success {
					status = "success"
				}
				metrics.CommandsTotal.WithLabelValues("pop3", "USER", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "USER").Observe(time.Since(start).Seconds())
			}()

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting user command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			isAuthenticated := s.authenticated
			release()

			if isAuthenticated {
				if s.handleClientError(writer, "-ERR Already authenticated\r\n") {
					// Close the connection if too many errors are encountered
					return
				}
				continue
			}

			// We will only accept email addresses as address
			// Remove quotes if present for compatibility
			username := server.UnquoteString(parts[1])
			newUserAddress, err := server.NewAddress(username)
			if err != nil {
				s.DebugLog("invalid username format", "error", err)
				if s.handleClientError(writer, fmt.Sprintf("-ERR %s\r\n", err.Error())) {
					return
				}
				continue
			}
			userAddress = &newUserAddress
			writer.WriteString("+OK User accepted\r\n")
			success = true

		case "PASS":
			start := time.Now()
			success := false
			defer func() {
				status := "failure"
				if success {
					status = "success"
				}
				metrics.CommandsTotal.WithLabelValues("pop3", "PASS", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "PASS").Observe(time.Since(start).Seconds())
			}()

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting pass command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}
			isAuthenticated := s.authenticated
			release()

			if isAuthenticated {
				if s.handleClientError(writer, "-ERR Already authenticated\r\n") {
					return
				}
				continue
			}

			if userAddress == nil {
				s.DebugLog("pass without user")
				writer.WriteString("-ERR Must provide USER first\r\n")
				writer.Flush()
				continue
			}

			s.DebugLog("authentication attempt", "address", userAddress.FullAddress())

			// Remove quotes from password if present for compatibility
			password := server.UnquoteString(parts[1])

			// Reject empty passwords immediately - no rate limiting needed
			// Empty passwords are never valid under any condition
			if password == "" {
				if s.handleClientError(writer, "-ERR Authentication failed\r\n") {
					return
				}
				continue
			}

			// Get connection and proxy info for rate limiting
			netConn := *s.conn
			var proxyInfo *server.ProxyProtocolInfo
			if s.ProxyIP != "" {
				proxyInfo = &server.ProxyProtocolInfo{
					SrcIP: s.RemoteIP,
				}
			}

			// Apply progressive authentication delay BEFORE any other checks
			remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
			server.ApplyAuthenticationDelay(ctx, s.server.authLimiter, remoteAddr, "POP3-PASS")

			// Check authentication rate limiting after delay
			if s.server.authLimiter != nil {
				if err := s.server.authLimiter.CanAttemptAuthWithProxy(ctx, netConn, proxyInfo, userAddress.FullAddress()); err != nil {
					// Check if this is a rate limit error
					var rateLimitErr *server.RateLimitError
					if errors.As(err, &rateLimitErr) {
						logger.Info("POP3: Rate limit exceeded",
							"address", userAddress.FullAddress(),
							"ip", rateLimitErr.IP,
							"reason", rateLimitErr.Reason,
							"failure_count", rateLimitErr.FailureCount,
							"blocked_until", rateLimitErr.BlockedUntil.Format(time.RFC3339))

						// Track rate limiting
						metrics.AuthenticationAttempts.WithLabelValues("pop3", "rate_limited").Inc()
					} else {
						s.DebugLog("[PASS] rate limited", "error", err)
						metrics.AuthenticationAttempts.WithLabelValues("pop3", "rate_limited").Inc()
					}

					if s.handleClientError(writer, "-ERR [LOGIN-DELAY] Too many authentication attempts. Please try again later.\r\n") {
						return
					}
					continue
				}
			}

			// Master username authentication: user@domain.com@MASTER_USERNAME
			// Check if suffix matches configured MasterUsername
			authSuccess := false
			masterAuthUsed := false
			var accountID int64
			if len(s.server.masterUsername) > 0 && userAddress.HasSuffix() && checkMasterCredential(userAddress.Suffix(), s.server.masterUsername) {
				// Suffix matches MasterUsername, authenticate with MasterPassword
				if checkMasterCredential(password, s.server.masterPassword) {
					s.DebugLog("master username authentication successful", "base_address", userAddress.BaseAddress(), "master_username", userAddress.Suffix())
					authSuccess = true
					masterAuthUsed = true
					// Use base address (without suffix) to get account
					accountID, err = s.server.rdb.GetAccountIDByAddressWithRetry(ctx, userAddress.BaseAddress())
					if err != nil {
						s.DebugLog("failed to get account id for user", "base_address", userAddress.BaseAddress(), "error", err)
						// Record failed attempt
						if s.server.authLimiter != nil {
							s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, userAddress.BaseAddress(), false)
						}
						if s.handleClientError(writer, "-ERR [AUTH] Authentication failed\r\n") {
							s.DebugLog("authentication failed")
							return
						}
						continue
					}
				} else {
					// Record failed master password authentication
					metrics.AuthenticationAttempts.WithLabelValues("pop3", "failure").Inc()
					if s.server.authLimiter != nil {
						s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, userAddress.BaseAddress(), false)
					}

					// Master username suffix was provided but master password was wrong - fail immediately
					if s.handleClientError(writer, "-ERR [AUTH] Invalid master credentials\r\n") {
						s.DebugLog("authentication failed, invalid master credentials")
						return
					}
					continue
				}
			}

			// Try master SASL password authentication (traditional)
			if !authSuccess && len(s.server.masterSASLUsername) > 0 && len(s.server.masterSASLPassword) > 0 {
				if userAddress.BaseAddress() == string(s.server.masterSASLUsername) && password == string(s.server.masterSASLPassword) {
					s.DebugLog("master sasl password authentication successful", "base_address", userAddress.BaseAddress())
					authSuccess = true
					masterAuthUsed = true
					// For master password, we need to get the user ID
					accountID, err = s.server.rdb.GetAccountIDByAddressWithRetry(ctx, userAddress.BaseAddress())
					if err != nil {
						s.DebugLog("failed to get account id for master user", "base_address", userAddress.BaseAddress(), "error", err)
						// Record failed attempt
						if s.server.authLimiter != nil {
							s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, userAddress.BaseAddress(), false)
						}
						if s.handleClientError(writer, "-ERR [AUTH] Authentication failed\r\n") {
							s.DebugLog("authentication failed")
							return
						}
						continue
					}
				}
			}

			// If master password didn't work, try regular authentication
			if !authSuccess {
				// Use base address (without +detail) for authentication
				accountID, err = s.server.Authenticate(ctx, userAddress.BaseAddress(), password)
				if err != nil {
					// Check if error is due to context cancellation (server shutdown)
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						s.InfoLog("authentication cancelled due to server shutdown")
						metrics.CriticalOperationDuration.WithLabelValues("pop3_authentication").Observe(time.Since(start).Seconds())
						if s.handleClientError(writer, "-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n") {
							return
						}
						continue
					}

					// Record failed attempt
					if s.server.authLimiter != nil {
						s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, userAddress.FullAddress(), false)
					}
					// Track failed authentication
					metrics.AuthenticationAttempts.WithLabelValues("pop3", "failure").Inc()
					metrics.CriticalOperationDuration.WithLabelValues("pop3_authentication").Observe(time.Since(start).Seconds())
					if s.handleClientError(writer, "-ERR [AUTH] Authentication failed\r\n") {
						s.DebugLog("authentication failed")
						return
					}
					continue
				}
				authSuccess = true
			}

			// Record successful attempt
			if s.server.authLimiter != nil {
				s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, userAddress.FullAddress(), true)
			}

			// This is a potential write operation.
			// Ensure default mailboxes (INBOX/Drafts/Sent/Spam/Trash) exist
			err = s.server.rdb.CreateDefaultMailboxesWithRetry(ctx, accountID)
			if err != nil {
				s.DebugLog("error creating default mailboxes", "error", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}
			// Create a context that signals to the DB layer to use the master connection.
			// We will set useMasterDB later under the write lock.
			readCtx := context.WithValue(ctx, consts.UseMasterDBKey, true)

			inboxMailboxID, err := s.server.rdb.GetMailboxByNameWithRetry(readCtx, accountID, consts.MailboxInbox)
			if err != nil {
				s.DebugLog("error getting inbox", "error", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}

			// Acquire write lock to update session state
			acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.WarnLog(" failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			s.inboxMailboxID = inboxMailboxID.ID
			s.authenticated = true
			s.User = server.NewUser(*userAddress, accountID) // Initialize User for connection tracking
			s.deleted = make(map[int]bool)                   // Initialize deletion map on authentication
			s.useMasterDB = true                             // Pin session to master DB after a write to ensure consistency
			release()

			s.server.authenticatedConnections.Add(1)

			// Log authentication success
			// Note: Regular auth via Authenticate() already logs in server.go with cached/method
			// For master password auth, we log here with method=master
			if masterAuthUsed {
				duration := time.Since(start)
				s.InfoLog("authentication successful", "address", userAddress.BaseAddress(), "account_id", accountID, "cached", false, "method", "master", "duration", fmt.Sprintf("%.3fs", duration.Seconds()))
			}

			// Track successful authentication
			metrics.AuthenticatedConnectionsCurrent.WithLabelValues("pop3").Inc()
			metrics.CriticalOperationDuration.WithLabelValues("pop3_authentication").Observe(time.Since(start).Seconds())

			// Track domain and user connection activity
			if s.User != nil {
				metrics.TrackDomainConnection("pop3", s.Domain())
				metrics.TrackUserActivity("pop3", s.FullAddress(), "connection", 1)
			}

			// Register connection for tracking
			s.registerConnection(userAddress.FullAddress())

			// Start termination poller to check for kick commands
			s.startTerminationPoller()

			writer.WriteString("+OK Password accepted\r\n")
			success = true

		case "STAT":
			start := time.Now()
			success := false
			defer func() {
				status := "failure"
				if success {
					status = "success"
				}
				metrics.CommandsTotal.WithLabelValues("pop3", "STAT", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "STAT").Observe(time.Since(start).Seconds())
			}()

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting stat command")
				return
			}

			// Acquire read lock to check inbox mailbox ID
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			// Create a context for read operations that respects session pinning
			readCtx := ctx
			if s.useMasterDB {
				readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
			}

			mailboxID := s.inboxMailboxID
			release()
			messagesCount, size, err := s.server.rdb.GetMailboxMessageCountAndSizeSumWithRetry(readCtx, mailboxID)
			if err != nil {
				s.DebugLog("stat error", "error", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}
			writer.WriteString(fmt.Sprintf("+OK %d %d\r\n", messagesCount, size))
			success = true

		case "LIST":
			start := time.Now()
			success := false
			defer func() {
				status := "failure"
				if success {
					status = "success"
				}
				metrics.CommandsTotal.WithLabelValues("pop3", "LIST", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "LIST").Observe(time.Since(start).Seconds())
			}()

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting list command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}
			isAuthenticated := s.authenticated
			mailboxID := s.inboxMailboxID
			useMasterDB := s.useMasterDB
			release()

			if !isAuthenticated {
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
			}

			// Create a context for read operations that respects session pinning
			readCtx := ctx
			if useMasterDB {
				readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
			}

			messages, err := s.server.rdb.ListMessagesWithRetry(readCtx, mailboxID)
			if err != nil {
				s.DebugLog("list error", "error", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}

			// Acquire write lock to update session state and read the data
			acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}
			s.messages = messages
			s.DebugLog("loaded messages from database", "count", len(messages), "mailbox_id", mailboxID)

			// Copy the data needed for the response.
			type listInfo struct {
				size int64
			}
			var responseData []listInfo
			for i, msg := range s.messages {
				if !s.deleted[i] {
					responseData = append(responseData, listInfo{size: int64(msg.Size)})
				}
			}
			release() // Release lock before I/O.

			// Phase 4: Build and send response outside the lock.
			writer.WriteString(fmt.Sprintf("+OK %d messages\r\n", len(responseData)))
			if len(responseData) > 0 {
				for i, info := range responseData {
					writer.WriteString(fmt.Sprintf("%d %d\r\n", i+1, info.size))
				}
			}
			writer.WriteString(".\r\n")
			s.DebugLog("listed messages", "count", len(s.messages))

			success = true

		case "UIDL":
			start := time.Now()
			success := false
			defer func() {
				status := "failure"
				if success {
					status = "success"
				}
				metrics.CommandsTotal.WithLabelValues("pop3", "UIDL", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "UIDL").Observe(time.Since(start).Seconds())
			}()

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting uidl command")
				return
			}

			// Acquire read lock to check authentication state and loading needs
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}
			isAuthenticated := s.authenticated
			mailboxID := s.inboxMailboxID
			needsLoading := (s.messages == nil)
			useMasterDB := s.useMasterDB
			release()

			if !isAuthenticated {
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
			}

			if needsLoading {
				// Create a context for read operations that respects session pinning
				readCtx := ctx
				if useMasterDB {
					readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
				}
				messages, err := s.server.rdb.ListMessagesWithRetry(readCtx, mailboxID)
				if err != nil {
					s.DebugLog("uidl error", "error", err)
					writer.WriteString("-ERR Internal server error\r\n")
					writer.Flush()
					continue
				}

				// Acquire write lock to update session state
				acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
				if !acquired {
					s.WarnLog("failed to acquire write lock within timeout")
					writer.WriteString("-ERR Server busy, please try again\r\n")
					writer.Flush()
					continue
				}
				s.messages = messages
				release()
			}

			// Handle UIDL with message number argument
			if len(parts) > 1 {
				msgNumber, err := strconv.Atoi(parts[1])
				if err != nil || msgNumber < 1 {
					if s.handleClientError(writer, "-ERR Invalid message number\r\n") {
						return
					}
					continue
				}

				// Acquire read lock to access messages
				acquired, release = s.mutexHelper.AcquireReadLockWithTimeout()
				if !acquired {
					s.WarnLog("failed to acquire read lock within timeout")
					writer.WriteString("-ERR Server busy, please try again\r\n")
					writer.Flush()
					continue
				}

				if msgNumber > len(s.messages) {
					release()
					if s.handleClientError(writer, "-ERR No such message\r\n") {
						return
					}
					continue
				}

				msg := s.messages[msgNumber-1]
				if s.deleted[msgNumber-1] {
					release()
					if s.handleClientError(writer, "-ERR Message is deleted\r\n") {
						return
					}
					continue
				}

				// Use UID as the unique identifier (more reliable than ContentHash)
				release()
				writer.WriteString(fmt.Sprintf("+OK %d %d\r\n", msgNumber, msg.UID))
			} else {
				// UIDL without arguments - list all messages
				// Acquire read lock to access messages and deleted status
				acquired, release = s.mutexHelper.AcquireReadLockWithTimeout()
				if !acquired {
					s.WarnLog("failed to acquire read lock within timeout")
					writer.WriteString("-ERR Server busy, please try again\r\n")
					writer.Flush()
					continue
				}

				// Copy the data needed for the response.
				type uidlInfo struct {
					uid imap.UID
				}
				var responseData []uidlInfo
				for i, msg := range s.messages {
					if !s.deleted[i] {
						responseData = append(responseData, uidlInfo{uid: msg.UID})
					}
				}
				release() // Release lock before I/O.

				// Phase 4: Build and send response outside the lock.
				writer.WriteString(fmt.Sprintf("+OK %d messages\r\n", len(responseData)))
				if len(responseData) > 0 {
					for i, info := range responseData {
						writer.WriteString(fmt.Sprintf("%d %d\r\n", i+1, info.uid))
					}
				}
				writer.WriteString(".\r\n")
			}
			s.DebugLog("uidl command executed")
			success = true

		case "TOP":
			start := time.Now()
			success := false
			defer func() {
				status := "failure"
				if success {
					status = "success"
				}
				metrics.CommandsTotal.WithLabelValues("pop3", "TOP", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "TOP").Observe(time.Since(start).Seconds())
			}()

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting top command")
				return
			}

			if len(parts) < 3 {
				if s.handleClientError(writer, "-ERR Missing message number or lines parameter\r\n") {
					return
				}
				continue
			}

			msgNumber, err := strconv.Atoi(parts[1])
			if err != nil || msgNumber < 1 {
				if s.handleClientError(writer, "-ERR Invalid message number\r\n") {
					return
				}
				continue
			}

			lines, err := strconv.Atoi(parts[2])
			if err != nil || lines < 0 {
				if s.handleClientError(writer, "-ERR Invalid lines parameter\r\n") {
					return
				}
				continue
			}

			// Phase 1: Read session state to determine if messages need loading.
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}
			isAuthenticated := s.authenticated
			mailboxID := s.inboxMailboxID
			needsLoading := (s.messages == nil)
			release()

			if !isAuthenticated {
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
			}

			// Phase 2: Load messages if needed (outside of any lock).
			var loadedMessages []db.Message
			if needsLoading {
				// Create a context for read operations that respects session pinning
				readCtx := ctx
				if s.useMasterDB {
					readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
				}
				loadedMessages, err = s.server.rdb.ListMessagesWithRetry(readCtx, mailboxID)
				if err != nil {
					s.DebugLog("top error", "error", err)
					writer.WriteString("-ERR Internal server error\r\n")
					writer.Flush()
					continue
				}
			}

			// Phase 3: Acquire lock to check message state and get a copy of the message.
			var msg db.Message
			var isDeleted bool
			var msgFound = false

			// Use a write lock if we need to update the messages slice.
			if needsLoading {
				acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
			} else {
				acquired, release = s.mutexHelper.AcquireReadLockWithTimeout()
			}

			if !acquired {
				s.WarnLog("failed to acquire lock for top command")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			// If we loaded messages, update the session state.
			if needsLoading {
				s.messages = loadedMessages
				s.DebugLog("loaded messages from database", "count", len(s.messages), "mailbox_id", mailboxID)
			}

			// Now check message bounds and status under the lock.
			if msgNumber > len(s.messages) {
				// msgFound remains false
			} else {
				msg = s.messages[msgNumber-1]
				isDeleted = s.deleted[msgNumber-1]
				msgFound = true
			}
			release() // Release the lock before I/O.

			// Phase 4: Handle message retrieval and response outside the lock.
			if !msgFound {
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			if isDeleted {
				if s.handleClientError(writer, "-ERR Message is deleted\r\n") {
					return
				}
				continue
			}

			if msg.UID == 0 {
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			logger.Debug("POP3: Fetching message headers", "uid", msg.UID)
			bodyData, err := s.getMessageBody(&msg)
			if err != nil {
				if err == consts.ErrMessageNotAvailable {
					writer.WriteString("-ERR Message not available\r\n")
				} else {
					s.DebugLog("top internal error", "error", err)
					writer.WriteString("-ERR Internal server error\r\n")
				}
				writer.Flush()
				continue
			}

			// Normalize line endings for consistent processing
			messageStr := string(bodyData)
			messageStr = strings.ReplaceAll(messageStr, "\r\n", "\n") // Normalize to LF

			// Find header/body separator
			headerEndIndex := strings.Index(messageStr, "\n\n")
			if headerEndIndex == -1 {
				// Message has no body, just headers
				// Convert back to CRLF for POP3 protocol
				result := strings.ReplaceAll(messageStr, "\n", "\r\n")
				// Dot-stuff per RFC 1939
				stuffedResult := dotStuffPOP3(result)
				writer.WriteString(fmt.Sprintf("+OK %d octets\r\n", len(result)))
				writer.WriteString(stuffedResult)
				writer.WriteString("\r\n.\r\n")
				s.DebugLog("retrieved headers for message", "uid", msg.UID)
				// Free memory immediately after sending response
				if s.memTracker != nil && bodyData != nil {
					s.memTracker.Free(int64(len(bodyData)))
				}
				continue
			}

			// Extract headers
			headers := messageStr[:headerEndIndex]

			// Extract body lines if requested
			var result string
			if lines > 0 {
				bodyStart := headerEndIndex + 2 // Skip \n\n
				if bodyStart < len(messageStr) {
					bodyPart := messageStr[bodyStart:]
					bodyLines := strings.Split(bodyPart, "\n")

					// Take only the requested number of lines
					numLines := lines
					if numLines > len(bodyLines) {
						numLines = len(bodyLines)
					}

					selectedLines := bodyLines[:numLines]
					bodySnippet := strings.Join(selectedLines, "\n")

					result = headers + "\n\n" + bodySnippet
				} else {
					result = headers + "\n\n"
				}
			} else {
				result = headers + "\n\n"
			}

			// Convert back to CRLF for POP3 protocol
			result = strings.ReplaceAll(result, "\n", "\r\n")

			// Dot-stuff per RFC 1939
			stuffedResult := dotStuffPOP3(result)
			writer.WriteString(fmt.Sprintf("+OK %d octets\r\n", len(result)))
			writer.WriteString(stuffedResult)
			writer.WriteString("\r\n.\r\n")
			s.DebugLog("retrieved top lines of message", "lines", lines, "uid", msg.UID)

			// Free memory immediately after sending response
			if s.memTracker != nil && bodyData != nil {
				s.memTracker.Free(int64(len(bodyData)))
			}
			success = true

		case "RETR":
			retrieveStart := time.Now()
			success := false
			defer func() {
				status := "failure"
				if success {
					status = "success"
				}
				metrics.CommandsTotal.WithLabelValues("pop3", "RETR", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "RETR").Observe(time.Since(retrieveStart).Seconds())
			}()

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting retr command")
				return
			}

			// Phase 1: Read session state to determine if messages need loading.
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}
			isAuthenticated := s.authenticated
			mailboxID := s.inboxMailboxID
			needsLoading := (s.messages == nil)
			release()

			if !isAuthenticated {
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
			}

			if len(parts) < 2 {
				if s.handleClientError(writer, "-ERR Missing message number\r\n") {
					return
				}
				continue
			}

			msgNumber, err := strconv.Atoi(parts[1])
			if err != nil || msgNumber < 1 {
				if s.handleClientError(writer, "-ERR Invalid message number\r\n") {
					return
				}
				continue
			}

			// Phase 2: Load messages if needed (outside of any lock).
			var loadedMessages []db.Message
			if needsLoading {
				readCtx := ctx
				if s.useMasterDB {
					readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
				}
				loadedMessages, err = s.server.rdb.ListMessagesWithRetry(readCtx, mailboxID)
				if err != nil {
					s.DebugLog("retr error", "error", err)
					writer.WriteString("-ERR Internal server error\r\n")
					writer.Flush()
					continue
				}
			}

			// Phase 3: Acquire lock to check message state and get a copy of the message.
			var msg db.Message
			var isDeleted bool
			var msgFound = false

			if needsLoading {
				acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
			} else {
				acquired, release = s.mutexHelper.AcquireReadLockWithTimeout()
			}

			if !acquired {
				s.WarnLog("failed to acquire lock for retr command")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			if needsLoading {
				s.messages = loadedMessages
				s.DebugLog("loaded messages from database", "count", len(s.messages), "mailbox_id", mailboxID)
			}

			if msgNumber > len(s.messages) {
				// msgFound remains false
			} else {
				msg = s.messages[msgNumber-1]
				isDeleted = s.deleted[msgNumber-1]
				msgFound = true
			}
			release() // Release lock before I/O.

			// Phase 4: Handle message retrieval and response outside the lock.
			if !msgFound {
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			if isDeleted {
				if s.handleClientError(writer, "-ERR Message is deleted\r\n") {
					return
				}
				continue
			}

			if msg.UID == 0 {
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			logger.Debug("POP3: Fetching message body", "uid", msg.UID)
			bodyData, err := s.getMessageBody(&msg)
			if err != nil {
				if err == consts.ErrMessageNotAvailable {
					writer.WriteString("-ERR Message not available\r\n")
				} else {
					s.DebugLog("retr internal error", "error", err)
					writer.WriteString("-ERR Internal server error\r\n")
				}
				writer.Flush()
				continue
			}
			s.DebugLog("retrieved message body", "uid", msg.UID)

			// Validate body data to prevent empty line protocol violations
			if len(bodyData) == 0 {
				s.WarnLog("empty message body", "uid", msg.UID, "expected_size", msg.Size)
				// Free memory before error handling
				if s.memTracker != nil {
					s.memTracker.Free(int64(len(bodyData)))
				}
				if s.handleClientError(writer, "-ERR Message body is empty\r\n") {
					return
				}
				continue
			}

			// Warn if body size mismatch indicates corruption or incomplete fetch
			if len(bodyData) != msg.Size {
				s.WarnLog("body size mismatch", "uid", msg.UID, "expected", msg.Size, "got", len(bodyData))
			}

			// Dot-stuff the message body per RFC 1939 to prevent premature termination
			stuffedBody := dotStuffPOP3(string(bodyData))
			writer.WriteString(fmt.Sprintf("+OK %d octets\r\n", msg.Size))
			writer.WriteString(stuffedBody)
			writer.WriteString("\r\n.\r\n")
			s.DebugLog("retrieved message", "uid", msg.UID)

			// Free memory immediately after sending response
			if s.memTracker != nil && bodyData != nil {
				s.memTracker.Free(int64(len(bodyData)))
			}

			// Track successful message retrieval
			metrics.MessageThroughput.WithLabelValues("pop3", "retrieved", "success").Inc()
			metrics.BytesThroughput.WithLabelValues("pop3", "out").Add(float64(msg.Size))
			metrics.CriticalOperationDuration.WithLabelValues("pop3_retrieve").Observe(time.Since(retrieveStart).Seconds())

			// Track domain and user activity - RETR is bandwidth intensive!
			if s.User != nil {
				metrics.TrackDomainCommand("pop3", s.Domain(), "RETR")
				metrics.TrackUserActivity("pop3", s.FullAddress(), "command", 1)
				metrics.TrackDomainBytes("pop3", s.Domain(), "out", int64(msg.Size))
				metrics.TrackDomainMessage("pop3", s.Domain(), "fetched")
			}
			success = true

		case "NOOP":
			start := time.Now()
			success := false
			defer func() {
				status := "failure"
				if success {
					status = "success"
				}
				metrics.CommandsTotal.WithLabelValues("pop3", "NOOP", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "NOOP").Observe(time.Since(start).Seconds())
			}()

			writer.WriteString("+OK\r\n")
			success = true

		case "RSET":
			start := time.Now()
			success := false
			defer func() {
				status := "failure"
				if success {
					status = "success"
				}
				metrics.CommandsTotal.WithLabelValues("pop3", "RSET", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "RSET").Observe(time.Since(start).Seconds())
			}()

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting rset command")
				return
			}

			// Acquire write lock to update deleted map
			acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}
			defer release()
			s.deleted = make(map[int]bool)

			writer.WriteString("+OK\r\n")
			s.DebugLog("deleted messages reset")
			success = true

		case "DELE":
			start := time.Now()
			success := false
			defer func() {
				status := "failure"
				if success {
					status = "success"
				}
				metrics.CommandsTotal.WithLabelValues("pop3", "DELE", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "DELE").Observe(time.Since(start).Seconds())
			}()

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting dele command")
				return
			}

			if len(parts) < 2 {
				logger.Debug("missing message number")
				if s.handleClientError(writer, "-ERR Missing message number\r\n") {
					return
				}
				continue
			}

			msgNumber, err := strconv.Atoi(parts[1])
			if err != nil || msgNumber < 1 {
				s.DebugLog("dele invalid message number", "error", err)
				if s.handleClientError(writer, "-ERR Invalid message number\r\n") {
					return
				}
				continue
			}

			// Phase 1: Read session state to determine if messages need loading.
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire read lock for dele command")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}
			isAuthenticated := s.authenticated
			needsLoading := (s.messages == nil)
			mailboxID := s.inboxMailboxID
			release()

			if !isAuthenticated {
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
			}

			// Phase 2: Load messages if needed (outside of any lock).
			var loadedMessages []db.Message
			if needsLoading {
				readCtx := ctx
				if s.useMasterDB {
					readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
				}
				loadedMessages, err = s.server.rdb.ListMessagesWithRetry(readCtx, mailboxID)
				if err != nil {
					s.DebugLog("dele error", "error", err)
					writer.WriteString("-ERR Internal server error\r\n")
					writer.Flush()
					continue
				}
			}

			// Phase 3: Acquire write lock to update session state.
			acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire write lock for dele command")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			// If we loaded messages, update the session state.
			if needsLoading {
				s.messages = loadedMessages
				s.DebugLog("loaded messages from database", "count", len(s.messages), "mailbox_id", mailboxID)
			}

			// Validate message bounds and perform deletion
			if msgNumber > len(s.messages) {
				release()
				s.DebugLog("dele no such message", "msg_number", msgNumber)
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			msg := s.messages[msgNumber-1]
			if msg.UID == 0 {
				release()
				s.DebugLog("dele no such message", "msg_number", msgNumber)
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			s.deleted[msgNumber-1] = true
			release()

			writer.WriteString("+OK Message deleted\r\n")
			s.DebugLog("marked message for deletion", "msg_number", msgNumber, "uid", msg.UID, "mailbox_id", mailboxID, "total_deleted", len(s.deleted))

			metrics.MessageThroughput.WithLabelValues("pop3", "deleted", "success").Inc()
			success = true

		case "AUTH":
			start := time.Now()
			success := false
			defer func() {
				status := "failure"
				if success {
					status = "success"
				}
				metrics.CommandsTotal.WithLabelValues("pop3", "AUTH", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "AUTH").Observe(time.Since(start).Seconds())
			}()

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting auth command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}
			isAuthenticated := s.authenticated
			release()

			if isAuthenticated {
				if s.handleClientError(writer, "-ERR Already authenticated\r\n") {
					return
				}
				continue
			}

			if len(parts) < 2 {
				if s.handleClientError(writer, "-ERR Missing authentication mechanism\r\n") {
					return
				}
				continue
			}

			// Remove quotes from mechanism if present for compatibility
			mechanism := server.UnquoteString(parts[1])
			mechanism = strings.ToUpper(mechanism)
			if mechanism != "PLAIN" {
				if s.handleClientError(writer, "-ERR Unsupported authentication mechanism\r\n") {
					return
				}
				continue
			}

			// Check if initial response is provided
			var authData string
			if len(parts) > 2 {
				// Initial response provided - remove quotes if present
				authData = server.UnquoteString(parts[2])
			} else {
				// Request the authentication data
				writer.WriteString("+ \r\n")
				writer.Flush()

				// Read the authentication data
				authLine, err := reader.ReadString('\n')
				if err != nil {
					s.DebugLog("error reading auth data", "error", err)
					if s.handleClientError(writer, "-ERR Authentication failed\r\n") {
						return
					}
					continue
				}
				authData = strings.TrimSpace(authLine)
				// Remove quotes if present in continuation response
				authData = server.UnquoteString(authData)
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
				s.DebugLog("error decoding auth data", "error", err)
				if s.handleClientError(writer, "-ERR [AUTH] Invalid authentication data\r\n") {
					return
				}
				continue
			}

			// Parse SASL PLAIN format: [authz-id] \0 authn-id \0 password
			parts := strings.Split(string(decoded), "\x00")
			if len(parts) != 3 {
				s.DebugLog("invalid sasl plain format")
				if s.handleClientError(writer, "-ERR [AUTH] Invalid authentication format\r\n") {
					return
				}
				continue
			}

			authzID := parts[0]  // Authorization identity (who to act as)
			authnID := parts[1]  // Authentication identity (who is authenticating)
			password := parts[2] // Password

			s.DebugLog("sasl plain authentication", "authz_id", authzID, "authn_id", authnID)

			// Parse authentication-identity to check for suffix (master username or remotelookup token)
			authnParsed, parseErr := server.NewAddress(authnID)

			var accountID int64
			var impersonating bool

			// 1. Check for Master Username Authentication (user@domain.com@MASTER_USERNAME)
			if parseErr == nil && len(s.server.masterUsername) > 0 && authnParsed.HasSuffix() && checkMasterCredential(authnParsed.Suffix(), s.server.masterUsername) {
				// Suffix matches MasterUsername, authenticate with MasterPassword
				if checkMasterCredential(password, s.server.masterPassword) {
					// Determine target user to impersonate
					targetUserToImpersonate := authzID
					if targetUserToImpersonate == "" {
						// No authorization identity provided, use base address from authnID
						targetUserToImpersonate = authnParsed.BaseAddress()
					}

					s.DebugLog("master username authenticated, attempting impersonation", "master_username", authnParsed.Suffix(), "target_user", targetUserToImpersonate)

					// Parse target user address
					address, err := server.NewAddress(targetUserToImpersonate)
					if err != nil {
						s.DebugLog("failed to parse impersonation target user", "target_user", targetUserToImpersonate, "error", err)
						if s.handleClientError(writer, "-ERR [AUTH] Invalid impersonation target user format\r\n") {
							return
						}
						continue
					}

					accountID, err = s.server.rdb.GetAccountIDByAddressWithRetry(ctx, address.BaseAddress())
					if err != nil {
						s.DebugLog("failed to get account id for impersonation target user", "target_user", targetUserToImpersonate, "error", err)
						if s.handleClientError(writer, "-ERR [AUTH] Impersonation target user not found\r\n") {
							return
						}
						continue
					}

					impersonating = true
				} else {
					// Record failed master password authentication
					metrics.AuthenticationAttempts.WithLabelValues("pop3", "failure").Inc()

					// Master username suffix was provided but master password was wrong - fail immediately
					if s.handleClientError(writer, "-ERR [AUTH] Invalid master credentials\r\n") {
						s.DebugLog("authentication failed, invalid master credentials")
						return
					}
					continue
				}
			}

			// 2. Check for Master SASL Authentication (traditional)
			if !impersonating && len(s.server.masterSASLUsername) > 0 && len(s.server.masterSASLPassword) > 0 {
				// Check if this is a master SASL login
				if authnID == string(s.server.masterSASLUsername) && password == string(s.server.masterSASLPassword) {
					// Master SASL authentication successful
					if authzID == "" {
						s.DebugLog("master sasl authentication successful but no authorization identity provided", "authn_id", authnID)
						if s.handleClientError(writer, "-ERR [AUTH] Master SASL login requires an authorization identity.\r\n") {
							return
						}
						continue
					}

					s.DebugLog("master sasl user authenticated, attempting impersonation", "authn_id", authnID, "authz_id", authzID)

					// Log in as the authzID without a password check
					address, err := server.NewAddress(authzID)
					if err != nil {
						s.DebugLog("failed to parse impersonation target user", "authz_id", authzID, "error", err)
						if s.handleClientError(writer, "-ERR [AUTH] Invalid impersonation target user format\r\n") {
							return
						}
						continue
					}

					accountID, err = s.server.rdb.GetAccountIDByAddressWithRetry(ctx, address.BaseAddress())
					if err != nil {
						s.DebugLog("failed to get account id for impersonation target user", "authz_id", authzID, "error", err)
						if s.handleClientError(writer, "-ERR [AUTH] Impersonation target user not found\r\n") {
							return
						}
						continue
					}

					impersonating = true
				}
			}

			// If not using master SASL, perform regular authentication
			if !impersonating {
				// For regular POP3, we don't support proxy authentication
				if authzID != "" && authzID != authnID {
					s.DebugLog("proxy authentication requires master credentials", "authz_id", authzID, "authn_id", authnID)
					if s.handleClientError(writer, "-ERR [AUTH] Proxy authentication requires master_sasl_username and master_sasl_password to be configured\r\n") {
						return
					}
					continue
				}

				// Authenticate the user
				address, err := server.NewAddress(authnID)
				if err != nil {
					s.DebugLog("invalid address format", "error", err)
					if s.handleClientError(writer, "-ERR [AUTH] Invalid username format\r\n") {
						return
					}
					continue
				}

				s.DebugLog("authentication attempt", "address", address.FullAddress())

				// Get connection and proxy info for rate limiting
				netConn := *s.conn
				var proxyInfo *server.ProxyProtocolInfo
				if s.ProxyIP != "" {
					proxyInfo = &server.ProxyProtocolInfo{
						SrcIP: s.RemoteIP,
					}
				}

				// Apply progressive authentication delay BEFORE any other checks
				remoteAddr := &server.StringAddr{Addr: s.RemoteIP}
				server.ApplyAuthenticationDelay(ctx, s.server.authLimiter, remoteAddr, "POP3-SASL")

				// Check authentication rate limiting after delay
				if s.server.authLimiter != nil {
					if err := s.server.authLimiter.CanAttemptAuthWithProxy(ctx, netConn, proxyInfo, address.FullAddress()); err != nil {
						s.DebugLog("sasl plain rate limited", "error", err)
						if s.handleClientError(writer, "-ERR [LOGIN-DELAY] Too many authentication attempts. Please try again later.\r\n") {
							return
						}
						continue
					}
				}

				accountID, err = s.server.Authenticate(ctx, address.BaseAddress(), password)
				if err != nil {
					// Check if error is due to context cancellation (server shutdown)
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						s.InfoLog("sasl authentication cancelled due to server shutdown")
						if s.handleClientError(writer, "-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n") {
							return
						}
						continue
					}

					// Record failed attempt
					if s.server.authLimiter != nil {
						s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, address.FullAddress(), false)
					}
					if s.handleClientError(writer, "-ERR [AUTH] Authentication failed\r\n") {
						s.DebugLog("authentication failed")
						return
					}
					continue
				}

				// Record successful attempt
				if s.server.authLimiter != nil {
					s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, address.FullAddress(), true)
				}
			}

			// This is a potential write operation.
			// Ensure default mailboxes (INBOX/Drafts/Sent/Spam/Trash) exist
			err = s.server.rdb.CreateDefaultMailboxesWithRetry(ctx, accountID)
			if err != nil {
				s.DebugLog("error creating default mailboxes", "error", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}
			// Create a context that signals to the DB layer to use the master connection.
			// We will set useMasterDB later under the write lock.
			readCtx := context.WithValue(ctx, consts.UseMasterDBKey, true)

			inboxMailboxID, err := s.server.rdb.GetMailboxByNameWithRetry(readCtx, accountID, consts.MailboxInbox)
			if err != nil {
				s.DebugLog("error getting inbox", "error", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}

			// Acquire write lock to update session state
			acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			s.inboxMailboxID = inboxMailboxID.ID
			s.authenticated = true
			// Initialize User for connection tracking - will use correct email below
			// For impersonation: authzID, otherwise: authnID
			var userEmail string
			if impersonating {
				userEmail = authzID
			} else {
				userEmail = authnID
			}
			userAddr, _ := server.NewAddress(userEmail)
			s.User = server.NewUser(userAddr, accountID)
			s.deleted = make(map[int]bool) // Initialize deletion map on authentication
			s.useMasterDB = true           // Pin session to master DB after a write to ensure consistency
			release()

			s.server.authenticatedConnections.Add(1)

			// Log authentication success with standardized format
			// Note: Regular auth via Authenticate() already logs in server.go with cached/method
			// For master SASL auth, we log here with method=master
			if impersonating {
				duration := time.Since(start)
				s.InfoLog("authentication successful", "address", authzID, "account_id", accountID, "cached", false, "method", "master", "duration", fmt.Sprintf("%.3fs", duration.Seconds()))
				// Register connection for tracking with the impersonated user's email
				s.registerConnection(authzID)
			} else {
				// Regular SASL auth - Authenticate() already logged, just register connection
				// Register connection for tracking with the authenticated user's email
				s.registerConnection(authnID)
			}

			// Start termination poller to check for kick commands
			s.startTerminationPoller()

			writer.WriteString("+OK Authentication successful\r\n")
			success = true

		case "LANG":
			start := time.Now()
			success := false
			defer func() {
				status := "failure"
				if success {
					status = "success"
				}
				metrics.CommandsTotal.WithLabelValues("pop3", "LANG", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "LANG").Observe(time.Since(start).Seconds())
			}()

			// LANG command - set or query language
			// Acquire read lock to access current language
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}
			currentLang := s.language
			release()

			if len(parts) == 1 {
				// LANG without arguments - list supported languages
				writer.WriteString("+OK Language listing follows\r\n")
				writer.WriteString("en English\r\n")
				writer.WriteString(".\r\n")
			} else {
				// LANG with language tag
				langTag := strings.ToLower(parts[1])

				// For now, we only support English
				if langTag != "en" && langTag != "*" {
					writer.WriteString("-ERR [LANG] Unsupported language\r\n")
					writer.Flush()
					continue
				}

				// Acquire write lock to update language
				acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
				if !acquired {
					s.WarnLog("failed to acquire write lock within timeout")
					writer.WriteString("-ERR Server busy, please try again\r\n")
					writer.Flush()
					continue
				}
				defer release()

				if langTag == "*" {
					s.language = "en" // Default to English
				} else {
					s.language = langTag
				}

				writer.WriteString(fmt.Sprintf("+OK Language changed to %s\r\n", s.language))
			}
			s.DebugLog("lang command executed", "current", currentLang)
			success = true

		case "UTF8":
			start := time.Now()
			success := false
			defer func() {
				status := "failure"
				if success {
					status = "success"
				}
				metrics.CommandsTotal.WithLabelValues("pop3", "UTF8", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "UTF8").Observe(time.Since(start).Seconds())
			}()

			// UTF8 command - enable UTF-8 mode
			// Acquire write lock to update UTF8 mode
			acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			s.utf8Mode = true
			release()

			writer.WriteString("+OK UTF8 enabled\r\n")
			s.DebugLog("utf8 mode enabled")
			success = true

		case "QUIT":
			start := time.Now()
			success := false
			defer func() {
				status := "failure"
				if success {
					status = "success"
				}
				metrics.CommandsTotal.WithLabelValues("pop3", "QUIT", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "QUIT").Observe(time.Since(start).Seconds())
			}()

			s.DebugLog("quit command received, starting message expunge process")
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting quit command")
				return
			}

			// Phase 1: Collect messages to expunge under a read lock.
			var messagesToExpunge []db.Message
			var mailboxID int64
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.InfoLog("failed to acquire read lock, cannot expunge messages")
				// Continue with QUIT, but don't expunge.
			} else {
				mailboxID = s.inboxMailboxID
				for i, deleted := range s.deleted {
					if deleted && i < len(s.messages) {
						messagesToExpunge = append(messagesToExpunge, s.messages[i])
					}
				}
				release()
			}

			// Phase 2: Perform cache and database operations outside the lock.
			var expungeUIDs []imap.UID
			for _, msg := range messagesToExpunge {
				s.DebugLog("will expunge message", "uid", msg.UID)
				// Delete from cache before expunging
				if err := s.server.cache.Delete(msg.ContentHash); err != nil && !isNotExist(err) {
					s.WarnLog("failed to delete message from cache", "content_hash", msg.ContentHash, "error", err)
				}
				expungeUIDs = append(expungeUIDs, msg.UID)
			}

			if len(expungeUIDs) > 0 {
				s.DebugLog("expunging messages", "count", len(expungeUIDs), "mailbox_id", mailboxID, "uids", expungeUIDs)
				_, err = s.server.rdb.ExpungeMessageUIDsWithRetry(ctx, mailboxID, expungeUIDs...)
				if err != nil {
					s.DebugLog("error expunging messages", "mailbox_id", mailboxID, "error", err)
				} else {
					s.DebugLog("successfully expunged messages", "count", len(expungeUIDs), "mailbox_id", mailboxID)
				}
			} else {
				s.DebugLog("no messages to expunge", "mailbox_id", mailboxID)
			}

			userAddress = nil

			writer.WriteString("+OK Goodbye\r\n")
			writer.Flush()

			success = true
			// Return and let defer s.Close() handle cleanup
			return

		case "XCLIENT":
			// XCLIENT command for Dovecot-style parameter forwarding
			start := time.Now()
			success := false
			defer func() {
				status := "failure"
				if success {
					status = "success"
				}
				metrics.CommandsTotal.WithLabelValues("pop3", "XCLIENT", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "XCLIENT").Observe(time.Since(start).Seconds())
			}()

			// Extract the arguments (everything after XCLIENT)
			args := ""
			if len(parts) > 1 {
				args = strings.Join(parts[1:], " ")
			}

			s.handleXCLIENT(args, writer)
			success = true

		default:
			writer.WriteString(fmt.Sprintf("-ERR Unknown command: %s\r\n", cmd))
			s.DebugLog("unknown command", "command", cmd)
		}

		// Flush response and check for timeout
		if err := writer.Flush(); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.WarnLog("command timeout", "command", cmd, "timeout", s.server.commandTimeout)

				// Track timeout event in metrics
				metrics.CommandTimeoutsTotal.WithLabelValues("pop3", cmd).Inc()

				// Try to send error message if possible
				(*s.conn).SetDeadline(time.Now().Add(5 * time.Second)) // Brief window to send error
				writer.WriteString(fmt.Sprintf("-ERR Command %s exceeded timeout\r\n", cmd))
				writer.Flush()
				return
			}
			s.DebugLog("error flushing response", "command", cmd, "error", err)
			return
		}

		// Clear deadline after successful command completion
		(*s.conn).SetDeadline(time.Time{})
	}
}

func isNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}

func (s *POP3Session) handleClientError(writer *bufio.Writer, errMsg string) bool {
	s.errorsCount++
	if s.errorsCount > Pop3MaxErrorsAllowed {
		writer.WriteString("-ERR Too many errors, closing connection\r\n")
		writer.Flush()
		return true
	}
	// Make a delay to prevent brute force attacks
	delay := time.Duration(s.errorsCount) * Pop3ErrorDelay
	time.Sleep(delay)

	// Replace [AUTH] with [LOGIN-DELAY n] where n is seconds until next attempt is allowed
	errMsg = strings.Replace(errMsg, "[AUTH]", fmt.Sprintf("[LOGIN-DELAY %d]", int(delay.Seconds())), 1)

	writer.WriteString(errMsg)
	writer.Flush()
	return false
}

func (s *POP3Session) closeWithoutLock() error {
	metrics.ConnectionDuration.WithLabelValues("pop3").Observe(time.Since(s.startTime).Seconds())

	// Log and record peak memory usage
	if s.memTracker != nil {
		peak := s.memTracker.Peak()
		metrics.SessionMemoryPeakBytes.WithLabelValues("pop3").Observe(float64(peak))
		if peak > 0 {
			s.DebugLog("session memory peak", "peak", server.FormatBytes(peak))
		}
	}

	totalCount := s.server.totalConnections.Add(-1)
	var authCount int64 = 0

	// Prometheus metrics - connection closed
	metrics.ConnectionsCurrent.WithLabelValues("pop3").Dec()

	(*s.conn).Close()

	// Remove session from active tracking
	s.server.removeSession(s)

	// Release connection from limiter
	if s.releaseConn != nil {
		s.releaseConn()
		s.releaseConn = nil // Prevent double release
	}

	if s.User != nil {
		if s.authenticated {
			authCount = s.server.authenticatedConnections.Add(-1)
			metrics.AuthenticatedConnectionsCurrent.WithLabelValues("pop3").Dec()

			// Unregister connection from tracker
			s.unregisterConnection()
		} else {
			authCount = s.server.authenticatedConnections.Load()
		}
		s.InfoLog("closed", "total_connections", totalCount, "authenticated_connections", authCount)

		// Clean up session state
		s.User = nil
		s.Id = ""
		s.messages = nil
		s.deleted = nil
		s.authenticated = false

		if s.cancel != nil { // Ensure session cancel is called if not already
			s.cancel()
		}
	} else {
		authCount = s.server.authenticatedConnections.Load()
		s.DebugLog("closed unauthenticated connection", "total_connections", totalCount, "authenticated_connections", authCount)
	}

	return nil
}

func (s *POP3Session) Close() error {
	acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.WarnLog("failed to acquire write lock within timeout")
		// Still close the connection even if we can't acquire the lock
		return s.closeWithoutLock()
	}
	defer release()
	return s.closeWithoutLock()
}

func (s *POP3Session) getMessageBody(msg *db.Message) ([]byte, error) {
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted, aborting message body fetch")
		return nil, fmt.Errorf("request aborted")
	}

	if msg.IsUploaded {
		// Try cache first
		data, err := s.server.cache.Get(msg.ContentHash)
		if err == nil && data != nil {
			// Validate cached data is not empty
			if len(data) == 0 {
				logger.Warn("POP3: Cache contains empty body", "uid", msg.UID, "hash", msg.ContentHash)
				// Don't return empty data, fall through to S3
				data = nil
			} else {
				logger.Debug("POP3: Cache hit", "uid", msg.UID)
				// Track memory usage for cached data
				if s.memTracker != nil {
					if allocErr := s.memTracker.Allocate(int64(len(data))); allocErr != nil {
						metrics.SessionMemoryLimitExceeded.WithLabelValues("pop3").Inc()
						return nil, fmt.Errorf("session memory limit exceeded: %v", allocErr)
					}
				}
				return data, nil
			}
		}

		// Fallback to S3
		logger.Debug("POP3: Cache miss - fetching from S3", "uid", msg.UID, "hash", msg.ContentHash)
		address, err := s.server.rdb.GetPrimaryEmailForAccountWithRetry(s.ctx, msg.AccountID)
		if err != nil {
			return nil, fmt.Errorf("failed to get primary address for account %d: %w", msg.AccountID, err)
		}

		s3Key := helpers.NewS3Key(address.Domain(), address.LocalPart(), msg.ContentHash)

		reader, err := s.server.s3.GetWithRetry(s.server.appCtx, s3Key)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve message UID %d from S3: %v", msg.UID, err)
		}
		defer reader.Close()
		data, err = io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		// Validate S3 data is not empty
		if len(data) == 0 {
			logger.Warn("POP3: Retrieved empty body from S3", "uid", msg.UID, "hash", msg.ContentHash, "s3_key", s3Key)
			return nil, fmt.Errorf("message UID %d has empty body in S3 (hash: %s)", msg.UID, msg.ContentHash)
		}
		// Track memory usage for S3 data
		if s.memTracker != nil {
			if allocErr := s.memTracker.Allocate(int64(len(data))); allocErr != nil {
				metrics.SessionMemoryLimitExceeded.WithLabelValues("pop3").Inc()
				return nil, fmt.Errorf("session memory limit exceeded: %v", allocErr)
			}
		}
		// Store in cache
		logger.Debug("POP3: Storing in cache", "uid", msg.UID, "hash", msg.ContentHash)
		_ = s.server.cache.Put(msg.ContentHash, data)
		return data, nil
	}

	// If not uploaded to S3, try fetch from local disk
	logger.Debug("POP3: Fetching not yet uploaded message from disk", "uid", msg.UID)
	filePath := s.server.uploader.FilePath(msg.ContentHash, msg.AccountID)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Debug("POP3: Message not found locally - assuming pending", "uid", msg.UID, "hash", msg.ContentHash)
			return nil, consts.ErrMessageNotAvailable
		}
		// Other error trying to access the local file
		return nil, fmt.Errorf("error retrieving message UID %d from local disk: %w", msg.UID, err)
	}
	if data == nil { // Should ideally not happen if GetLocalFile returns nil, nil for "not found"
		return nil, fmt.Errorf("message UID %d (hash %s) not found on disk (GetLocalFile returned nil data, nil error)", msg.UID, msg.ContentHash)
	}
	// Validate disk data is not empty
	if len(data) == 0 {
		logger.Warn("POP3: Retrieved empty body from disk", "uid", msg.UID, "hash", msg.ContentHash, "path", filePath)
		return nil, fmt.Errorf("message UID %d has empty body on disk (hash: %s, path: %s)", msg.UID, msg.ContentHash, filePath)
	}
	// Track memory usage for disk data
	if s.memTracker != nil {
		if allocErr := s.memTracker.Allocate(int64(len(data))); allocErr != nil {
			metrics.SessionMemoryLimitExceeded.WithLabelValues("pop3").Inc()
			return nil, fmt.Errorf("session memory limit exceeded: %v", allocErr)
		}
	}
	return data, nil
}

// registerConnection registers the connection in the connection tracker
func (s *POP3Session) registerConnection(email string) {
	if s.server.connTracker != nil && s.authenticated {
		// Use configured database query timeout for connection tracking (database INSERT)
		queryTimeout := s.server.rdb.GetQueryTimeout()
		ctx, cancel := context.WithTimeout(s.ctx, queryTimeout)
		defer cancel()

		clientAddr := server.GetAddrString((*s.conn).RemoteAddr())

		if err := s.server.connTracker.RegisterConnection(ctx, s.AccountID(), email, "POP3", clientAddr); err != nil {
			s.InfoLog("rejected connection registration", "error", err)
		}
	}
}

// unregisterConnection removes the connection from the connection tracker
func (s *POP3Session) unregisterConnection() {
	if s.server.connTracker != nil && s.authenticated {
		// Use configured database query timeout for connection tracking (database DELETE)
		queryTimeout := s.server.rdb.GetQueryTimeout()
		ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
		defer cancel()

		clientAddr := server.GetAddrString((*s.conn).RemoteAddr())

		if err := s.server.connTracker.UnregisterConnection(ctx, s.AccountID(), "POP3", clientAddr); err != nil {
			s.DebugLog("failed to unregister connection", "error", err)
		}
	}
}

// startTerminationPoller starts a goroutine that waits for kick notifications
func (s *POP3Session) startTerminationPoller() {
	if s.server.connTracker == nil || !s.authenticated {
		return
	}

	// Register session for kick notifications and get a channel that closes on kick
	kickChan := s.server.connTracker.RegisterSession(s.AccountID())

	go func() {
		// Unregister when done
		defer s.server.connTracker.UnregisterSession(s.AccountID(), kickChan)

		select {
		case <-kickChan:
			// Kick notification received - close connection
			s.InfoLog("connection kicked, disconnecting user")
			(*s.conn).Close()
		case <-s.ctx.Done():
			// Session ended normally
		}
	}()
}

func checkMasterCredential(provided string, actual []byte) bool {
	return subtle.ConstantTimeCompare([]byte(provided), actual) == 1
}

// dotStuffPOP3 performs byte-stuffing per RFC 1939 Section 3.
// Any line beginning with a termination octet (.) must be prepended with another dot.
// This prevents premature message termination when the body contains lines starting with "."
func dotStuffPOP3(data string) string {
	// Fast path: if no dots at line start, return as-is
	if !strings.Contains(data, "\r\n.") && !strings.HasPrefix(data, ".") {
		return data
	}

	var result strings.Builder
	result.Grow(len(data) + 64) // Pre-allocate with some buffer for stuffing

	lines := strings.Split(data, "\r\n")
	for i, line := range lines {
		if strings.HasPrefix(line, ".") {
			result.WriteString(".")
		}
		result.WriteString(line)
		if i < len(lines)-1 {
			result.WriteString("\r\n")
		}
	}

	return result.String()
}
