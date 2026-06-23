package pop3

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/storage"
)

const Pop3MaxErrorsAllowed = 3                  // Maximum number of errors tolerated before the connection is terminated
const Pop3ErrorDelay = 3 * time.Second          // Wait for this many seconds before allowing another command
const Pop3DefaultIdleTimeout = 10 * time.Minute // RFC 1939 §3: auto-logout timer MUST be at least 10 minutes
const Pop3MaxLineLength = 1024                  // RFC 1939 §3: commands and responses limited to 512 octets (use 1024 for safety)

type POP3Session struct {
	server.Session
	server         *POP3Server
	conn           *net.Conn    // Connection to the client
	mutex          sync.RWMutex // Mutex for protecting session state
	mutexHelper    *server.MutexTimeoutHelper
	authenticated  atomic.Bool        // Flag to indicate if the user has been authenticated
	messages       []db.Message       // List of messages in the mailbox as returned by the LIST command
	deleted        map[int]bool       // Map of message IDs marked for deletion
	inboxMailboxID int64              // POP3 suppots only INBOX
	ctx            context.Context    // Context for this session
	cancel         context.CancelFunc // Function to cancel the session's context
	errorsCount    int                // Number of errors encountered during the session
	language       string             // Current language for responses (default "en")
	utf8Mode       atomic.Bool        // UTF8 mode enabled for this session
	releaseConn    func()             // Function to release connection from limiter
	useMasterDB    atomic.Bool        // Pin session to master DB after a write to ensure consistency
	startTime      time.Time
	memTracker     *server.SessionMemoryTracker // Memory usage tracker for this session

	// Session statistics for summary logging
	messagesRetrieved int // Messages retrieved with RETR
	messagesDeleted   int // Messages marked for deletion with DELE
	messagesExpunged  int // Messages actually expunged on QUIT
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
		if !s.authenticated.Load() && s.server.authIdleTimeout > 0 {
			(*s.conn).SetReadDeadline(time.Now().Add(s.server.authIdleTimeout))
		} else if s.server.commandTimeout > 0 {
			(*s.conn).SetReadDeadline(time.Now().Add(s.server.commandTimeout))
		} else {
			(*s.conn).SetReadDeadline(time.Time{}) // No timeout
		}

		line, err := server.ReadBoundedLine(reader, Pop3MaxLineLength)
		if err != nil {
			if err == server.ErrLineTooLong {
				writer.WriteString("-ERR Line too long\r\n")
				writer.Flush()
				s.WarnLog("line too long, closing connection")
				return
			}
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
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("pop3", "CAPA", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "CAPA").Observe(time.Since(start).Seconds())
			}

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

			recordMetrics("success")

		case "USER":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("pop3", "USER", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "USER").Observe(time.Since(start).Seconds())
			}

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting user command")
				recordMetrics("failure")
				return
			}

			// Check authentication state (atomic read, no lock needed)
			if s.authenticated.Load() {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Already authenticated\r\n") {
					// Close the connection if too many errors are encountered
					return
				}
				continue
			}

			// USER requires an argument; reject a missing one rather than indexing
			// parts[1] and panicking (RFC 1939: USER name).
			if len(parts) < 2 {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Missing username\r\n") {
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
				recordMetrics("failure")
				if s.handleClientError(writer, fmt.Sprintf("-ERR %s\r\n", err.Error())) {
					return
				}
				continue
			}
			userAddress = &newUserAddress
			writer.WriteString("+OK User accepted\r\n")

			recordMetrics("success")

		case "PASS":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("pop3", "PASS", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "PASS").Observe(time.Since(start).Seconds())
			}

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting pass command")
				recordMetrics("failure")
				return
			}

			// Check authentication state (atomic read, no lock needed)
			if s.authenticated.Load() {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Already authenticated\r\n") {
					return
				}
				continue
			}

			if userAddress == nil {
				s.DebugLog("pass without user")
				writer.WriteString("-ERR Must provide USER first\r\n")
				writer.Flush()
				recordMetrics("failure")
				continue
			}

			// Check insecure_auth: reject PASS over non-TLS when insecure_auth is false
			if !s.server.insecureAuth && !s.isConnectionSecure() {
				s.DebugLog("authentication rejected - TLS required", "address", userAddress.FullAddress())
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Authentication requires TLS connection\r\n") {
					return
				}
				continue
			}

			s.DebugLog("authentication attempt", "address", userAddress.FullAddress())

			// PASS requires an argument; reject a missing one rather than indexing
			// parts[1] and panicking (RFC 1939: PASS string).
			if len(parts) < 2 {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Missing password\r\n") {
					return
				}
				continue
			}

			// Remove quotes from password if present for compatibility
			password := server.UnquoteString(parts[1])

			// Reject empty passwords immediately - no rate limiting needed
			// Empty passwords are never valid under any condition
			if password == "" {
				recordMetrics("failure")
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
			if err := server.ApplyAuthenticationDelay(ctx, s.server.authLimiter, remoteAddr, "POP3-PASS"); err != nil {
				if errors.Is(err, server.ErrDelayQueueFull) {
					// Delay queue full - reject immediately to prevent goroutine exhaustion
					logger.Info("POP3: Delay queue full, rejecting connection", "address", userAddress.FullAddress(), "ip", s.RemoteIP)
					recordMetrics("failure")
					if s.handleClientError(writer, "-ERR [IN-USE] Too many concurrent authentication attempts. Please try again later.\r\n") {
						return
					}
					continue
				}
				// Context cancelled or other error - close connection
				return
			}

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
						metrics.AuthenticationAttempts.WithLabelValues("pop3", s.server.name, s.server.hostname, "rate_limited").Inc()
					} else {
						s.DebugLog("[PASS] rate limited", "error", err)
						metrics.AuthenticationAttempts.WithLabelValues("pop3", s.server.name, s.server.hostname, "rate_limited").Inc()
					}

					recordMetrics("failure")
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
						recordMetrics("failure")
						if s.handleClientError(writer, "-ERR [AUTH] Authentication failed\r\n") {
							s.DebugLog("authentication failed")
							return
						}
						continue
					}
				} else {
					// Record failed master password authentication
					metrics.AuthenticationAttempts.WithLabelValues("pop3", s.server.name, s.server.hostname, "failure").Inc()
					if s.server.authLimiter != nil {
						s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, userAddress.BaseAddress(), false)
					}

					// Master username suffix was provided but master password was wrong - fail immediately
					recordMetrics("failure")
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
						recordMetrics("failure")
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
						recordMetrics("failure")
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
					metrics.AuthenticationAttempts.WithLabelValues("pop3", s.server.name, s.server.hostname, "failure").Inc()
					metrics.CriticalOperationDuration.WithLabelValues("pop3_authentication").Observe(time.Since(start).Seconds())
					recordMetrics("failure")
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
				writer.WriteString("-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n")
				writer.Flush()
				recordMetrics("failure")
				continue
			}
			// Create a context that signals to the DB layer to use the master connection.
			// We will set useMasterDB later under the write lock.
			readCtx := context.WithValue(ctx, consts.UseMasterDBKey, true)

			inboxMailboxID, err := s.server.rdb.GetMailboxByNameWithRetry(readCtx, accountID, consts.MailboxInbox)
			if err != nil {
				s.DebugLog("error getting inbox", "error", err)
				writer.WriteString("-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n")
				writer.Flush()
				recordMetrics("failure")
				continue
			}

			// Acquire write lock to update session state
			acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.WarnLog(" failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				recordMetrics("failure")
				continue
			}

			s.inboxMailboxID = inboxMailboxID.ID
			s.User = server.NewUser(*userAddress, accountID) // Initialize User for connection tracking
			s.deleted = make(map[int]bool)                   // Initialize deletion map on authentication
			s.useMasterDB.Store(true)                        // Pin session to master DB after a write to ensure consistency
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
			metrics.AuthenticatedConnectionsCurrent.WithLabelValues("pop3", s.server.name, s.server.hostname).Inc()
			metrics.CriticalOperationDuration.WithLabelValues("pop3_authentication").Observe(time.Since(start).Seconds())

			// IMPORTANT: Set authenticated flag AFTER incrementing both counters to prevent race condition
			// If session closes between counter increments and flag setting, cleanup won't decrement
			s.authenticated.Store(true)

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

			recordMetrics("success")

		case "STAT":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("pop3", "STAT", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "STAT").Observe(time.Since(start).Seconds())
			}

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting stat command")
				recordMetrics("failure")
				return
			}

			// Check authentication state (atomic read, no lock needed)
			if !s.authenticated.Load() {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
			}

			// Create a context for read operations that respects session pinning (atomic read, no lock needed)
			readCtx := ctx
			if s.useMasterDB.Load() {
				readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
			}

			// Acquire read lock to check inbox mailbox ID and compute deleted adjustments
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				recordMetrics("failure")
				continue
			}

			mailboxID := s.inboxMailboxID
			// RFC 1939 §5: STAT must exclude messages marked as deleted in this session.
			// Compute the count and size of deleted messages to subtract from DB totals.
			deletedCount, deletedSize := computeDeletedStats(s.messages, s.deleted)
			release()

			messagesCount, size, err := s.server.rdb.GetMailboxMessageCountAndSizeSumWithRetry(readCtx, mailboxID)
			if err != nil {
				s.DebugLog("stat error", "error", err)
				writer.WriteString("-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n")
				writer.Flush()
				recordMetrics("failure")
				continue
			}

			// Adjust for session-local deletions
			adjustedCount := messagesCount - deletedCount
			adjustedSize := size - deletedSize
			if adjustedCount < 0 {
				adjustedCount = 0
			}
			if adjustedSize < 0 {
				adjustedSize = 0
			}

			writer.WriteString(fmt.Sprintf("+OK %d %d\r\n", adjustedCount, adjustedSize))

			recordMetrics("success")

		case "LIST":
			start := time.Now()
			var backendDuration float64
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("pop3", "LIST", status).Inc()
				if backendDuration == 0 {
					backendDuration = time.Since(start).Seconds()
				}
				metrics.CommandDuration.WithLabelValues("pop3", "LIST").Observe(backendDuration)
			}

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting list command")
				recordMetrics("failure")
				return
			}

			// Check authentication state (atomic read, no lock needed)
			if !s.authenticated.Load() {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
			}

			// Acquire read lock to check loading needs
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				recordMetrics("failure")
				continue
			}
			mailboxID := s.inboxMailboxID
			needsLoading := (s.messages == nil)
			release()

			// Load messages if not yet loaded
			if needsLoading {
				// Create a context for read operations that respects session pinning (atomic read, no lock needed)
				readCtx := ctx
				if s.useMasterDB.Load() {
					readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
				}

				messages, err := s.server.rdb.ListMessagesWithRetry(readCtx, mailboxID)
				if err != nil {
					s.DebugLog("list error", "error", err)
					writer.WriteString("-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n")
					writer.Flush()
					recordMetrics("failure")
					continue
				}

				// Acquire write lock to update session state
				acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
				if !acquired {
					s.WarnLog("failed to acquire write lock within timeout")
					writer.WriteString("-ERR Server busy, please try again\r\n")
					writer.Flush()
					recordMetrics("failure")
					continue
				}
				s.messages = messages
				s.DebugLog("loaded messages from database", "count", len(messages), "mailbox_id", mailboxID)
				release()
			}

			// Handle LIST with message number argument (RFC 1939 §5)
			if len(parts) > 1 {
				msgNumber, err := strconv.Atoi(parts[1])
				if err != nil || msgNumber < 1 {
					recordMetrics("failure")
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
					recordMetrics("failure")
					continue
				}

				ok, line := buildSingleListResponse(s.messages, s.deleted, msgNumber)
				release()

				if !ok {
					recordMetrics("failure")
					if msgNumber > len(s.messages) {
						if s.handleClientError(writer, "-ERR No such message\r\n") {
							return
						}
					} else {
						if s.handleClientError(writer, "-ERR Message is deleted\r\n") {
							return
						}
					}
					continue
				}

				backendDuration = time.Since(start).Seconds()
				writer.WriteString(fmt.Sprintf("+OK %s\r\n", line))
			} else {
				// LIST without arguments - list all messages
				// Acquire read lock to access messages and deleted status
				acquired, release = s.mutexHelper.AcquireReadLockWithTimeout()
				if !acquired {
					s.WarnLog("failed to acquire read lock within timeout")
					writer.WriteString("-ERR Server busy, please try again\r\n")
					writer.Flush()
					recordMetrics("failure")
					continue
				}

				// Build response lines preserving original message numbers (RFC 1939 §5).
				responseLines := buildListResponseLines(s.messages, s.deleted)
				nonDeletedCount := countNonDeletedMessages(s.messages, s.deleted)
				release() // Release lock before I/O.

				// Build and send response outside the lock.
				backendDuration = time.Since(start).Seconds()

				writer.WriteString(fmt.Sprintf("+OK %d messages\r\n", nonDeletedCount))
				for _, line := range responseLines {
					writer.WriteString(line + "\r\n")
				}
				writer.WriteString(".\r\n")
			}
			s.DebugLog("list command executed")

			recordMetrics("success")

		case "UIDL":
			start := time.Now()
			var backendDuration float64
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("pop3", "UIDL", status).Inc()
				if backendDuration == 0 {
					backendDuration = time.Since(start).Seconds()
				}
				metrics.CommandDuration.WithLabelValues("pop3", "UIDL").Observe(backendDuration)
			}

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting uidl command")
				recordMetrics("failure")
				return
			}

			// Check authentication state (atomic read, no lock needed)
			if !s.authenticated.Load() {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
			}

			// Acquire read lock to check loading needs
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				recordMetrics("failure")
				continue
			}
			mailboxID := s.inboxMailboxID
			needsLoading := (s.messages == nil)
			release()

			if needsLoading {
				// Create a context for read operations that respects session pinning (atomic read, no lock needed)
				readCtx := ctx
				if s.useMasterDB.Load() {
					readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
				}
				messages, err := s.server.rdb.ListMessagesWithRetry(readCtx, mailboxID)
				if err != nil {
					s.DebugLog("uidl error", "error", err)
					writer.WriteString("-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n")
					writer.Flush()
					recordMetrics("failure")
					continue
				}

				// Acquire write lock to update session state
				acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
				if !acquired {
					s.WarnLog("failed to acquire write lock within timeout")
					writer.WriteString("-ERR Server busy, please try again\r\n")
					writer.Flush()
					recordMetrics("failure")
					continue
				}
				s.messages = messages
				release()
			}

			// Handle UIDL with message number argument
			if len(parts) > 1 {
				msgNumber, err := strconv.Atoi(parts[1])
				if err != nil || msgNumber < 1 {
					recordMetrics("failure")
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
					recordMetrics("failure")
					continue
				}

				if msgNumber > len(s.messages) {
					release()
					recordMetrics("failure")
					if s.handleClientError(writer, "-ERR No such message\r\n") {
						return
					}
					continue
				}

				msg := s.messages[msgNumber-1]
				if s.deleted[msgNumber-1] {
					release()
					recordMetrics("failure")
					if s.handleClientError(writer, "-ERR Message is deleted\r\n") {
						return
					}
					continue
				}

				// Use UID as the unique identifier (more reliable than ContentHash)
				release()

				backendDuration = time.Since(start).Seconds()
				writer.WriteString(fmt.Sprintf("+OK %d %d\r\n", msgNumber, msg.UID))
			} else {
				// UIDL without arguments - list all messages
				// Acquire read lock to access messages and deleted status
				acquired, release = s.mutexHelper.AcquireReadLockWithTimeout()
				if !acquired {
					s.WarnLog("failed to acquire read lock within timeout")
					writer.WriteString("-ERR Server busy, please try again\r\n")
					writer.Flush()
					recordMetrics("failure")
					continue
				}

				// Build response lines preserving original message numbers (RFC 1939 §5).
				responseLines := buildUIDLResponseLines(s.messages, s.deleted)
				nonDeletedCount := countNonDeletedMessages(s.messages, s.deleted)
				release() // Release lock before I/O.

				// Phase 4: Build and send response outside the lock.
				backendDuration = time.Since(start).Seconds()
				writer.WriteString(fmt.Sprintf("+OK %d messages\r\n", nonDeletedCount))
				for _, line := range responseLines {
					writer.WriteString(line + "\r\n")
				}
				writer.WriteString(".\r\n")
			}
			s.DebugLog("uidl command executed")

			recordMetrics("success")

		case "TOP":
			start := time.Now()
			var backendDuration float64
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("pop3", "TOP", status).Inc()
				if backendDuration == 0 {
					backendDuration = time.Since(start).Seconds()
				}
				metrics.CommandDuration.WithLabelValues("pop3", "TOP").Observe(backendDuration)
			}

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting top command")
				recordMetrics("failure")
				return
			}

			// Check authentication state (atomic read, no lock needed)
			if !s.authenticated.Load() {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
			}

			if len(parts) < 3 {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Missing message number or lines parameter\r\n") {
					return
				}
				continue
			}

			msgNumber, err := strconv.Atoi(parts[1])
			if err != nil || msgNumber < 1 {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Invalid message number\r\n") {
					return
				}
				continue
			}

			lines, err := strconv.Atoi(parts[2])
			if err != nil || lines < 0 {
				recordMetrics("failure")
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
				recordMetrics("failure")
				continue
			}
			mailboxID := s.inboxMailboxID
			needsLoading := (s.messages == nil)
			release()

			// Phase 2: Load messages if needed (outside of any lock).
			var loadedMessages []db.Message
			if needsLoading {
				// Create a context for read operations that respects session pinning (atomic read, no lock needed)
				readCtx := ctx
				if s.useMasterDB.Load() {
					readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
				}
				loadedMessages, err = s.server.rdb.ListMessagesWithRetry(readCtx, mailboxID)
				if err != nil {
					s.DebugLog("top error", "error", err)
					writer.WriteString("-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n")
					writer.Flush()
					recordMetrics("failure")
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
				recordMetrics("failure")
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
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			if isDeleted {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Message is deleted\r\n") {
					return
				}
				continue
			}

			if msg.UID == 0 {
				recordMetrics("failure")
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
				} else if errors.Is(err, errBodyTransientlyUnavailable) {
					s.WarnLog("TOP: message body temporarily unavailable, asking client to retry", "uid", msg.UID, "error", err)
					writer.WriteString("-ERR [SYS/TEMP] Message temporarily unavailable, please try again later\r\n")
				} else {
					s.DebugLog("top internal error", "error", err)
					writer.WriteString("-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n")
				}
				writer.Flush()
				// A transient "retry later" is not a server failure; bucket it separately
				// so the failure metric reflects only genuine failures.
				if errors.Is(err, errBodyTransientlyUnavailable) {
					recordMetrics("unavailable")
				} else {
					recordMetrics("failure")
				}
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
				if strings.HasSuffix(stuffedResult, "\r\n") {
					writer.WriteString(stuffedResult + ".\r\n")
				} else {
					writer.WriteString(stuffedResult + "\r\n.\r\n")
				}
				s.DebugLog("retrieved headers for message", "uid", msg.UID)
				// Free memory immediately after sending response
				if s.memTracker != nil && bodyData != nil {
					s.memTracker.Free(int64(len(bodyData)))
				}
				recordMetrics("success")
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

			backendDuration = time.Since(start).Seconds()
			writer.WriteString(fmt.Sprintf("+OK %d octets\r\n", len(result)))
			if strings.HasSuffix(stuffedResult, "\r\n") {
				writer.WriteString(stuffedResult + ".\r\n")
			} else {
				writer.WriteString(stuffedResult + "\r\n.\r\n")
			}
			s.DebugLog("retrieved top lines of message", "lines", lines, "uid", msg.UID)

			// Free memory immediately after sending response
			if s.memTracker != nil && bodyData != nil {
				s.memTracker.Free(int64(len(bodyData)))
			}

			recordMetrics("success")

		case "RETR":
			retrieveStart := time.Now()
			var backendDuration float64
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("pop3", "RETR", status).Inc()
				if backendDuration == 0 {
					backendDuration = time.Since(retrieveStart).Seconds()
				}
				metrics.CommandDuration.WithLabelValues("pop3", "RETR").Observe(backendDuration)
			}

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting retr command")
				recordMetrics("failure")
				return
			}

			// Check authentication state (atomic read, no lock needed)
			if !s.authenticated.Load() {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
			}

			if len(parts) < 2 {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Missing message number\r\n") {
					return
				}
				continue
			}

			msgNumber, err := strconv.Atoi(parts[1])
			if err != nil || msgNumber < 1 {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Invalid message number\r\n") {
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
				recordMetrics("failure")
				continue
			}
			mailboxID := s.inboxMailboxID
			needsLoading := (s.messages == nil)
			release()

			// Phase 2: Load messages if needed (outside of any lock).
			var loadedMessages []db.Message
			if needsLoading {
				// Create a context for read operations that respects session pinning (atomic read, no lock needed)
				readCtx := ctx
				if s.useMasterDB.Load() {
					readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
				}
				loadedMessages, err = s.server.rdb.ListMessagesWithRetry(readCtx, mailboxID)
				if err != nil {
					s.DebugLog("retr error", "error", err)
					writer.WriteString("-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n")
					writer.Flush()
					recordMetrics("failure")
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
				recordMetrics("failure")
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
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			if isDeleted {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Message is deleted\r\n") {
					return
				}
				continue
			}

			if msg.UID == 0 {
				recordMetrics("failure")
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
				} else if errors.Is(err, errBodyTransientlyUnavailable) {
					s.WarnLog("RETR: message body temporarily unavailable, asking client to retry", "uid", msg.UID, "error", err)
					writer.WriteString("-ERR [SYS/TEMP] Message temporarily unavailable, please try again later\r\n")
				} else {
					s.DebugLog("retr internal error", "error", err)
					writer.WriteString("-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n")
				}
				writer.Flush()
				// A transient "retry later" is not a server failure; bucket it separately
				// so the failure metric reflects only genuine failures.
				if errors.Is(err, errBodyTransientlyUnavailable) {
					recordMetrics("unavailable")
				} else {
					recordMetrics("failure")
				}
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
				recordMetrics("failure")
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

			backendDuration = time.Since(retrieveStart).Seconds()
			writer.WriteString(fmt.Sprintf("+OK %d octets\r\n", msg.Size))
			if strings.HasSuffix(stuffedBody, "\r\n") {
				writer.WriteString(stuffedBody + ".\r\n")
			} else {
				writer.WriteString(stuffedBody + "\r\n.\r\n")
			}
			s.DebugLog("retrieved message", "uid", msg.UID)

			// Free memory immediately after sending response
			if s.memTracker != nil && bodyData != nil {
				s.memTracker.Free(int64(len(bodyData)))
			}

			// Track successful message retrieval
			metrics.MessageThroughput.WithLabelValues("pop3", "retrieved", "success").Inc()
			metrics.BytesThroughput.WithLabelValues("pop3", "out").Add(float64(msg.Size))
			metrics.CriticalOperationDuration.WithLabelValues("pop3_retrieve").Observe(backendDuration)

			// Track domain and user activity - RETR is bandwidth intensive!
			if s.User != nil {
				metrics.TrackDomainCommand("pop3", s.Domain(), "RETR")
				metrics.TrackUserActivity("pop3", s.FullAddress(), "command", 1)
				metrics.TrackDomainBytes("pop3", s.Domain(), "out", int64(msg.Size))
				metrics.TrackDomainMessage("pop3", s.Domain(), "fetched")
			}

			// Track for session summary
			s.messagesRetrieved++

			recordMetrics("success")

		case "NOOP":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("pop3", "NOOP", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "NOOP").Observe(time.Since(start).Seconds())
			}

			// Check authentication state (atomic read, no lock needed)
			if !s.authenticated.Load() {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
			}

			writer.WriteString("+OK\r\n")

			recordMetrics("success")

		case "RSET":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("pop3", "RSET", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "RSET").Observe(time.Since(start).Seconds())
			}

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting rset command")
				recordMetrics("failure")
				return
			}

			// Check authentication state (atomic read, no lock needed)
			if !s.authenticated.Load() {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
			}

			// Acquire write lock to update deleted map
			acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				recordMetrics("failure")
				continue
			}
			s.deleted = make(map[int]bool)
			release()

			writer.WriteString("+OK\r\n")
			s.DebugLog("deleted messages reset")

			recordMetrics("success")

		case "DELE":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("pop3", "DELE", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "DELE").Observe(time.Since(start).Seconds())
			}

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting dele command")
				recordMetrics("failure")
				return
			}

			// Check authentication state (atomic read, no lock needed)
			if !s.authenticated.Load() {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
			}

			if len(parts) < 2 {
				logger.Debug("missing message number")
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Missing message number\r\n") {
					return
				}
				continue
			}

			msgNumber, err := strconv.Atoi(parts[1])
			if err != nil || msgNumber < 1 {
				s.DebugLog("dele invalid message number", "error", err)
				recordMetrics("failure")
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
				recordMetrics("failure")
				continue
			}
			needsLoading := (s.messages == nil)
			mailboxID := s.inboxMailboxID
			release()

			// Phase 2: Load messages if needed (outside of any lock).
			var loadedMessages []db.Message
			if needsLoading {
				// Create a context for read operations that respects session pinning (atomic read, no lock needed)
				readCtx := ctx
				if s.useMasterDB.Load() {
					readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
				}
				loadedMessages, err = s.server.rdb.ListMessagesWithRetry(readCtx, mailboxID)
				if err != nil {
					s.DebugLog("dele error", "error", err)
					writer.WriteString("-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n")
					writer.Flush()
					recordMetrics("failure")
					continue
				}
			}

			// Phase 3: Acquire write lock to update session state.
			acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire write lock for dele command")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				recordMetrics("failure")
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
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			msg := s.messages[msgNumber-1]
			if msg.UID == 0 {
				release()
				s.DebugLog("dele no such message", "msg_number", msgNumber)
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			s.deleted[msgNumber-1] = true

			// Track for session summary
			s.messagesDeleted++

			release()

			writer.WriteString("+OK Message deleted\r\n")
			s.DebugLog("marked message for deletion", "msg_number", msgNumber, "uid", msg.UID, "mailbox_id", mailboxID, "total_deleted", len(s.deleted))

			metrics.MessageThroughput.WithLabelValues("pop3", "deleted", "success").Inc()

			recordMetrics("success")

		case "AUTH":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("pop3", "AUTH", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "AUTH").Observe(time.Since(start).Seconds())
			}

			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting auth command")
				recordMetrics("failure")
				return
			}

			// Check authentication state (atomic read, no lock needed)
			if s.authenticated.Load() {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Already authenticated\r\n") {
					return
				}
				continue
			}

			if len(parts) < 2 {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Missing authentication mechanism\r\n") {
					return
				}
				continue
			}

			// Remove quotes from mechanism if present for compatibility
			mechanism := server.UnquoteString(parts[1])
			mechanism = strings.ToUpper(mechanism)
			if mechanism != "PLAIN" {
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Unsupported authentication mechanism\r\n") {
					return
				}
				continue
			}

			// Check insecure_auth: reject AUTH over non-TLS when insecure_auth is false
			if !s.server.insecureAuth && !s.isConnectionSecure() {
				s.DebugLog("AUTH PLAIN rejected - TLS required")
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR Authentication requires TLS connection\r\n") {
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

				// Read the authentication data (bounded to avoid a pre-auth memory blow-up)
				authLine, err := server.ReadBoundedLine(reader, Pop3MaxLineLength)
				if err != nil {
					s.DebugLog("error reading auth data", "error", err)
					recordMetrics("failure")
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
				recordMetrics("failure")
				continue
			}

			// Decode base64
			decoded, err := base64.StdEncoding.DecodeString(authData)
			if err != nil {
				s.DebugLog("error decoding auth data", "error", err)
				recordMetrics("failure")
				if s.handleClientError(writer, "-ERR [AUTH] Invalid authentication data\r\n") {
					return
				}
				continue
			}

			// Parse SASL PLAIN format: [authz-id] \0 authn-id \0 password
			parts := strings.Split(string(decoded), "\x00")
			if len(parts) != 3 {
				s.DebugLog("invalid sasl plain format")
				recordMetrics("failure")
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
						recordMetrics("failure")
						if s.handleClientError(writer, "-ERR [AUTH] Invalid impersonation target user format\r\n") {
							return
						}
						continue
					}

					accountID, err = s.server.rdb.GetAccountIDByAddressWithRetry(ctx, address.BaseAddress())
					if err != nil {
						s.DebugLog("failed to get account id for impersonation target user", "target_user", targetUserToImpersonate, "error", err)
						recordMetrics("failure")
						if s.handleClientError(writer, "-ERR [AUTH] Impersonation target user not found\r\n") {
							return
						}
						continue
					}

					impersonating = true
				} else {
					// Record failed master password authentication
					metrics.AuthenticationAttempts.WithLabelValues("pop3", s.server.name, s.server.hostname, "failure").Inc()

					// Master username suffix was provided but master password was wrong - fail immediately
					recordMetrics("failure")
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
						recordMetrics("failure")
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
						recordMetrics("failure")
						if s.handleClientError(writer, "-ERR [AUTH] Invalid impersonation target user format\r\n") {
							return
						}
						continue
					}

					accountID, err = s.server.rdb.GetAccountIDByAddressWithRetry(ctx, address.BaseAddress())
					if err != nil {
						s.DebugLog("failed to get account id for impersonation target user", "authz_id", authzID, "error", err)
						recordMetrics("failure")
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
					recordMetrics("failure")
					if s.handleClientError(writer, "-ERR [AUTH] Proxy authentication requires master_sasl_username and master_sasl_password to be configured\r\n") {
						return
					}
					continue
				}

				// Authenticate the user
				address, err := server.NewAddress(authnID)
				if err != nil {
					s.DebugLog("invalid address format", "error", err)
					recordMetrics("failure")
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
				if err := server.ApplyAuthenticationDelay(ctx, s.server.authLimiter, remoteAddr, "POP3-SASL"); err != nil {
					if errors.Is(err, server.ErrDelayQueueFull) {
						// Delay queue full - reject immediately to prevent goroutine exhaustion
						logger.Info("POP3: Delay queue full, rejecting connection", "address", address.FullAddress(), "ip", s.RemoteIP)
						recordMetrics("failure")
						if s.handleClientError(writer, "-ERR [IN-USE] Too many concurrent authentication attempts. Please try again later.\r\n") {
							return
						}
						continue
					}
					// Context cancelled or other error - close connection
					return
				}

				// Check authentication rate limiting after delay
				if s.server.authLimiter != nil {
					if err := s.server.authLimiter.CanAttemptAuthWithProxy(ctx, netConn, proxyInfo, address.FullAddress()); err != nil {
						s.DebugLog("sasl plain rate limited", "error", err)
						recordMetrics("failure")
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
						recordMetrics("failure")
						if s.handleClientError(writer, "-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n") {
							return
						}
						continue
					}

					// Record failed attempt
					if s.server.authLimiter != nil {
						s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, address.FullAddress(), false)
					}
					recordMetrics("failure")
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
				writer.WriteString("-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n")
				writer.Flush()
				recordMetrics("failure")
				continue
			}
			// Create a context that signals to the DB layer to use the master connection.
			// We will set useMasterDB later under the write lock.
			readCtx := context.WithValue(ctx, consts.UseMasterDBKey, true)

			inboxMailboxID, err := s.server.rdb.GetMailboxByNameWithRetry(readCtx, accountID, consts.MailboxInbox)
			if err != nil {
				s.DebugLog("error getting inbox", "error", err)
				writer.WriteString("-ERR [SYS/TEMP] Service temporarily unavailable, please try again later\r\n")
				writer.Flush()
				recordMetrics("failure")
				continue
			}

			// Acquire write lock to update session state
			acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				recordMetrics("failure")
				continue
			}

			s.inboxMailboxID = inboxMailboxID.ID
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
			s.useMasterDB.Store(true)      // Pin session to master DB after a write to ensure consistency
			release()

			s.server.authenticatedConnections.Add(1)

			// Log authentication success with standardized format
			// Note: Regular auth via Authenticate() already logs in server.go with cached/method
			// For master SASL auth, we log here with method=master
			if impersonating {
				duration := time.Since(start)
				s.InfoLog("authentication successful", "address", authzID, "account_id", accountID, "cached", false, "method", "master", "duration", fmt.Sprintf("%.3fs", duration.Seconds()))
			}

			// Track successful authentication - MUST be before setting authenticated flag
			metrics.AuthenticatedConnectionsCurrent.WithLabelValues("pop3", s.server.name, s.server.hostname).Inc()
			metrics.CriticalOperationDuration.WithLabelValues("pop3_authentication").Observe(time.Since(start).Seconds())

			// IMPORTANT: Set authenticated flag AFTER incrementing both counters to prevent race condition
			s.authenticated.Store(true)

			// Register connection for tracking
			if impersonating {
				s.registerConnection(authzID)
			} else {
				s.registerConnection(authnID)
			}

			// Start termination poller to check for kick commands
			s.startTerminationPoller()

			writer.WriteString("+OK Authentication successful\r\n")

			recordMetrics("success")

		case "LANG":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("pop3", "LANG", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "LANG").Observe(time.Since(start).Seconds())
			}

			// LANG command - set or query language
			// Acquire read lock to access current language
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.WarnLog("failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				recordMetrics("failure")
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
					recordMetrics("failure")
					continue
				}

				// Acquire write lock to update language
				acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
				if !acquired {
					s.WarnLog("failed to acquire write lock within timeout")
					writer.WriteString("-ERR Server busy, please try again\r\n")
					writer.Flush()
					recordMetrics("failure")
					continue
				}

				if langTag == "*" {
					s.language = "en" // Default to English
				} else {
					s.language = langTag
				}
				release()

				writer.WriteString(fmt.Sprintf("+OK Language changed to %s\r\n", s.language))
			}
			s.DebugLog("lang command executed", "current", currentLang)

			recordMetrics("success")

		case "UTF8":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("pop3", "UTF8", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "UTF8").Observe(time.Since(start).Seconds())
			}

			// UTF8 command - enable UTF-8 mode (atomic write, no lock needed)
			s.utf8Mode.Store(true)

			writer.WriteString("+OK UTF8 enabled\r\n")
			s.DebugLog("utf8 mode enabled")

			recordMetrics("success")

		case "QUIT":
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("pop3", "QUIT", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "QUIT").Observe(time.Since(start).Seconds())
			}

			s.DebugLog("quit command received, starting message expunge process")
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.WarnLog("request aborted, aborting quit command")
				recordMetrics("failure")
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
				if s.server.cache != nil {
					if err := s.server.cache.Delete(msg.ContentHash); err != nil && !isNotExist(err) {
						s.WarnLog("failed to delete message from cache", "content_hash", msg.ContentHash, "error", err)
					}
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
					// Track for session summary
					s.messagesExpunged = len(expungeUIDs)
				}
			} else {
				s.DebugLog("no messages to expunge", "mailbox_id", mailboxID)
			}

			userAddress = nil

			writer.WriteString("+OK Goodbye\r\n")
			writer.Flush()

			recordMetrics("success")
			// Return and let defer s.Close() handle cleanup
			return

		case "XCLIENT":
			// XCLIENT command for Dovecot-style parameter forwarding
			start := time.Now()
			recordMetrics := func(status string) {
				metrics.CommandsTotal.WithLabelValues("pop3", "XCLIENT", status).Inc()
				metrics.CommandDuration.WithLabelValues("pop3", "XCLIENT").Observe(time.Since(start).Seconds())
			}

			// Extract the arguments (everything after XCLIENT)
			args := ""
			if len(parts) > 1 {
				args = strings.Join(parts[1:], " ")
			}

			s.handleXCLIENT(args, writer)

			recordMetrics("success")

		case "LAST":
			// LAST is an obsolete command from RFC 1081 (the original POP3),
			// removed in RFC 1939. Some legacy clients still probe for it.
			// Reject it like any unsupported command so the client falls back
			// to UIDL/STAT, but log at debug level since it is a known
			// obsolete command rather than garbage/probing traffic.
			metrics.CommandsTotal.WithLabelValues("pop3", "LAST", "failure").Inc()
			writer.WriteString("-ERR LAST is obsolete (RFC 1939)\r\n")
			s.DebugLog("rejected obsolete command", "command", cmd)

		default:
			metrics.CommandsTotal.WithLabelValues("pop3", "UNKNOWN", "failure").Inc()
			fmt.Fprintf(writer, "-ERR Unknown command: %s\r\n", cmd)
			s.WarnLog("unknown command", "command", cmd, "line", helpers.MaskSensitive(line, cmd, "PASS", "AUTH"))
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
	duration := time.Since(s.startTime)
	metrics.ConnectionDuration.WithLabelValues("pop3", s.server.name, s.server.hostname).Observe(duration.Seconds())

	// Log and record peak memory usage
	if s.memTracker != nil {
		peak := s.memTracker.Peak()
		metrics.SessionMemoryPeakBytes.WithLabelValues("pop3", s.server.name, s.server.hostname).Observe(float64(peak))
		if peak > 0 {
			s.DebugLog("session memory peak", "peak", server.FormatBytes(peak))
		}
	}

	// Log session summary with statistics (similar to Dovecot)
	if s.messagesRetrieved > 0 || s.messagesDeleted > 0 || s.messagesExpunged > 0 {
		s.InfoLog("session summary",
			"duration", fmt.Sprintf("%.1fs", duration.Seconds()),
			"retrieved", s.messagesRetrieved,
			"deleted", s.messagesDeleted,
			"expunged", s.messagesExpunged)
	}

	totalCount := s.server.totalConnections.Add(-1)
	var authCount int64 = 0

	// Prometheus metrics - connection closed
	metrics.ConnectionsCurrent.WithLabelValues("pop3", s.server.name, s.server.hostname).Dec()

	(*s.conn).Close()

	// Remove session from active tracking
	s.server.removeSession(s)

	// Release connection from limiter
	if s.releaseConn != nil {
		s.releaseConn()
		s.releaseConn = nil // Prevent double release
	}

	if s.User != nil {
		if s.authenticated.Load() {
			authCount = s.server.authenticatedConnections.Add(-1)
			metrics.AuthenticatedConnectionsCurrent.WithLabelValues("pop3", s.server.name, s.server.hostname).Dec()

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
		s.authenticated.Store(false)

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

// errBodyTransientlyUnavailable marks a message body that exists (or will shortly) but
// cannot be retrieved from this node right now. Two causes feed it, both transient:
//   - not yet uploaded: staged for upload, not on local disk here and not in S3 yet
//     (the upload worker will land it shortly); see bodyUploadStillPending.
//   - S3 unavailable: the message is uploaded but S3 is unreachable (network/timeout/
//     5xx/circuit-open) — distinct from a 404/NoSuchKey, which is permanent loss.
//
// RETR/TOP answer it with -ERR [SYS/TEMP] ... please try again later so the client
// retries (and does not DELE), rather than -ERR Message not available which reads as a
// permanent failure. The wrapping error text carries the specific cause for logging.
var errBodyTransientlyUnavailable = errors.New("message body temporarily unavailable")

// pop3BodyFetchRetry* tune the bounded retry of the S3 read on the not-yet-uploaded path.
// They absorb the read-before-write race where the background S3 PUT lands shortly after
// the fetch (e.g. a cross-node delivery still uploading). The wait is only ever spent
// when an upload is still pending (loadMessageBody gates on bodyUploadStillPending), so a
// body that is never coming is not waited on; and because a transient result aborts the
// connection/session command, at most one message per command pays it. The window is generous:
// ~(pop3BodyFetchRetryAttempts-1) * pop3BodyFetchRetryDelay ≈ 1s.
const (
	pop3BodyFetchRetryAttempts = 3
	pop3BodyFetchRetryDelay    = 500 * time.Millisecond
)

func (s *POP3Session) getMessageBody(msg *db.Message) ([]byte, error) {
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted, aborting message body fetch")
		return nil, fmt.Errorf("request aborted")
	}

	data, err := s.loadMessageBody(msg)
	if err != nil {
		return nil, err
	}

	// Single accounting point for every source in loadMessageBody (cache, S3, disk).
	if s.memTracker != nil {
		if allocErr := s.memTracker.Allocate(int64(len(data))); allocErr != nil {
			metrics.SessionMemoryLimitExceeded.WithLabelValues("pop3", s.server.name, s.server.hostname).Inc()
			return nil, fmt.Errorf("session memory limit exceeded: %v", allocErr)
		}
	}
	return data, nil
}

// loadMessageBody returns the raw message body from the fastest available source.
// Preference order:
//   - uploaded messages:     local cache → S3 → local staging disk (S3 outage)
//   - not-yet-uploaded msgs: local staging disk → S3 (cross-node / late-upload race)
func (s *POP3Session) loadMessageBody(msg *db.Message) ([]byte, error) {
	if msg.IsUploaded {
		// Try cache first (nil-safe: cache is optional and not configured in tests).
		if s.server.cache != nil {
			if cacheData, cacheErr := s.server.cache.Get(msg.ContentHash); cacheErr == nil && cacheData != nil {
				// Validate cached data is not empty
				if len(cacheData) == 0 {
					logger.Warn("POP3: Cache contains empty body, falling through to S3", "uid", msg.UID, "content_hash", msg.ContentHash)
				} else {
					logger.Debug("POP3: Cache hit", "uid", msg.UID)
					return cacheData, nil
				}
			}
		}

		// Fallback to S3
		logger.Debug("POP3: Cache miss - fetching from S3", "uid", msg.UID, "hash", msg.ContentHash)
		data, err := s.fetchBodyFromS3(msg)
		if err != nil {
			// S3 is unavailable — fall back to the local staging file if the uploader
			// still has it. This covers test environments (where S3 is a no-op stub)
			// and transient S3 outages where the upload worker has not yet run.
			if s.server.uploader != nil {
				filePath := s.server.uploader.FilePath(msg.ContentHash, msg.AccountID)
				if diskData, diskErr := os.ReadFile(filePath); diskErr == nil && len(diskData) > 0 {
					logger.Debug("POP3: S3 unavailable, served from local disk", "uid", msg.UID)
					return diskData, nil
				}
			}
			// The message is marked uploaded but S3 could not serve it and the local
			// staging copy is gone. Distinguish a transient S3 outage (network/timeout/
			// 5xx/circuit-open) from a genuinely missing object (404/NoSuchKey): on a
			// transient failure ask the client to retry (RETR/TOP -> -ERR [SYS/TEMP])
			// instead of reporting the message permanently gone. A NoSuchKey maps to
			// -ERR Message not available (the object is permanently lost).
			// Only a genuine S3-reachability failure is transient. fetchBodyFromS3 wraps
			// such failures (network/timeout/5xx/circuit-open) in ErrRetrieveFailed; it
			// also wraps NoSuchKey there, which IsNotFoundError excludes. Permanent
			// conditions (empty/0-byte object, missing S3 key, read error) are NOT
			// ErrRetrieveFailed and must NOT be reported transient, or the client would
			// retry forever instead of getting -ERR Message not available.
			if errors.Is(err, storage.ErrRetrieveFailed) && !resilient.IsNotFoundError(err) {
				return nil, fmt.Errorf("message UID %d: %w (S3 unavailable): %v", msg.UID, errBodyTransientlyUnavailable, err)
			}
			// Permanent. A NoSuchKey on an uploaded message is genuine content loss worth
			// alerting on — logged only here, where the message is marked uploaded (a 404
			// during the not-yet-uploaded race is expected and not logged). RETR/TOP map
			// ErrMessageNotAvailable to -ERR Message not available.
			if resilient.IsNotFoundError(err) {
				s.WarnLog("message marked uploaded but missing from S3 (NoSuchKey)", "uid", msg.UID, "content_hash", msg.ContentHash, "s3_domain", msg.S3Domain, "s3_localpart", msg.S3Localpart)
			}
			return nil, consts.ErrMessageNotAvailable
		}
		return data, nil
	}

	// Not yet uploaded to S3: the body should be in this node's local staging dir.
	if s.server.uploader == nil {
		logger.Debug("POP3: No uploader configured, message not available", "uid", msg.UID)
		return nil, consts.ErrMessageNotAvailable
	}
	logger.Debug("POP3: Fetching not yet uploaded message from disk", "uid", msg.UID)
	filePath := s.server.uploader.FilePath(msg.ContentHash, msg.AccountID)
	if data, diskErr := os.ReadFile(filePath); diskErr == nil && len(data) > 0 {
		return data, nil
	}

	// Local staging file is missing or empty. In a multi-backend cluster the body may
	// have been delivered/staged on another node and already uploaded to S3, while this
	// node's in-memory message still reads uploaded=false. Try S3 with the stored key —
	// with a short bounded retry to absorb the read-before-write race where the S3 PUT
	// lands within the same second as this fetch. NoSuchKey fails fast, so each miss is cheap.
	//
	// Decide up front whether the body is still expected to arrive. We only wait-and-retry
	// S3 when it is: there is no point sleeping for a body that is never coming.
	pending := s.bodyUploadStillPending(msg)

	if msg.S3Domain != "" && msg.S3Localpart != "" {
		attempts := 1
		if pending {
			attempts = pop3BodyFetchRetryAttempts
		}
		for attempt := 0; attempt < attempts; attempt++ {
			s3Data, s3Err := s.fetchBodyFromS3(msg)
			if s3Err == nil {
				logger.Debug("POP3: local staging file missing, served from S3", "uid", msg.UID, "attempt", attempt)
				return s3Data, nil
			}
			// Only NoSuchKey ("object hasn't landed yet") benefits from waiting and
			// retrying. Any other error is either a transient outage that GetWithRetry
			// already exhausted its own backoff on (looping would just multiply that
			// latency) or a permanent condition — stop and let classification decide.
			if !resilient.IsNotFoundError(s3Err) {
				break
			}
			if attempt < attempts-1 {
				select {
				case <-time.After(pop3BodyFetchRetryDelay):
				case <-s.ctx.Done():
					return nil, s.ctx.Err()
				}
			}
		}
	}

	// Body still unavailable. Distinguish transient from permanent: if the upload is still
	// pending (or the message has since been marked uploaded), the body is in flight — tell
	// the client to retry (errBodyTransientlyUnavailable -> -ERR [SYS/TEMP] ... try again later, and
	// the client must not DELE). Otherwise the content is genuinely gone, which RETR/TOP map
	// to -ERR Message not available.
	if pending {
		return nil, errBodyTransientlyUnavailable
	}
	logger.Debug("POP3: message body not on disk and not in S3, content unavailable", "uid", msg.UID, "hash", msg.ContentHash)
	return nil, consts.ErrMessageNotAvailable
}

// bodyUploadStillPending reports whether the system still intends to make this body
// available — i.e. a pending_upload record exists, or the message has since been marked
// uploaded (so a retry should find it in S3). It distinguishes the transient
// read-before-upload race from genuine, permanent content loss. On a DB error it returns
// true (conservative: a client retry is safer than reporting the message permanently gone).
func (s *POP3Session) bodyUploadStillPending(msg *db.Message) bool {
	pending, err := s.server.rdb.PendingUploadExistsWithRetry(s.ctx, msg.ContentHash, msg.AccountID)
	if err != nil {
		s.WarnLog("could not check pending-upload status; treating body as transiently unavailable", "uid", msg.UID, "error", err)
		return true
	}
	if pending {
		return true
	}
	uploaded, err := s.server.rdb.IsContentHashUploadedWithRetry(s.ctx, msg.ContentHash, msg.AccountID)
	if err != nil {
		s.WarnLog("could not check uploaded status; treating body as transiently unavailable", "uid", msg.UID, "error", err)
		return true
	}
	return uploaded
}

// fetchBodyFromS3 retrieves a message body from S3 using the key components
// stored on the message record. It validates the payload is non-empty and warms
// the local cache on success.
func (s *POP3Session) fetchBodyFromS3(msg *db.Message) ([]byte, error) {
	if msg.S3Domain == "" || msg.S3Localpart == "" {
		return nil, fmt.Errorf("message UID %d is missing S3 key information", msg.UID)
	}
	s3Key := helpers.NewS3Key(msg.S3Domain, msg.S3Localpart, msg.ContentHash)

	// Guard against a nil-client panic (e.g. test stubs using &storage.S3Storage{})
	// so it becomes an error rather than killing the connection goroutine.
	var reader io.ReadCloser
	var s3GetErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				s3GetErr = fmt.Errorf("S3 get panicked: %v", r)
			}
		}()
		reader, s3GetErr = s.server.s3.GetWithRetry(s.server.appCtx, s3Key)
	}()
	if s3GetErr != nil {
		logger.Debug("POP3: S3 GetWithRetry failed", "uid", msg.UID, "s3_key", s3Key, "error", s3GetErr)
		return nil, fmt.Errorf("message UID %d: %w: %w", msg.UID, storage.ErrRetrieveFailed, s3GetErr)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		logger.Debug("POP3: failed to read S3 response", "uid", msg.UID, "error", err)
		return nil, err
	}
	if len(data) == 0 {
		logger.Warn("POP3: Retrieved empty body from S3", "uid", msg.UID, "hash", msg.ContentHash, "s3_key", s3Key)
		return nil, fmt.Errorf("message UID %d (hash: %s): %w", msg.UID, msg.ContentHash, storage.ErrEmptyData)
	}

	logger.Debug("POP3: successfully fetched from S3", "uid", msg.UID, "size", len(data))
	if s.server.cache != nil {
		_ = s.server.cache.Put(msg.ContentHash, data)
	}
	return data, nil
}

// registerConnection registers the connection in the connection tracker
func (s *POP3Session) registerConnection(email string) {
	if s.server.connTracker != nil && s.authenticated.Load() {
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
	if s.server.connTracker != nil && s.authenticated.Load() {
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
	if s.server.connTracker == nil || !s.authenticated.Load() {
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

// isConnectionSecure checks if the underlying connection is TLS-encrypted.
// Used when insecure_auth is false to reject auth over non-TLS connections.
func (s *POP3Session) isConnectionSecure() bool {
	if s.conn == nil || *s.conn == nil {
		return false
	}
	conn := *s.conn
	// Check if the connection itself is TLS
	if _, ok := conn.(*tls.Conn); ok {
		return true
	}
	// Unwrap connection layers to find TLS
	currentConn := conn
	for currentConn != nil {
		if _, ok := currentConn.(*tls.Conn); ok {
			return true
		}
		if wrapper, ok := currentConn.(interface{ Unwrap() net.Conn }); ok {
			currentConn = wrapper.Unwrap()
		} else {
			break
		}
	}
	return false
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
