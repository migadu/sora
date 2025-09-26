package pop3

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

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
	*server.User                // User associated with the session
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
}

func (s *POP3Session) handleConnection() {
	defer s.cancel()

	defer s.Close()
	reader := bufio.NewReader(*s.conn)
	writer := bufio.NewWriter(*s.conn)

	writer.WriteString("+OK POP3 server ready\r\n")
	writer.Flush()

	s.Log("connected")

	ctx := s.ctx
	var userAddress *server.Address

	for {
		(*s.conn).SetReadDeadline(time.Now().Add(Pop3IdleTimeout))

		line, err := reader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				writer.WriteString("-ERR Connection timed out due to inactivity\r\n")
				writer.Flush()
				s.Log("timed out - connection closed WITHOUT calling QUIT (messages not expunged)")
			} else if err == io.EOF {
				// Client closed connection without QUIT
				s.Log("CLIENT DROPPED CONNECTION WITHOUT CALLING QUIT - messages marked for deletion will NOT be expunged!")
			} else {
				s.Log("error: %v", err)
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

		s.Log("C: %s", helpers.MaskSensitive(line, cmd, "PASS", "AUTH"))

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
				s.Log("WARNING: context cancelled, aborting USER command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
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
			newUserAddress, err := server.NewAddress(parts[1])
			if err != nil {
				s.Log("error: %v", err)
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
				s.Log("WARNING: context cancelled, aborting PASS command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
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
				s.Log("PASS without USER")
				writer.WriteString("-ERR Must provide USER first\r\n")
				writer.Flush()
				continue
			}

			s.Log("authentication attempt for %s", userAddress.FullAddress())

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
					s.Log("[PASS] rate limited: %v", err)
					// Track rate limiting
					metrics.AuthenticationAttempts.WithLabelValues("pop3", "rate_limited").Inc()
					if s.handleClientError(writer, "-ERR [LOGIN-DELAY] Too many authentication attempts. Please try again later.\r\n") {
						return
					}
					continue
				}
			}

			// Try master password authentication first
			authSuccess := false
			var userID int64
			if len(s.server.masterSASLUsername) > 0 && len(s.server.masterSASLPassword) > 0 {
				if userAddress.FullAddress() == string(s.server.masterSASLUsername) && parts[1] == string(s.server.masterSASLPassword) {
					s.Log("[PASS] Master password authentication successful for '%s'", userAddress.FullAddress())
					authSuccess = true
					// For master password, we need to get the user ID
					userID, err = s.server.rdb.GetAccountIDByAddressWithRetry(ctx, userAddress.FullAddress())
					if err != nil {
						s.Log("[PASS] Failed to get account ID for master user '%s': %v", userAddress.FullAddress(), err)
						// Record failed attempt
						if s.server.authLimiter != nil {
							s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, userAddress.FullAddress(), false)
						}
						if s.handleClientError(writer, "-ERR [AUTH] Authentication failed\r\n") {
							s.Log("authentication failed")
							return
						}
						continue
					}
				}
			}

			// If master password didn't work, try regular authentication
			if !authSuccess {
				userID, err = s.server.rdb.AuthenticateWithRetry(ctx, userAddress.FullAddress(), parts[1])
				if err != nil {
					// Record failed attempt
					if s.server.authLimiter != nil {
						s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, userAddress.FullAddress(), false)
					}
					// Track failed authentication
					metrics.AuthenticationAttempts.WithLabelValues("pop3", "failure").Inc()
					metrics.CriticalOperationDuration.WithLabelValues("pop3_authentication").Observe(time.Since(start).Seconds())
					if s.handleClientError(writer, "-ERR [AUTH] Authentication failed\r\n") {
						s.Log("authentication failed")
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
			err = s.server.rdb.CreateDefaultMailboxesWithRetry(ctx, userID)
			if err != nil {
				s.Log("USER error creating default mailboxes: %v", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}
			// Create a context that signals to the DB layer to use the master connection.
			// We will set useMasterDB later under the write lock.
			readCtx := context.WithValue(ctx, consts.UseMasterDBKey, true)

			inboxMailboxID, err := s.server.rdb.GetMailboxByNameWithRetry(readCtx, userID, consts.MailboxInbox)
			if err != nil {
				s.Log("USER error getting INBOX: %v", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}

			// Acquire write lock to update session state
			acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			s.inboxMailboxID = inboxMailboxID.ID
			s.authenticated = true
			s.deleted = make(map[int]bool) // Initialize deletion map on authentication
			s.useMasterDB = true           // Pin session to master DB after a write to ensure consistency
			release()
			authCount := s.server.authenticatedConnections.Add(1)
			totalCount := s.server.totalConnections.Load()
			s.Log("authenticated (connections: total=%d, authenticated=%d)", totalCount, authCount)

			// Track successful authentication
			metrics.AuthenticationAttempts.WithLabelValues("pop3", "success").Inc()
			metrics.AuthenticatedConnectionsCurrent.WithLabelValues("pop3").Inc()
			metrics.CriticalOperationDuration.WithLabelValues("pop3_authentication").Observe(time.Since(start).Seconds())

			// Track domain and user connection activity
			if s.User != nil {
				metrics.TrackDomainConnection("pop3", s.Domain())
				metrics.TrackUserActivity("pop3", s.FullAddress(), "connection", 1)
			}

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
				s.Log("WARNING: context cancelled, aborting STAT command")
				return
			}

			// Acquire read lock to check inbox mailbox ID
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
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
				s.Log("STAT error: %v", err)
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
				s.Log("WARNING: context cancelled, aborting LIST command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
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
				s.Log("LIST error: %v", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}

			// Acquire write lock to update session state and read the data
			acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}
			s.messages = messages
			s.Log("LIST: Loaded %d messages from database for mailbox %d", len(messages), mailboxID)

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
			s.Log("listed %d messages", len(s.messages))

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
				s.Log("WARNING: context cancelled, aborting UIDL command")
				return
			}

			// Acquire read lock to check authentication state and loading needs
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
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
					s.Log("UIDL error: %v", err)
					writer.WriteString("-ERR Internal server error\r\n")
					writer.Flush()
					continue
				}

				// Acquire write lock to update session state
				acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
				if !acquired {
					s.Log("WARNING: failed to acquire write lock within timeout")
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
					s.Log("WARNING: failed to acquire read lock within timeout")
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
					s.Log("WARNING: failed to acquire read lock within timeout")
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
			s.Log("UIDL command executed")
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
				s.Log("WARNING: context cancelled, aborting TOP command")
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
				s.Log("WARNING: failed to acquire read lock within timeout")
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
					s.Log("TOP error: %v", err)
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
				s.Log("WARNING: failed to acquire lock for TOP command")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			// If we loaded messages, update the session state.
			if needsLoading {
				s.messages = loadedMessages
				s.Log("TOP: Loaded %d messages from database for mailbox %d", len(s.messages), mailboxID)
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

			log.Printf("fetching message headers for UID %d", msg.UID)
			bodyData, err := s.getMessageBody(&msg)
			if err != nil {
				if err == consts.ErrMessageNotAvailable {
					writer.WriteString("-ERR Message not available\r\n")
				} else {
					s.Log("TOP internal error: %v", err)
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
				writer.WriteString(fmt.Sprintf("+OK %d octets\r\n", len(result)))
				writer.WriteString(result)
				writer.WriteString("\r\n.\r\n")
				s.Log("retrieved headers for message %d", msg.UID)
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

			writer.WriteString(fmt.Sprintf("+OK %d octets\r\n", len(result)))
			writer.WriteString(result)
			writer.WriteString("\r\n.\r\n")
			s.Log("retrieved top %d lines of message %d", lines, msg.UID)
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
				s.Log("WARNING: context cancelled, aborting RETR command")
				return
			}

			// Phase 1: Read session state to determine if messages need loading.
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
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
					s.Log("RETR error: %v", err)
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
				s.Log("WARNING: failed to acquire lock for RETR command")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			if needsLoading {
				s.messages = loadedMessages
				s.Log("RETR: Loaded %d messages from database for mailbox %d", len(s.messages), mailboxID)
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

			log.Printf("fetching message body for UID %d", msg.UID)
			bodyData, err := s.getMessageBody(&msg)
			if err != nil {
				if err == consts.ErrMessageNotAvailable {
					writer.WriteString("-ERR Message not available\r\n")
				} else {
					s.Log("RETR internal error: %v", err)
					writer.WriteString("-ERR Internal server error\r\n")
				}
				writer.Flush()
				continue
			}
			s.Log("retrieved message body for UID %d", msg.UID)

			writer.WriteString(fmt.Sprintf("+OK %d octets\r\n", msg.Size))
			writer.WriteString(string(bodyData))
			writer.WriteString("\r\n.\r\n")
			s.Log("retrieved message %d", msg.UID)

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
				s.Log("WARNING: context cancelled, aborting RSET command")
				return
			}

			// Acquire write lock to update deleted map
			acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}
			defer release()
			s.deleted = make(map[int]bool)

			writer.WriteString("+OK\r\n")
			s.Log("reset")
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
				s.Log("WARNING: context cancelled, aborting DELE command")
				return
			}

			if len(parts) < 2 {
				log.Printf("missing message number")
				if s.handleClientError(writer, "-ERR Missing message number\r\n") {
					return
				}
				continue
			}

			msgNumber, err := strconv.Atoi(parts[1])
			if err != nil || msgNumber < 1 {
				s.Log("DELE error: %v", err)
				if s.handleClientError(writer, "-ERR Invalid message number\r\n") {
					return
				}
				continue
			}

			// Phase 1: Read session state to determine if messages need loading.
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock for DELE command")
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
					s.Log("DELE error: %v", err)
					writer.WriteString("-ERR Internal server error\r\n")
					writer.Flush()
					continue
				}
			}

			// Phase 3: Acquire write lock to update session state.
			acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire write lock for DELE command")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			// If we loaded messages, update the session state.
			if needsLoading {
				s.messages = loadedMessages
				s.Log("DELE: Loaded %d messages from database for mailbox %d", len(s.messages), mailboxID)
			}

			// Validate message bounds and perform deletion
			if msgNumber > len(s.messages) {
				release()
				s.Log("DELE error: no such message %d", msgNumber)
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			msg := s.messages[msgNumber-1]
			if msg.UID == 0 {
				release()
				s.Log("DELE error: no such message %d", msgNumber)
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			s.deleted[msgNumber-1] = true
			release()

			writer.WriteString("+OK Message deleted\r\n")
			s.Log("DELE: marked message %d (UID %d) for deletion in mailbox %d. Total deleted: %d", msgNumber, msg.UID, mailboxID, len(s.deleted))

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
				s.Log("WARNING: context cancelled, aborting AUTH command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
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

			mechanism := strings.ToUpper(parts[1])
			if mechanism != "PLAIN" {
				if s.handleClientError(writer, "-ERR Unsupported authentication mechanism\r\n") {
					return
				}
				continue
			}

			// Check if initial response is provided
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
					s.Log("error reading auth data: %v", err)
					if s.handleClientError(writer, "-ERR Authentication failed\r\n") {
						return
					}
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
				s.Log("error decoding auth data: %v", err)
				if s.handleClientError(writer, "-ERR [AUTH] Invalid authentication data\r\n") {
					return
				}
				continue
			}

			// Parse SASL PLAIN format: [authz-id] \0 authn-id \0 password
			parts := strings.Split(string(decoded), "\x00")
			if len(parts) != 3 {
				s.Log("invalid SASL PLAIN format")
				if s.handleClientError(writer, "-ERR [AUTH] Invalid authentication format\r\n") {
					return
				}
				continue
			}

			authzID := parts[0]  // Authorization identity (who to act as)
			authnID := parts[1]  // Authentication identity (who is authenticating)
			password := parts[2] // Password

			s.Log("[SASL PLAIN] AuthorizationID: '%s', AuthenticationID: '%s'", authzID, authnID)

			// Check for Master SASL Authentication
			var userID int64
			var impersonating bool

			if len(s.server.masterSASLUsername) > 0 && len(s.server.masterSASLPassword) > 0 {
				// Check if this is a master SASL login
				if authnID == string(s.server.masterSASLUsername) && password == string(s.server.masterSASLPassword) {
					// Master SASL authentication successful
					if authzID == "" {
						s.Log("[AUTH] Master SASL authentication for '%s' successful, but no authorization identity provided.", authnID)
						if s.handleClientError(writer, "-ERR [AUTH] Master SASL login requires an authorization identity.\r\n") {
							return
						}
						continue
					}

					s.Log("[AUTH] Master SASL user '%s' authenticated. Attempting to impersonate '%s'.", authnID, authzID)

					// Log in as the authzID without a password check
					address, err := server.NewAddress(authzID)
					if err != nil {
						s.Log("[AUTH] Failed to parse impersonation target user '%s': %v", authzID, err)
						if s.handleClientError(writer, "-ERR [AUTH] Invalid impersonation target user format\r\n") {
							return
						}
						continue
					}

					userID, err = s.server.rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
					if err != nil {
						s.Log("[AUTH] Failed to get account ID for impersonation target user '%s': %v", authzID, err)
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
					s.Log("proxy authentication not supported: authz='%s', authn='%s'", authzID, authnID)
					if s.handleClientError(writer, "-ERR [AUTH] Proxy authentication not supported\r\n") {
						return
					}
					continue
				}

				// Authenticate the user
				address, err := server.NewAddress(authnID)
				if err != nil {
					s.Log("invalid address format: %v", err)
					if s.handleClientError(writer, "-ERR [AUTH] Invalid username format\r\n") {
						return
					}
					continue
				}

				s.Log("authentication attempt for %s", address.FullAddress())

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
						s.Log("[SASL PLAIN] rate limited: %v", err)
						if s.handleClientError(writer, "-ERR [LOGIN-DELAY] Too many authentication attempts. Please try again later.\r\n") {
							return
						}
						continue
					}
				}

				userID, err = s.server.rdb.AuthenticateWithRetry(ctx, address.FullAddress(), password)
				if err != nil {
					// Record failed attempt
					if s.server.authLimiter != nil {
						s.server.authLimiter.RecordAuthAttemptWithProxy(ctx, netConn, proxyInfo, address.FullAddress(), false)
					}
					if s.handleClientError(writer, "-ERR [AUTH] Authentication failed\r\n") {
						s.Log("authentication failed")
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
			err = s.server.rdb.CreateDefaultMailboxesWithRetry(ctx, userID)
			if err != nil {
				s.Log("AUTH error creating default mailboxes: %v", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}
			// Create a context that signals to the DB layer to use the master connection.
			// We will set useMasterDB later under the write lock.
			readCtx := context.WithValue(ctx, consts.UseMasterDBKey, true)

			inboxMailboxID, err := s.server.rdb.GetMailboxByNameWithRetry(readCtx, userID, consts.MailboxInbox)
			if err != nil {
				s.Log("AUTH error getting INBOX: %v", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}

			// Acquire write lock to update session state
			acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			s.inboxMailboxID = inboxMailboxID.ID
			s.authenticated = true
			s.deleted = make(map[int]bool) // Initialize deletion map on authentication
			s.useMasterDB = true           // Pin session to master DB after a write to ensure consistency
			release()

			authCount := s.server.authenticatedConnections.Add(1)
			totalCount := s.server.totalConnections.Load()
			if impersonating {
				s.Log("authenticated via Master SASL PLAIN as '%s' (connections: total=%d, authenticated=%d)", authzID, totalCount, authCount)
			} else {
				s.Log("authenticated via SASL PLAIN (connections: total=%d, authenticated=%d)", totalCount, authCount)
			}

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
				s.Log("WARNING: failed to acquire read lock within timeout")
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
					s.Log("WARNING: failed to acquire write lock within timeout")
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
			s.Log("LANG command: current=%s", currentLang)
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
				s.Log("WARNING: failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			s.utf8Mode = true
			release()

			writer.WriteString("+OK UTF8 enabled\r\n")
			s.Log("UTF8 mode enabled")
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

			s.Log("QUIT: Command received, starting message expunge process")
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("WARNING: context cancelled, aborting QUIT command")
				return
			}

			// Phase 1: Collect messages to expunge under a read lock.
			var messagesToExpunge []db.Message
			var mailboxID int64
			acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("QUIT: Failed to acquire read lock, cannot expunge messages.")
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
				s.Log("QUIT: Will expunge message UID %d", msg.UID)
				// Delete from cache before expunging
				if err := s.server.cache.Delete(msg.ContentHash); err != nil && !isNotExist(err) {
					s.Log("[CACHE] WARNING: failed to delete message %s from cache: %v", msg.ContentHash, err)
				}
				expungeUIDs = append(expungeUIDs, msg.UID)
			}

			if len(expungeUIDs) > 0 {
				s.Log("expunging %d messages from mailbox %d: %v", len(expungeUIDs), mailboxID, expungeUIDs)
				_, err = s.server.rdb.ExpungeMessageUIDsWithRetry(ctx, mailboxID, expungeUIDs...)
				if err != nil {
					s.Log("error expunging messages from mailbox %d: %v", mailboxID, err)
				} else {
					s.Log("successfully expunged %d messages from mailbox %d", len(expungeUIDs), mailboxID)
				}
			} else {
				s.Log("no messages to expunge from mailbox %d", mailboxID)
			}

			userAddress = nil

			writer.WriteString("+OK Goodbye\r\n")
			writer.Flush()
			s.Close()
			success = true
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
			s.Log("unknown command: %s", cmd)
		}
		writer.Flush()
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

func (s *POP3Session) Close() error {
	acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.Log("failed to acquire write lock within timeout")
		// Still close the connection even if we can't acquire the lock
		(*s.conn).Close()
		// Release connection from limiter
		if s.releaseConn != nil {
			s.releaseConn()
			s.releaseConn = nil // Prevent double release
		}
		if s.cancel != nil {
			s.cancel()
		}
		return nil
	}
	defer release()

	metrics.ConnectionDuration.WithLabelValues("pop3").Observe(time.Since(s.startTime).Seconds())

	totalCount := s.server.totalConnections.Add(-1)
	var authCount int64 = 0

	// Prometheus metrics - connection closed
	metrics.ConnectionsCurrent.WithLabelValues("pop3").Dec()

	(*s.conn).Close()

	// Release connection from limiter
	if s.releaseConn != nil {
		s.releaseConn()
		s.releaseConn = nil // Prevent double release
	}

	if s.User != nil {
		if s.authenticated {
			authCount = s.server.authenticatedConnections.Add(-1)
			metrics.AuthenticatedConnectionsCurrent.WithLabelValues("pop3").Dec()
		} else {
			authCount = s.server.authenticatedConnections.Load()
		}
		s.Log("closed (connections: total=%d, authenticated=%d)", totalCount, authCount)

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
		s.Log("closed unauthenticated connection (connections: total=%d, authenticated=%d)",
			totalCount, authCount)
	}
	return nil
}

func (s *POP3Session) getMessageBody(msg *db.Message) ([]byte, error) {
	if s.ctx.Err() != nil {
		s.Log("context cancelled, aborting message body fetch")
		return nil, fmt.Errorf("context cancelled")
	}

	if msg.IsUploaded {
		// Try cache first
		data, err := s.server.cache.Get(msg.ContentHash)
		if err == nil && data != nil {
			log.Printf("[CACHE] hit for UID %d", msg.UID)
			return data, nil
		}

		// Fallback to S3
		log.Printf("[CACHE] miss for UID %d, fetching from S3 (%s)", msg.UID, msg.ContentHash)
		address, err := s.server.rdb.GetPrimaryEmailForAccountWithRetry(s.ctx, msg.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to get primary address for account %d: %w", msg.UserID, err)
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
		// Store in cache
		log.Printf("[CACHE] storing UID %d in cache (%s)", msg.UID, msg.ContentHash)
		_ = s.server.cache.Put(msg.ContentHash, data)
		return data, nil
	}

	// If not uploaded to S3, try fetch from local disk
	log.Printf("fetching not yet uploaded message UID %d from disk", msg.UID)
	filePath := s.server.uploader.FilePath(msg.ContentHash, msg.UserID)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("message UID %d (hash %s) not found locally and not marked as uploaded. Assuming pending remote processing.", msg.UID, msg.ContentHash)
			return nil, consts.ErrMessageNotAvailable
		}
		// Other error trying to access the local file
		return nil, fmt.Errorf("error retrieving message UID %d from local disk: %w", msg.UID, err)
	}
	if data == nil { // Should ideally not happen if GetLocalFile returns nil, nil for "not found"
		return nil, fmt.Errorf("message UID %d (hash %s) not found on disk (GetLocalFile returned nil data, nil error)", msg.UID, msg.ContentHash)
	}
	return data, nil
}
