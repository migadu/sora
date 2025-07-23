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
				s.Log("timed out")
			} else if err == io.EOF {
				// Client closed connection without QUIT
				s.Log("client dropped connection")
			} else {
				s.Log("error: %v", err)
			}
			return
		}

		line = strings.TrimSpace(line)
		parts := strings.Split(line, " ")
		cmd := strings.ToUpper(parts[0])

		switch cmd {
		case "CAPA":
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

		case "USER":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("WARNING: context cancelled, aborting USER command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			isAuthenticated := s.authenticated
			s.mutex.RUnlock()
			cancel()

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

		case "PASS":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("WARNING: context cancelled, aborting PASS command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			isAuthenticated := s.authenticated
			s.mutex.RUnlock()
			cancel()

			if isAuthenticated {
				writer.WriteString("-ERR Already authenticated\r\n")
				writer.Flush()
				continue
			}

			if userAddress == nil {
				s.Log("PASS without USER")
				writer.WriteString("-ERR Must provide USER first\r\n")
				writer.Flush()
				continue
			}

			s.Log("authentication attempt for %s", userAddress.FullAddress())

			userID, err := s.server.db.Authenticate(ctx, userAddress.FullAddress(), parts[1])
			if err != nil {
				if s.handleClientError(writer, "-ERR [AUTH] Authentication failed\r\n") {
					s.Log("authentication failed")
					return
				}
				continue
			}

			// No auto-creation of mailboxes, they have to exist already for POP3
			inboxMailboxID, err := s.server.db.GetMailboxByName(ctx, userID, consts.MailboxInbox)
			if err != nil {
				if err == consts.ErrMailboxNotFound {
					if s.handleClientError(writer, fmt.Sprintf("-ERR %s\r\n", err.Error())) {
						return
					}
					continue
				}
				s.Log("USER error: %v", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}

			// Acquire write lock to update session state
			acquired, cancel = s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			s.inboxMailboxID = inboxMailboxID.ID
			s.authenticated = true
			s.mutex.Unlock()
			cancel()

			authCount := s.server.authenticatedConnections.Add(1)
			totalCount := s.server.totalConnections.Load()
			s.Log("authenticated (connections: total=%d, authenticated=%d)", totalCount, authCount)

			writer.WriteString("+OK Password accepted\r\n")

		case "STAT":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("WARNING: context cancelled, aborting STAT command")
				return
			}

			// Acquire read lock to check inbox mailbox ID
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			mailboxID := s.inboxMailboxID
			s.mutex.RUnlock()
			cancel()

			messagesCount, size, err := s.server.db.GetMailboxMessageCountAndSizeSum(ctx, mailboxID)
			if err != nil {
				s.Log("STAT error: %v", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}
			writer.WriteString(fmt.Sprintf("+OK %d %d\r\n", messagesCount, size))

		case "LIST":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("WARNING: context cancelled, aborting LIST command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			isAuthenticated := s.authenticated
			mailboxID := s.inboxMailboxID
			s.mutex.RUnlock()
			cancel()

			if !isAuthenticated {
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
			}

			messages, err := s.server.db.ListMessages(ctx, mailboxID)
			if err != nil {
				s.Log("LIST error: %v", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}

			// Acquire write lock to update session state and read the data
			acquired, cancel = s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			s.messages = messages

			// Build response while still holding the write lock (we can read our own write)
			if len(messages) == 0 {
				s.mutex.Unlock()
				cancel()
				writer.WriteString("+OK 0 messages\r\n.\r\n")
			} else {
				writer.WriteString("+OK scan listing follows\r\n")
				for i, msg := range messages {
					if !s.deleted[i] {
						writer.WriteString(fmt.Sprintf("%d %d\r\n", i+1, msg.Size))
					}
				}
				s.mutex.Unlock()
				cancel()
				writer.WriteString(".\r\n")
			}
			s.Log("listed %d messages", len(s.messages))

		case "UIDL":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("WARNING: context cancelled, aborting UIDL command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			isAuthenticated := s.authenticated
			mailboxID := s.inboxMailboxID
			s.mutex.RUnlock()
			cancel()

			if !isAuthenticated {
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
			}

			// If messages haven't been loaded yet, load them
			if s.messages == nil {
				messages, err := s.server.db.ListMessages(ctx, mailboxID)
				if err != nil {
					s.Log("UIDL error: %v", err)
					writer.WriteString("-ERR Internal server error\r\n")
					writer.Flush()
					continue
				}

				// Acquire write lock to update session state
				acquired, cancel = s.mutexHelper.AcquireWriteLockWithTimeout()
				if !acquired {
					s.Log("WARNING: failed to acquire write lock within timeout")
					writer.WriteString("-ERR Server busy, please try again\r\n")
					writer.Flush()
					continue
				}

				s.messages = messages
				s.mutex.Unlock()
				cancel()
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
				acquired, cancel = s.mutexHelper.AcquireReadLockWithTimeout()
				if !acquired {
					s.Log("WARNING: failed to acquire read lock within timeout")
					writer.WriteString("-ERR Server busy, please try again\r\n")
					writer.Flush()
					continue
				}

				if msgNumber > len(s.messages) {
					s.mutex.RUnlock()
					cancel()
					if s.handleClientError(writer, "-ERR No such message\r\n") {
						return
					}
					continue
				}

				msg := s.messages[msgNumber-1]
				if s.deleted[msgNumber-1] {
					s.mutex.RUnlock()
					cancel()
					if s.handleClientError(writer, "-ERR Message is deleted\r\n") {
						return
					}
					continue
				}

				s.mutex.RUnlock()
				cancel()

				// Use UID as the unique identifier (more reliable than ContentHash)
				writer.WriteString(fmt.Sprintf("+OK %d %d\r\n", msgNumber, msg.UID))
			} else {
				// UIDL without arguments - list all messages
				// Acquire read lock to access messages and deleted status
				acquired, cancel = s.mutexHelper.AcquireReadLockWithTimeout()
				if !acquired {
					s.Log("WARNING: failed to acquire read lock within timeout")
					writer.WriteString("-ERR Server busy, please try again\r\n")
					writer.Flush()
					continue
				}

				if len(s.messages) == 0 {
					s.mutex.RUnlock()
					cancel()
					writer.WriteString("+OK 0 messages\r\n.\r\n")
				} else {
					writer.WriteString("+OK unique-id listing follows\r\n")
					for i, msg := range s.messages {
						if !s.deleted[i] {
							// Use UID as the unique identifier (more reliable than ContentHash)
							writer.WriteString(fmt.Sprintf("%d %d\r\n", i+1, msg.UID))
						}
					}
					s.mutex.RUnlock()
					cancel()
					writer.WriteString(".\r\n")
				}
			}
			s.Log("UIDL command executed")

		case "TOP":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("WARNING: context cancelled, aborting TOP command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			isAuthenticated := s.authenticated
			mailboxID := s.inboxMailboxID
			s.mutex.RUnlock()
			cancel()

			if !isAuthenticated {
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
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

			// If messages haven't been loaded yet, load them
			if s.messages == nil {
				messages, err := s.server.db.ListMessages(ctx, mailboxID)
				if err != nil {
					s.Log("TOP error: %v", err)
					writer.WriteString("-ERR Internal server error\r\n")
					writer.Flush()
					continue
				}

				// Update session state with the messages
				acquired, cancel = s.mutexHelper.AcquireWriteLockWithTimeout()
				if !acquired {
					s.Log("WARNING: failed to acquire write lock within timeout")
					writer.WriteString("-ERR Server busy, please try again\r\n")
					writer.Flush()
					continue
				}

				s.messages = messages
				s.mutex.Unlock()
				cancel()
			}

			if msgNumber > len(s.messages) {
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			msg := s.messages[msgNumber-1]
			if msg.UID == 0 {
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			// Check if message is deleted
			acquired, cancel = s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			isDeleted := s.deleted[msgNumber-1]
			s.mutex.RUnlock()
			cancel()

			if isDeleted {
				if s.handleClientError(writer, "-ERR Message is deleted\r\n") {
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

		case "RETR":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("WARNING: context cancelled, aborting RETR command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			isAuthenticated := s.authenticated
			mailboxID := s.inboxMailboxID

			// We'll check if messages are nil or if we need to retrieve them
			var messagesNil bool
			var localMsg *db.Message

			if s.messages == nil {
				messagesNil = true
			} else if len(parts) < 2 {
				s.mutex.RUnlock()
				cancel()
				if s.handleClientError(writer, "-ERR Missing message number\r\n") {
					return
				}
				continue
			} else {
				msgNumber, err := strconv.Atoi(parts[1])
				if err != nil || msgNumber < 1 {
					s.mutex.RUnlock()
					cancel()
					if s.handleClientError(writer, "-ERR Invalid message number\r\n") {
						return
					}
					continue
				}

				if msgNumber > len(s.messages) {
					s.mutex.RUnlock()
					cancel()
					if s.handleClientError(writer, "-ERR No such message\r\n") {
						return
					}
					continue
				}

				// Make a copy of the message while under lock
				msgCopy := s.messages[msgNumber-1]
				localMsg = &msgCopy
			}
			s.mutex.RUnlock()
			cancel()

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

			// If messages are nil, we need to load them first
			if messagesNil {
				messages, err := s.server.db.ListMessages(ctx, mailboxID)
				if err != nil {
					s.Log("RETR error: %v", err)
					writer.WriteString("-ERR Internal server error\r\n")
					writer.Flush()
					continue
				}

				// Update session state with the messages
				acquired, cancel = s.mutexHelper.AcquireWriteLockWithTimeout()
				if !acquired {
					s.Log("WARNING: failed to acquire write lock within timeout")
					writer.WriteString("-ERR Server busy, please try again\r\n")
					writer.Flush()
					continue
				}

				s.messages = messages
				s.mutex.Unlock()
				cancel()

				// Recheck the message number now that we have messages
				if msgNumber > len(s.messages) {
					if s.handleClientError(writer, "-ERR No such message\r\n") {
						return
					}
					continue
				}

				// Make a copy of the message
				msgCopy := s.messages[msgNumber-1]
				localMsg = &msgCopy
			}

			if localMsg == nil || localMsg.UID == 0 {
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			log.Printf("fetching message body for UID %d", localMsg.UID)
			bodyData, err := s.getMessageBody(localMsg)
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
			s.Log("retrieved message body for UID %d", localMsg.UID)

			writer.WriteString(fmt.Sprintf("+OK %d octets\r\n", localMsg.Size))
			writer.WriteString(string(bodyData))
			writer.WriteString("\r\n.\r\n")
			s.Log("retrieved message %d", localMsg.UID)

		case "NOOP":
			writer.WriteString("+OK\r\n")

		case "RSET":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("WARNING: context cancelled, aborting RSET command")
				return
			}

			// Acquire write lock to update deleted map
			acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			s.deleted = make(map[int]bool)
			s.mutex.Unlock()
			cancel()

			writer.WriteString("+OK\r\n")
			s.Log("reset")

		case "DELE":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("WARNING: context cancelled, aborting DELE command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			isAuthenticated := s.authenticated
			s.mutex.RUnlock()
			cancel()

			if !isAuthenticated {
				if s.handleClientError(writer, "-ERR Not authenticated\r\n") {
					return
				}
				continue
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

			if s.messages == nil {
				s.messages, err = s.server.db.ListMessages(ctx, s.inboxMailboxID)
				if err != nil {
					s.Log("DELE error: %v", err)
					writer.WriteString("-ERR Internal server error\r\n")
					writer.Flush()
					continue
				}
			}

			if msgNumber > len(s.messages) {
				s.Log("DELE error: no such message %d", msgNumber)
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			msg := s.messages[msgNumber-1]
			if msg.UID == 0 {
				s.Log("DELE error: no such message %d", msgNumber)
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			// Acquire write lock to update deleted map
			acquired, cancel = s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.Log("WARNING failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			s.deleted[msgNumber-1] = true
			s.mutex.Unlock()
			cancel()

			writer.WriteString("+OK Message deleted\r\n")
			s.Log("marked message %d for deletion", msg.UID)

		case "AUTH":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("WARNING: context cancelled, aborting AUTH command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			isAuthenticated := s.authenticated
			s.mutex.RUnlock()
			cancel()

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

			// For POP3, we don't support proxy authentication
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

			userID, err := s.server.db.Authenticate(ctx, address.FullAddress(), password)
			if err != nil {
				if s.handleClientError(writer, "-ERR [AUTH] Authentication failed\r\n") {
					s.Log("authentication failed")
					return
				}
				continue
			}

			// No auto-creation of mailboxes, they have to exist already for POP3
			inboxMailboxID, err := s.server.db.GetMailboxByName(ctx, userID, consts.MailboxInbox)
			if err != nil {
				if err == consts.ErrMailboxNotFound {
					if s.handleClientError(writer, fmt.Sprintf("-ERR %s\r\n", err.Error())) {
						return
					}
					continue
				}
				s.Log("AUTH error: %v", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}

			// Acquire write lock to update session state
			acquired, cancel = s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			s.inboxMailboxID = inboxMailboxID.ID
			s.authenticated = true
			s.mutex.Unlock()
			cancel()

			authCount := s.server.authenticatedConnections.Add(1)
			totalCount := s.server.totalConnections.Load()
			s.Log("authenticated via SASL PLAIN (connections: total=%d, authenticated=%d)", totalCount, authCount)

			writer.WriteString("+OK Authentication successful\r\n")

		case "LANG":
			// LANG command - set or query language
			// Acquire read lock to access current language
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}
			currentLang := s.language
			s.mutex.RUnlock()
			cancel()

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
				acquired, cancel = s.mutexHelper.AcquireWriteLockWithTimeout()
				if !acquired {
					s.Log("WARNING: failed to acquire write lock within timeout")
					writer.WriteString("-ERR Server busy, please try again\r\n")
					writer.Flush()
					continue
				}

				if langTag == "*" {
					s.language = "en" // Default to English
				} else {
					s.language = langTag
				}
				s.mutex.Unlock()
				cancel()

				writer.WriteString(fmt.Sprintf("+OK Language changed to %s\r\n", s.language))
			}
			s.Log("LANG command: current=%s", currentLang)

		case "UTF8":
			// UTF8 command - enable UTF-8 mode
			// Acquire write lock to update UTF8 mode
			acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			s.utf8Mode = true
			s.mutex.Unlock()
			cancel()

			writer.WriteString("+OK UTF8 enabled\r\n")
			s.Log("UTF8 mode enabled")

		case "QUIT":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("WARNING: context cancelled, aborting QUIT command")
				return
			}

			// Acquire read lock to access messages, deleted map, and mailbox ID
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("WARNING: failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				return
			}

			var expungeUIDs []imap.UID
			var mailboxID int64

			// Copy needed data while under read lock
			mailboxID = s.inboxMailboxID

			// Delete messages marked for deletion
			for i, deleted := range s.deleted {
				if deleted && i < len(s.messages) {
					s.Log("expunging message %d", i)
					msg := s.messages[i]

					// Delete from cache before expunging
					contentHash := msg.ContentHash // Make a copy since we'll use it after unlocking
					err := s.server.cache.Delete(contentHash)
					if err != nil && !isNotExist(err) {
						s.Log("[CACHE] WARNING: failed to delete message %s from cache: %v", contentHash, err)
					}
					expungeUIDs = append(expungeUIDs, msg.UID)
				}
			}
			s.mutex.RUnlock()
			cancel()

			err = s.server.db.ExpungeMessageUIDs(ctx, mailboxID, expungeUIDs...)
			if err != nil {
				s.Log("error expunging messages: %v", err)
			}

			userAddress = nil

			writer.WriteString("+OK Goodbye\r\n")
			writer.Flush()
			s.Close()
			return

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
	// Acquire write lock to update session state
	acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.Log("failed to acquire write lock within timeout")
		// Still close the connection even if we can't acquire the lock
		(*s.conn).Close()
		if s.cancel != nil {
			s.cancel()
		}
		return nil
	}
	defer func() {
		s.mutex.Unlock()
		cancel()
	}()

	totalCount := s.server.totalConnections.Add(-1)
	var authCount int64 = 0

	(*s.conn).Close()
	if s.User != nil {
		if s.authenticated {
			authCount = s.server.authenticatedConnections.Add(-1)
		} else {
			authCount = s.server.authenticatedConnections.Load()
		}
		s.Log("closed (connections: total=%d, authenticated=%d)", totalCount, authCount)
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
		reader, err := s.server.s3.Get(msg.ContentHash)
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
	data, err := s.server.uploader.GetLocalFile(msg.ContentHash)
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
