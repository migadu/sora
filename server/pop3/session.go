package pop3

import (
	"bufio"
	"context"
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
}

func (s *POP3Session) handleConnection() {
	defer s.cancel()

	defer s.Close()
	reader := bufio.NewReader(*s.conn)
	writer := bufio.NewWriter(*s.conn)

	writer.WriteString("+OK POP3 server ready\r\n")
	writer.Flush()

	s.Log("[POP3] connected")

	ctx := s.ctx
	var userAddress *server.Address

	for {
		(*s.conn).SetReadDeadline(time.Now().Add(Pop3IdleTimeout))

		line, err := reader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				writer.WriteString("-ERR Connection timed out due to inactivity\r\n")
				writer.Flush()
				s.Log("[POP3] timed out")
			} else if err == io.EOF {
				// Client closed connection without QUIT
				s.Log("[POP3] client dropped connection")
			} else {
				s.Log("[POP3] error: %v", err)
			}
			return
		}

		line = strings.TrimSpace(line)
		parts := strings.Split(line, " ")
		cmd := strings.ToUpper(parts[0])

		switch cmd {
		case "USER":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("[POP3] Context cancelled, aborting USER command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("[POP3] Failed to acquire read lock within timeout")
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
				s.Log("[POP3] error: %v", err)
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
				s.Log("[POP3] Context cancelled, aborting PASS command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("[POP3] Failed to acquire read lock within timeout")
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
				s.Log("[POP3] PASS without USER")
				writer.WriteString("-ERR Must provide USER first\r\n")
				writer.Flush()
				continue
			}

			s.Log("[POP3] authentication attempt for %s", userAddress.FullAddress())

			userID, err := s.server.db.Authenticate(ctx, userAddress.FullAddress(), parts[1])
			if err != nil {
				if s.handleClientError(writer, "-ERR Authentication failed\r\n") {
					s.Log("[POP3] authentication failed")
					return
				}
				continue
			}

			// No auto-creation of mailboxes, they have to exist

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
				s.Log("[POP3] Failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			s.inboxMailboxID = inboxMailboxID.ID
			s.Log("[POP3] authenticated")
			s.authenticated = true
			s.mutex.Unlock()
			cancel()

			writer.WriteString("+OK Password accepted\r\n")

		case "STAT":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("[POP3] Context cancelled, aborting STAT command")
				return
			}

			// Acquire read lock to check inbox mailbox ID
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("[POP3] Failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			mailboxID := s.inboxMailboxID
			s.mutex.RUnlock()
			cancel()

			messagesCount, size, err := s.server.db.GetMailboxMessageCountAndSizeSum(ctx, mailboxID)
			if err != nil {
				s.Log("[POP3] STAT error: %v", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}
			writer.WriteString(fmt.Sprintf("+OK %d %d\r\n", messagesCount, size))

		case "LIST":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("[POP3] Context cancelled, aborting LIST command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("[POP3] Failed to acquire read lock within timeout")
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
				s.Log("[POP3] LIST error: %v", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}

			// Acquire write lock to update session state
			acquired, cancel = s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.Log("[POP3] Failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			s.messages = messages
			s.mutex.Unlock()
			cancel()
			if err != nil {
				s.Log("[POP3] LIST error: %v", err)
				writer.WriteString("-ERR Internal server error\r\n")
				writer.Flush()
				continue
			}

			// Acquire read lock to access messages and deleted status
			acquired, cancel = s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("[POP3] Failed to acquire read lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			if len(s.messages) == 0 {
				s.mutex.RUnlock()
				cancel()
				writer.WriteString("+OK 0 messages\r\n.\r\n")
			} else {
				writer.WriteString("+OK scan listing follows\r\n")
				for i, msg := range s.messages {
					if !s.deleted[i] {
						writer.WriteString(fmt.Sprintf("%d %d\r\n", i+1, msg.Size))
					}
				}
				s.mutex.RUnlock()
				cancel()
				writer.WriteString(".\r\n")
			}
			s.Log("[POP3] listed %d messages", len(s.messages))

		case "RETR":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("[POP3] Context cancelled, aborting RETR command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("[POP3] Failed to acquire read lock within timeout")
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
					s.Log("[POP3] RETR error: %v", err)
					writer.WriteString("-ERR Internal server error\r\n")
					writer.Flush()
					continue
				}

				// Update session state with the messages
				acquired, cancel = s.mutexHelper.AcquireWriteLockWithTimeout()
				if !acquired {
					s.Log("[POP3] Failed to acquire write lock within timeout")
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

			log.Printf("[POP3] Fetching message body for UID %d", localMsg.UID)
			bodyData, err := s.getMessageBody(localMsg)
			if err != nil {
				if err == consts.ErrMessageNotAvailable {
					writer.WriteString("-ERR Message not available\r\n")
				} else {
					s.Log("[POP3] RETR internal error: %v", err)
					writer.WriteString("-ERR Internal server error\r\n")
				}
				writer.Flush()
				continue
			}
			s.Log("[POP3] retrieved message body for UID %d", localMsg.UID)

			writer.WriteString(fmt.Sprintf("+OK %d octets\r\n", localMsg.Size))
			writer.WriteString(string(bodyData))
			writer.WriteString("\r\n.\r\n")
			s.Log("[POP3] retrieved message %d", localMsg.UID)

		case "NOOP":
			writer.WriteString("+OK\r\n")

		case "RSET":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("[POP3] Context cancelled, aborting RSET command")
				return
			}

			// Acquire write lock to update deleted map
			acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.Log("[POP3] Failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			s.deleted = make(map[int]bool)
			s.mutex.Unlock()
			cancel()

			writer.WriteString("+OK\r\n")
			s.Log("[POP3] reset")

		case "DELE":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("[POP3] Context cancelled, aborting DELE command")
				return
			}

			// Acquire read lock to check authentication state
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("[POP3] Failed to acquire read lock within timeout")
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
				log.Printf("[POP3] Missing message number")
				if s.handleClientError(writer, "-ERR Missing message number\r\n") {
					return
				}
				continue
			}

			msgNumber, err := strconv.Atoi(parts[1])
			if err != nil || msgNumber < 1 {
				s.Log("[POP3] DELE error: %v", err)
				if s.handleClientError(writer, "-ERR Invalid message number\r\n") {
					return
				}
				continue
			}

			if s.messages == nil {
				s.messages, err = s.server.db.ListMessages(ctx, s.inboxMailboxID)
				if err != nil {
					s.Log("[POP3] DELE error: %v", err)
					writer.WriteString("-ERR Internal server error\r\n")
					writer.Flush()
					continue
				}
			}

			if msgNumber > len(s.messages) {
				s.Log("[POP3] DELE error: no such message %d", msgNumber)
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			msg := s.messages[msgNumber-1]
			if msg.UID == 0 {
				s.Log("[POP3] DELE error: no such message %d", msgNumber)
				if s.handleClientError(writer, "-ERR No such message\r\n") {
					return
				}
				continue
			}

			// Acquire write lock to update deleted map
			acquired, cancel = s.mutexHelper.AcquireWriteLockWithTimeout()
			if !acquired {
				s.Log("[POP3] Failed to acquire write lock within timeout")
				writer.WriteString("-ERR Server busy, please try again\r\n")
				writer.Flush()
				continue
			}

			s.deleted[msgNumber-1] = true
			s.mutex.Unlock()
			cancel()

			writer.WriteString("+OK Message deleted\r\n")
			s.Log("[POP3] marked message %d for deletion", msg.UID)

		case "QUIT":
			// Check context before processing command
			if s.ctx.Err() != nil {
				s.Log("[POP3] Context cancelled, aborting QUIT command")
				return
			}

			// Acquire read lock to access messages, deleted map, and mailbox ID
			acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
			if !acquired {
				s.Log("[POP3] Failed to acquire read lock within timeout")
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
					s.Log("[POP3] expunging message %d", i)
					msg := s.messages[i]

					// Delete from cache before expunging
					contentHash := msg.ContentHash // Make a copy since we'll use it after unlocking
					err := s.server.cache.Delete(contentHash)
					if err != nil && !isNotExist(err) {
						s.Log("[POP3] Failed to delete message %s from cache: %v", contentHash, err)
					}
					expungeUIDs = append(expungeUIDs, msg.UID)
				}
			}
			s.mutex.RUnlock()
			cancel()

			err = s.server.db.ExpungeMessageUIDs(ctx, mailboxID, expungeUIDs...)
			if err != nil {
				s.Log("[POP3] error expunging messages: %v", err)
			}

			userAddress = nil

			writer.WriteString("+OK Goodbye\r\n")
			writer.Flush()
			s.Close()
			return

		default:
			writer.WriteString(fmt.Sprintf("-ERR Unknown command: %s\r\n", cmd))
			s.Log("[POP3] unknown command: %s", cmd)
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
	time.Sleep(time.Duration(s.errorsCount) * Pop3ErrorDelay)
	writer.WriteString(errMsg)
	writer.Flush()
	return false
}

func (s *POP3Session) Close() error {
	// Acquire write lock to update session state
	acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.Log("[POP3][CLOSE] Failed to acquire write lock within timeout")
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

	(*s.conn).Close()
	if s.User != nil {
		s.Log("[POP3] closed")
		s.User = nil
		s.Id = ""
		s.messages = nil
		s.deleted = nil
		s.authenticated = false
		if s.cancel != nil { // Ensure session cancel is called if not already
			s.cancel()
		}
	}
	return nil
}

func (s *POP3Session) getMessageBody(msg *db.Message) ([]byte, error) {
	// Check context before fetching message body
	if s.ctx.Err() != nil {
		s.Log("[POP3] Context cancelled, aborting message body fetch")
		return nil, fmt.Errorf("context cancelled")
	}

	if msg.IsUploaded {
		// Try cache first
		data, err := s.server.cache.Get(msg.ContentHash)
		if err == nil && data != nil {
			log.Printf("[POP3][CACHE] Hit for UID %d", msg.UID)
			return data, nil
		}

		// Fallback to S3
		log.Printf("[POP3][CACHE] Miss. Fetching UID %d from S3 (%s)", msg.UID, msg.ContentHash)
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
		log.Printf("[POP3][CACHE] Storing UID %d in cache (%s)", msg.UID, msg.ContentHash)
		_ = s.server.cache.Put(msg.ContentHash, data)
		return data, nil
	}

	// If not uploaded to S3, try fetch from local disk
	log.Printf("[POP3] Fetching not yet uploaded message UID %d from disk", msg.UID)
	data, err := s.server.uploader.GetLocalFile(msg.ContentHash)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[POP3] Message UID %d (hash %s) not found locally and not marked as uploaded. Assuming pending remote processing.", msg.UID, msg.ContentHash)
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
