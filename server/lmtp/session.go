package lmtp

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-smtp"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/sieveengine"
)

//go:embed default.sieve
var defaultSieveScript string

// sendToExternalRelay queues a message for external relay delivery
func (s *LMTPSession) sendToExternalRelay(from string, to string, message []byte) error {
	if s.backend.relayQueue == nil {
		return fmt.Errorf("relay queue not configured")
	}

	// Queue the message for background delivery
	err := s.backend.relayQueue.Enqueue(from, to, "redirect", message)
	if err != nil {
		return fmt.Errorf("failed to enqueue relay message: %w", err)
	}

	// Notify worker for immediate processing if available
	if s.backend.relayWorker != nil {
		s.backend.relayWorker.NotifyQueued()
	}

	return nil
}

// LMTPSession represents a single LMTP session.
type LMTPSession struct {
	server.Session
	backend     *LMTPServerBackend
	sender      *server.Address
	conn        *smtp.Conn
	cancel      context.CancelFunc
	ctx         context.Context
	mutex       sync.RWMutex
	mutexHelper *server.MutexTimeoutHelper
	releaseConn func() // Function to release connection from limiter
	useMasterDB bool   // Pin session to master DB after a write to ensure consistency
	startTime   time.Time
}

func (s *LMTPSession) Mail(from string, opts *smtp.MailOptions) error {
	start := time.Now()
	success := false
	defer func() {
		status := "failure"
		if success {
			status = "success"
		}
		metrics.CommandsTotal.WithLabelValues("lmtp", "MAIL", status).Inc()
		metrics.CommandDuration.WithLabelValues("lmtp", "MAIL").Observe(time.Since(start).Seconds())
	}()

	s.DebugLog("processing mail from command", "from", from)

	// Handle null sender (MAIL FROM:<>) used for bounce messages
	// Per RFC 5321, empty reverse-path is used for delivery status notifications
	var fromAddress server.Address
	if from == "" {
		// Null sender - create a special empty address
		fromAddress = server.Address{} // Empty address for null sender
		s.DebugLog("null sender accepted (bounce message)")
	} else {
		// Normal sender - validate address
		var err error
		fromAddress, err = server.NewAddress(from)
		if err != nil {
			s.WarnLog("invalid from address", "from", from, "error", err)
			return &smtp.SMTPError{
				Code:         553,
				EnhancedCode: smtp.EnhancedCode{5, 1, 7},
				Message:      "Invalid sender",
			}
		}
		s.DebugLog("mail from accepted", "from", fromAddress.FullAddress())
	}

	// Acquire write lock to update sender
	acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.WarnLog("failed to acquire write lock", "command", "MAIL")
		return &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 4, 5},
			Message:      "Server busy, try again later",
		}
	}
	defer release()

	s.sender = &fromAddress

	success = true
	return nil
}

func (s *LMTPSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	start := time.Now()
	success := false
	defer func() {
		status := "failure"
		if success {
			status = "success"
		}
		metrics.CommandsTotal.WithLabelValues("lmtp", "RCPT", status).Inc()
		metrics.CommandDuration.WithLabelValues("lmtp", "RCPT").Observe(time.Since(start).Seconds())
	}()

	s.DebugLog("processing rcpt to command", "to", to)

	// Process XRCPTFORWARD parameters if present
	// This supports Dovecot-style per-recipient parameter forwarding
	if opts != nil {
		s.ParseRCPTForward(opts)
	}

	toAddress, err := server.NewAddress(to)
	if err != nil {
		s.WarnLog("invalid to address", "error", err)
		return &smtp.SMTPError{
			Code:         513,
			EnhancedCode: smtp.EnhancedCode{5, 0, 1},
			Message:      "Invalid recipient",
		}
	}
	fullAddress := toAddress.FullAddress()
	lookupAddress := toAddress.BaseAddress()

	// Log if we're using a detail address
	if toAddress.Detail() != "" {
		s.DebugLog("ignoring address detail for lookup", "full_address", fullAddress, "lookup_address", lookupAddress)
	}

	s.DebugLog("looking up user id", "address", lookupAddress)
	// Create a context for read operations that respects session pinning
	readCtx := s.ctx
	if s.useMasterDB {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	var AccountID int64
	err = s.backend.rdb.QueryRowWithRetry(readCtx, `
		SELECT c.account_id
		FROM credentials c
		JOIN accounts a ON c.account_id = a.id
		WHERE LOWER(c.address) = $1 AND a.deleted_at IS NULL
	`, lookupAddress).Scan(&AccountID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// User not found - permanent failure
			s.DebugLog("user not found", "address", lookupAddress)
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 1, 1},
				Message:      "No such user here",
			}
		} else {
			// Database error (connection failure, timeout, etc.) - temporary failure
			s.WarnLog("database error during user lookup", "address", lookupAddress, "error", err)
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 4, 3},
				Message:      "Temporary failure, please try again later",
			}
		}
	}

	// This is a potential write operation, so it must use the main context.
	// Ensure default mailboxes (INBOX/Drafts/Sent/Spam/Trash) exist. Use the resilient method.
	err = s.backend.rdb.CreateDefaultMailboxesWithRetry(s.ctx, AccountID)
	if err != nil {
		return s.InternalError("failed to create default mailboxes: %v", err)
	}

	// Acquire write lock to update User
	acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.WarnLog("failed to acquire write lock", "command", "RCPT")
		return &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 4, 5},
			Message:      "Server busy, try again later",
		}
	}
	defer release()
	s.User = server.NewUser(toAddress, AccountID) // Use the original address (with detail part)
	// Pin the session to the master DB to prevent reading stale data from a replica.
	s.useMasterDB = true

	success = true
	s.DebugLog("recipient accepted", "recipient", fullAddress, "account_id", AccountID)
	return nil
}

func (s *LMTPSession) Data(r io.Reader) error {
	// Prometheus metrics - start delivery timing
	start := time.Now()
	success := false
	defer func() {
		status := "failure"
		if success {
			status = "success"
		}
		metrics.CommandsTotal.WithLabelValues("lmtp", "DATA", status).Inc()
		metrics.CommandDuration.WithLabelValues("lmtp", "DATA").Observe(time.Since(start).Seconds())
	}()

	// Acquire write lock for accessing session state and potentially updating it (useMasterDB)
	acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.WarnLog("failed to acquire write lock", "command", "DATA")
		return &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 4, 5},
			Message:      "Server busy, try again later",
		}
	}
	defer release()

	// Check if we have a valid sender and recipient
	if s.sender == nil || s.User == nil {
		s.WarnLog("data command without valid sender or recipient")
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "Bad sequence of commands (missing MAIL FROM or RCPT TO)",
		}
	}

	var buf bytes.Buffer

	// Limit the read if max_message_size is configured
	var reader io.Reader = r
	if s.backend.maxMessageSize > 0 {
		// Add 1 byte to detect when limit is exceeded
		reader = io.LimitReader(r, s.backend.maxMessageSize+1)
	}

	_, err := io.Copy(&buf, reader)
	if err != nil {
		return s.InternalError("failed to read message: %v", err)
	}

	// Check if message exceeds configured limit
	if s.backend.maxMessageSize > 0 && int64(buf.Len()) > s.backend.maxMessageSize {
		s.WarnLog("message size exceeds limit", "size", buf.Len(), "limit", s.backend.maxMessageSize)
		return &smtp.SMTPError{
			Code:         552,
			EnhancedCode: smtp.EnhancedCode{5, 3, 4},
			Message:      fmt.Sprintf("message size exceeds maximum allowed size of %d bytes", s.backend.maxMessageSize),
		}
	}

	s.DebugLog("message data read", "size", buf.Len())

	// Use the full message bytes as received for hashing, size, and header extraction.
	fullMessageBytes := buf.Bytes()

	// Prometheus metrics
	metrics.MessageSizeBytes.WithLabelValues("lmtp").Observe(float64(len(fullMessageBytes)))
	metrics.BytesThroughput.WithLabelValues("lmtp", "in").Add(float64(len(fullMessageBytes)))
	metrics.MessageThroughput.WithLabelValues("lmtp", "received", "success").Inc()

	// Extract raw headers string.
	// Headers are typically terminated by a double CRLF (\r\n\r\n).
	var rawHeadersText string
	headerEndIndex := bytes.Index(fullMessageBytes, []byte("\r\n\r\n"))
	if headerEndIndex != -1 {
		rawHeadersText = string(fullMessageBytes[:headerEndIndex])
	} else {
		// Log if headers are not clearly separated. rawHeadersText will be empty.
		// This might indicate a malformed email or an email with only headers and no body separator.
		s.WarnLog("could not find standard header/body separator in message")
	}

	messageContent, err := server.ParseMessage(bytes.NewReader(fullMessageBytes))
	if err != nil {
		return s.InternalError("failed to parse message: %v", err)
	}

	contentHash := helpers.HashContent(fullMessageBytes)
	s.DebugLog("message parsed", "content_hash", contentHash)

	// Parse message headers (this does not consume the body)
	mailHeader := mail.Header{Header: messageContent.Header}
	subject, _ := mailHeader.Subject()
	messageID, _ := mailHeader.MessageID()
	sentDate, _ := mailHeader.Date()
	inReplyTo, _ := mailHeader.MsgIDList("In-Reply-To")

	if sentDate.IsZero() {
		sentDate = time.Now()
		s.DebugLog("no sent date found, using current time", "sent_date", sentDate)
	} else {
		s.DebugLog("message sent date", "sent_date", sentDate)
	}

	bodyStructureVal := imapserver.ExtractBodyStructure(bytes.NewReader(buf.Bytes()))
	bodyStructure := &bodyStructureVal
	var plaintextBody *string
	plaintextBodyResult, err := helpers.ExtractPlaintextBody(messageContent)
	if err != nil {
		s.WarnLog("failed to extract plaintext body", "error", err)
		// The plaintext body is needed only for indexing, so we can ignore the error
		// Use empty string as fallback
		emptyStr := new(string)
		plaintextBody = emptyStr
	} else {
		plaintextBody = plaintextBodyResult
	}

	recipients := helpers.ExtractRecipients(messageContent.Header)

	// Store message locally for background upload to S3
	filePath, err := s.backend.uploader.StoreLocally(contentHash, s.AccountID(), fullMessageBytes)
	if err != nil {
		return s.InternalError("failed to save message to disk: %v", err)
	}
	s.DebugLog("message accepted locally", "path", *filePath)

	// SIEVE script processing

	// Create a context for read operations that respects session pinning
	readCtx := s.ctx
	if s.useMasterDB {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	activeScript, err := s.backend.rdb.GetActiveScriptWithRetry(readCtx, s.AccountID())
	var result sieveengine.Result
	var mailboxName string

	// Create an adapter for the VacationOracle interface
	sieveVacOracle := &dbVacationOracle{
		rdb: s.backend.rdb,
	}

	// Create the sieve context (used for both default and user scripts)
	sieveCtx := sieveengine.Context{
		EnvelopeFrom: s.sender.FullAddress(),
		EnvelopeTo:   s.User.Address.FullAddress(),
		Header:       messageContent.Header.Map(),
		Body:         *plaintextBody,
	}

	// Always run the default script first as a "before script"
	// Use the pre-parsed default executor from the backend
	if s.backend.defaultSieveExecutor != nil {
		// SIEVE debugging information
		if s.backend.debug {
			s.DebugLog("sieve message headers for evaluation")
			for key, values := range sieveCtx.Header {
				for _, value := range values {
					s.DebugLog("sieve header", "key", key, "value", value)
				}
			}
		}

		defaultResult, defaultEvalErr := s.backend.defaultSieveExecutor.Evaluate(s.ctx, sieveCtx)
		if defaultEvalErr != nil {
			metrics.SieveExecutions.WithLabelValues("lmtp", "failure").Inc()
			s.DebugLog("default sieve script evaluation error", "error", defaultEvalErr)
			// fallback: default to INBOX
			result = sieveengine.Result{Action: sieveengine.ActionKeep}
		} else {
			metrics.SieveExecutions.WithLabelValues("lmtp", "success").Inc()
			// Set the result from the default script
			result = defaultResult
			s.DebugLog("default sieve script result", "action", result.Action)

			// Log more details about the action
			switch result.Action {
			case sieveengine.ActionFileInto:
				s.DebugLog("default sieve fileinto", "mailbox", result.Mailbox)
			case sieveengine.ActionRedirect:
				s.DebugLog("default sieve redirect", "redirect_to", result.RedirectTo)
			case sieveengine.ActionDiscard:
				s.DebugLog("default sieve discard")
			case sieveengine.ActionVacation:
				s.DebugLog("default sieve vacation response triggered")
			case sieveengine.ActionKeep:
				s.DebugLog("default sieve keep")
			}
		}
	} else {
		s.DebugLog("no default sieve executor available")
		result = sieveengine.Result{Action: sieveengine.ActionKeep}
	}

	// If user has an active script, run it and let it override the resultAction
	if err == nil && activeScript != nil {
		s.DebugLog("using user sieve script", "name", activeScript.Name, "script_id", activeScript.ID, "updated_at", activeScript.UpdatedAt.Format(time.RFC3339))
		// Try to get the user script from cache or create and cache it with metadata validation
		userSieveExecutor, userScriptErr := s.backend.sieveCache.GetOrCreateWithMetadata(
			activeScript.Script,
			activeScript.ID,
			activeScript.UpdatedAt,
			s.AccountID(),
			sieveVacOracle,
		)
		if userScriptErr != nil {
			s.DebugLog("failed to get/create sieve executor", "error", userScriptErr)
			// Keep the result from the default script
		} else {
			userResult, userEvalErr := userSieveExecutor.Evaluate(s.ctx, sieveCtx)
			if userEvalErr != nil {
				metrics.SieveExecutions.WithLabelValues("lmtp", "failure").Inc()
				s.DebugLog("user sieve script evaluation error", "error", userEvalErr)
				// Keep the result from the default script
			} else {
				metrics.SieveExecutions.WithLabelValues("lmtp", "success").Inc()
				// Override the result with the user script result
				result = userResult
				s.DebugLog("user sieve script overrode result", "action", result.Action)

				// Log more details about the action
				switch result.Action {
				case sieveengine.ActionFileInto:
					s.DebugLog("user sieve fileinto", "mailbox", result.Mailbox)
				case sieveengine.ActionRedirect:
					s.DebugLog("user sieve redirect", "redirect_to", result.RedirectTo)
				case sieveengine.ActionDiscard:
					s.DebugLog("user sieve discard")
				case sieveengine.ActionVacation:
					s.DebugLog("user sieve vacation response triggered")
				case sieveengine.ActionKeep:
					s.DebugLog("user sieve keep")
				}
			}
		}
	} else {
		if err != nil && err != consts.ErrDBNotFound {
			s.DebugLog("failed to get active sieve script", "error", err)
		} else {
			s.DebugLog("no active script found, using default script result")
		}
	}

	s.DebugLog("executing sieve action", "action", result.Action)

	switch result.Action {
	case sieveengine.ActionDiscard:
		s.DebugLog("sieve message discarded")
		return nil

	case sieveengine.ActionFileInto:
		mailboxName = result.Mailbox
		if result.Copy {
			s.DebugLog("sieve fileinto :copy action", "mailbox", mailboxName)

			// First save to the specified mailbox
			err := s.saveMessageToMailbox(mailboxName, fullMessageBytes, contentHash,
				subject, messageID, sentDate, inReplyTo, bodyStructure, plaintextBody, recipients, rawHeadersText)
			if err != nil {
				return s.InternalError("failed to save message to specified mailbox: %v", err)
			}

			// Then save to INBOX (for the :copy functionality)
			s.DebugLog("saving copy to inbox due to :copy modifier")

			// Call saveMessageToMailbox again for INBOX
			err = s.saveMessageToMailbox(consts.MailboxInbox, fullMessageBytes, contentHash,
				subject, messageID, sentDate, inReplyTo, bodyStructure, plaintextBody, recipients, rawHeadersText)
			if err != nil {
				return s.InternalError("failed to save message copy to inbox: %v", err)
			}

			// Success - both copies saved
			s.InfoLog("message delivered according to fileinto :copy directive")
			return nil
		} else {
			s.DebugLog("sieve fileinto action", "mailbox", mailboxName)
		}

	case sieveengine.ActionRedirect:
		if result.Copy {
			s.DebugLog("sieve redirect :copy action", "redirect_to", result.RedirectTo)
		} else {
			s.DebugLog("sieve redirect action", "redirect_to", result.RedirectTo)
		}

		// Queue the message for external relay delivery if configured
		if s.backend.relayQueue != nil {
			s.DebugLog("queueing message for relay delivery")
			err := s.sendToExternalRelay(s.sender.FullAddress(), result.RedirectTo, fullMessageBytes)
			if err != nil {
				s.DebugLog("error enqueuing redirected message, falling back to inbox", "error", err)
				// Continue processing even if queue fails, store in INBOX as fallback
			} else {
				s.DebugLog("successfully queued message for relay delivery", "redirect_to", result.RedirectTo)

				// If :copy is not specified and relay succeeded, we don't store the message locally
				if !result.Copy {
					s.DebugLog("redirect without :copy - skipping local delivery")
					return nil
				}
				s.DebugLog("redirect :copy - continuing with local delivery")
			}
		} else {
			s.DebugLog("redirect requested but external relay not configured")
		}

		// Fallback: store in INBOX if relay is not configured or fails
		// Or if :copy is specified
		mailboxName = consts.MailboxInbox

	case sieveengine.ActionVacation:
		// Handle vacation response
		err := s.handleVacationResponse(result, messageContent)
		if err != nil {
			s.DebugLog("error handling vacation response", "error", err)
			// Continue processing even if vacation response fails
		}
		// Store the original message in INBOX
		mailboxName = consts.MailboxInbox

	default:
		s.DebugLog("sieve keep action")
		mailboxName = consts.MailboxInbox
	}

	// Save the message to the determined mailbox (either the specified one or INBOX)
	err = s.saveMessageToMailbox(mailboxName, fullMessageBytes, contentHash,
		subject, messageID, sentDate, inReplyTo, bodyStructure, plaintextBody, recipients, rawHeadersText)
	if err != nil {
		// Cleanup local file on failure (only if it was stored locally)
		if filePath != nil {
			_ = os.Remove(*filePath)
		}
		metrics.MessageThroughput.WithLabelValues("lmtp", "delivered", "failure").Inc()

		if errors.Is(err, consts.ErrDBUniqueViolation) {
			s.WarnLog("message already exists in database", "content_hash", contentHash)
			return &smtp.SMTPError{
				Code:         541,
				EnhancedCode: smtp.EnhancedCode{5, 0, 1},
				Message:      "Message already exists",
			}
		}
		return s.InternalError("failed to save message: %v", err)
	}

	metrics.MessageThroughput.WithLabelValues("lmtp", "delivered", "success").Inc()
	s.InfoLog("message delivered", "mailbox", mailboxName)

	// Track domain and user activity - LMTP delivery is critical!
	if s.User != nil {
		metrics.TrackDomainMessage("lmtp", s.Domain(), "delivered")
		metrics.TrackDomainBytes("lmtp", s.Domain(), "in", int64(len(fullMessageBytes)))
		metrics.TrackUserActivity("lmtp", s.FullAddress(), "command", 1)
	}

	success = true
	return nil
}

func (s *LMTPSession) Reset() {
	start := time.Now()
	defer func() {
		metrics.CommandsTotal.WithLabelValues("lmtp", "RSET", "success").Inc()
		metrics.CommandDuration.WithLabelValues("lmtp", "RSET").Observe(time.Since(start).Seconds())
	}()

	// Acquire write lock to reset session state
	acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.WarnLog("failed to acquire write lock", "command", "RESET")
		return
	}
	defer release()

	s.User = nil
	s.sender = nil

	s.DebugLog("session reset")
}

func (s *LMTPSession) Logout() error {
	// Check if this is a normal QUIT command or an abrupt connection close
	if s.conn != nil && s.conn.Conn() != nil {
		s.DebugLog("session logout requested")
	} else {
		s.DebugLog("client dropped connection")
	}

	// Acquire write lock for logout operations
	acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.WarnLog("failed to acquire write lock", "command", "LOGOUT")
		// Continue with logout even if we can't get the lock
	} else {
		defer release()
		// Clean up any session state if needed
	}

	// Release connection from limiter
	if s.releaseConn != nil {
		s.releaseConn()
		s.releaseConn = nil
	}

	metrics.ConnectionDuration.WithLabelValues("lmtp").Observe(time.Since(s.startTime).Seconds())

	// Decrement active connections (not total - total is cumulative)
	activeCount := s.backend.activeConnections.Add(-1)

	// Prometheus metrics - connection closed
	metrics.ConnectionsCurrent.WithLabelValues("lmtp").Dec()

	if s.cancel != nil {
		s.cancel()
	}

	s.InfoLog("session logout completed", "active_count", activeCount)

	return &smtp.SMTPError{
		Code:         221,
		EnhancedCode: smtp.EnhancedCode{2, 0, 0},
		Message:      "Closing transmission channel",
	}
}

func (s *LMTPSession) InternalError(format string, a ...any) error {
	errorMsg := fmt.Sprintf(format, a...)
	s.InfoLog("internal error", "message", errorMsg)
	return &smtp.SMTPError{
		Code:         421,
		EnhancedCode: smtp.EnhancedCode{4, 4, 2},
		Message:      errorMsg,
	}
}

// handleVacationResponse constructs and sends a vacation auto-response.
// The decision to send and the recording of the response event are handled
// by the Sieve engine's policy, using the VacationOracle.
func (s *LMTPSession) handleVacationResponse(result sieveengine.Result, originalMessage *message.Entity) error {
	if s.backend.relayQueue == nil {
		s.DebugLog("relay queue not configured, cannot send vacation response", "sender", s.sender.FullAddress())
		// Do not return error, as the Sieve engine might have already recorded the attempt.
		return nil
	}

	// Create the vacation response message
	var vacationFrom string
	if result.VacationFrom != "" {
		vacationFrom = result.VacationFrom
		s.DebugLog("using custom vacation from address", "from", vacationFrom)
	} else {
		vacationFrom = s.User.Address.FullAddress()
		s.DebugLog("using default vacation from address", "from", vacationFrom)
	}

	var vacationSubject string
	if result.VacationSubj != "" {
		vacationSubject = result.VacationSubj
		s.DebugLog("using custom vacation subject", "subject", vacationSubject)
	} else {
		vacationSubject = "Auto: Out of Office"
		s.DebugLog("using default vacation subject", "subject", vacationSubject)
	}

	// Get the original message ID for the In-Reply-To header
	originalHeader := mail.Header{Header: originalMessage.Header}
	originalMessageID, _ := originalHeader.MessageID()
	if originalMessageID != "" {
		s.DebugLog("using original message id for in-reply-to", "message_id", originalMessageID)
	}

	s.DebugLog("creating vacation response message")
	var vacationMessage bytes.Buffer
	var h message.Header
	h.Set("From", vacationFrom)
	h.Set("To", s.sender.FullAddress())
	h.Set("Subject", vacationSubject)
	messageID := fmt.Sprintf("<%d.vacation@%s>", time.Now().UnixNano(), s.HostName)
	h.Set("Message-ID", messageID)
	s.DebugLog("vacation message id", "message_id", messageID)

	if originalMessageID != "" {
		h.Set("In-Reply-To", originalMessageID)
		h.Set("References", originalMessageID)
	}
	h.Set("Auto-Submitted", "auto-replied")
	h.Set("X-Auto-Response-Suppress", "All")
	h.Set("Date", time.Now().Format(time.RFC1123Z))

	w, err := message.CreateWriter(&vacationMessage, h)
	if err != nil {
		s.DebugLog("error creating message writer", "error", err)
		return fmt.Errorf("failed to create message writer: %w", err)
	}

	var textHeader message.Header
	textHeader.Set("Content-Type", "text/plain; charset=utf-8")
	textWriter, err := w.CreatePart(textHeader)
	if err != nil {
		s.DebugLog("error creating text part", "error", err)
		return fmt.Errorf("failed to create text part: %w", err)
	}

	s.DebugLog("adding vacation message body", "body_length", len(result.VacationMsg))
	_, err = textWriter.Write([]byte(result.VacationMsg))
	if err != nil {
		s.DebugLog("error writing vacation message body", "error", err)
		return fmt.Errorf("failed to write vacation message body: %w", err)
	}

	textWriter.Close()
	w.Close()

	// Only send vacation response if relay queue is configured
	if s.backend.relayQueue != nil {
		sendErr := s.sendToExternalRelay(vacationFrom, s.sender.FullAddress(), vacationMessage.Bytes())
		if sendErr != nil {
			s.DebugLog("error enqueuing vacation response", "error", sendErr)
			// The Sieve engine's policy should have already recorded the response attempt.
			// Failure here is a delivery issue.
		} else {
			s.DebugLog("queued vacation response for relay delivery", "to", s.sender.FullAddress())
		}
	} else {
		s.DebugLog("relay queue not configured, cannot send vacation response")
	}

	// The recording of the vacation response is now handled by SievePolicy via VacationOracle
	return nil
}

// saveMessageToMailbox saves a message to the specified mailbox
func (s *LMTPSession) saveMessageToMailbox(mailboxName string,
	fullMessageBytes []byte, contentHash string, subject string, messageID string,
	sentDate time.Time, inReplyTo []string, bodyStructure *imap.BodyStructure,
	plaintextBody *string, recipients []helpers.Recipient, rawHeadersText string) error {

	// Create a context for read operations that respects session pinning
	readCtx := s.ctx
	if s.useMasterDB {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	mailbox, err := s.backend.rdb.GetMailboxByNameWithRetry(readCtx, s.AccountID(), mailboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.WarnLog("mailbox not found, falling back to inbox", "mailbox", mailboxName)
			mailbox, err = s.backend.rdb.GetMailboxByNameWithRetry(readCtx, s.AccountID(), consts.MailboxInbox)
			if err != nil {
				return fmt.Errorf("failed to get INBOX mailbox: %v", err)
			}
		} else {
			return fmt.Errorf("failed to get mailbox '%s': %v", mailboxName, err)
		}
	}

	size := int64(len(fullMessageBytes))

	_, messageUID, err := s.backend.rdb.InsertMessageWithRetry(s.ctx,
		&db.InsertMessageOptions{
			AccountID:     s.AccountID(),
			MailboxID:     mailbox.ID,
			S3Domain:      s.User.Address.Domain(),
			S3Localpart:   s.User.Address.LocalPart(),
			MailboxName:   mailbox.Name,
			ContentHash:   contentHash,
			MessageID:     messageID,
			InternalDate:  time.Now(),
			Size:          size,
			Subject:       subject,
			PlaintextBody: *plaintextBody,
			SentDate:      sentDate,
			InReplyTo:     inReplyTo,
			BodyStructure: bodyStructure,
			Recipients:    recipients,
			Flags:         []imap.Flag{}, // Explicitly set empty flags to mark as unread
			RawHeaders:    rawHeadersText,
			FTSRetention:  s.backend.ftsRetention,
		},
		db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  s.backend.hostname,
			Size:        size,
			AccountID:   s.AccountID(),
		})

	if err != nil {
		if errors.Is(err, consts.ErrDBUniqueViolation) {
			s.WarnLog("message already exists in database", "content_hash", contentHash)
			return fmt.Errorf("%w: message already exists", consts.ErrDBUniqueViolation)
		}
		return fmt.Errorf("failed to save message: %v", err)
	}

	// Pin this session to the master DB to ensure read-your-writes consistency
	s.useMasterDB = true

	// Notify uploader that a new upload is queued
	s.backend.uploader.NotifyUploadQueued()
	s.DebugLog("message saved", "uid", messageUID, "mailbox", mailbox.Name)
	return nil
}
