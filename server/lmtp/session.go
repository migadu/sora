package lmtp

import (
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
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
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/sieveengine"
)

//go:embed default.sieve
var defaultSieveScript string

// sendToExternalRelay sends a message to the external relay using TLS
func (s *LMTPSession) sendToExternalRelay(from string, to string, message []byte) error {
	if s.backend.externalRelay == "" {
		return fmt.Errorf("external relay not configured")
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	c, err := smtp.DialTLS(s.backend.externalRelay, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to external relay with TLS: %w", err)
	}
	defer c.Close()

	if err := c.Mail(from, nil); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}
	if err := c.Rcpt(to, nil); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("failed to start data: %w", err)
	}
	_, err = wc.Write(message)
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	err = wc.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	err = c.Quit()
	if err != nil {
		return fmt.Errorf("failed to quit: %w", err)
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
}

func (s *LMTPSession) Mail(from string, opts *smtp.MailOptions) error {
	s.Log("[LMTP] processing MAIL FROM command: %s", from)
	fromAddress, err := server.NewAddress(from)
	if err != nil {
		s.Log("[LMTP] invalid from address: %v", err)
		return &smtp.SMTPError{
			Code:         553,
			EnhancedCode: smtp.EnhancedCode{5, 1, 7},
			Message:      "Invalid sender",
		}
	}

	// Acquire write lock to update sender
	acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
	defer cancel()
	if !acquired {
		s.Log("[LMTP] failed to acquire write lock for Mail command")
		return &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 4, 5},
			Message:      "Server busy, try again later",
		}
	}

	s.sender = &fromAddress
	s.mutex.Unlock()

	s.Log("[LMTP] mail from=%s accepted", fromAddress.FullAddress())
	return nil
}

func (s *LMTPSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.Log("[LMTP] processing RCPT TO command: %s", to)
	toAddress, err := server.NewAddress(to)
	if err != nil {
		s.Log("[LMTP] invalid to address: %v", err)
		return &smtp.SMTPError{
			Code:         513,
			EnhancedCode: smtp.EnhancedCode{5, 0, 1},
			Message:      "Invalid recipient",
		}
	}
	fullAddress := toAddress.FullAddress()
	s.Log("[LMTP] looking up user ID for address: %s", fullAddress)
	userId, err := s.backend.db.GetAccountIDByAddress(s.ctx, fullAddress)
	if err != nil {
		s.Log("[LMTP] failed to get user ID by address: %v", err)
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 0, 2},
			Message:      "No such user here",
		}
	}

	// Acquire write lock to update User
	acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
	defer cancel()
	if !acquired {
		s.Log("[LMTP] failed to acquire write lock for Rcpt command")
		return &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 4, 5},
			Message:      "Server busy, try again later",
		}
	}

	s.User = server.NewUser(toAddress, userId)
	s.mutex.Unlock()

	// Ensure default mailboxes (INBOX/Drafts/Sent/Spam/Trash) exist
	err = s.backend.db.CreateDefaultMailboxes(s.ctx, userId)
	if err != nil {
		return s.InternalError("failed to create default mailboxes: %v", err)
	}

	s.Log("[LMTP] recipient accepted: %s (UserID: %d)", fullAddress, userId)
	return nil
}

func (s *LMTPSession) Data(r io.Reader) error {
	// Acquire read lock for accessing session state during message processing
	acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
	defer cancel()
	if !acquired {
		s.Log("[LMTP] failed to acquire read lock for Data command")
		return &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 4, 5},
			Message:      "Server busy, try again later",
		}
	}
	defer s.mutex.RUnlock()

	// Check if we have a valid sender and recipient
	if s.sender == nil || s.User == nil {
		s.Log("[LMTP] DATA command received without valid sender or recipient")
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "Bad sequence of commands (missing MAIL FROM or RCPT TO)",
		}
	}

	var buf bytes.Buffer
	_, err := io.Copy(&buf, r)
	if err != nil {
		return s.InternalError("failed to read message: %v", err)
	}
	s.Log("[LMTP] message data read successfully (%d bytes)", buf.Len())

	// Use the full message bytes as received for hashing, size, and header extraction.
	fullMessageBytes := buf.Bytes()

	// Extract raw headers string.
	// Headers are typically terminated by a double CRLF (\r\n\r\n).
	var rawHeadersText string
	headerEndIndex := bytes.Index(fullMessageBytes, []byte("\r\n\r\n"))
	if headerEndIndex != -1 {
		rawHeadersText = string(fullMessageBytes[:headerEndIndex])
	} else {
		// Log if headers are not clearly separated. rawHeadersText will be empty.
		// This might indicate a malformed email or an email with only headers and no body separator.
		s.Log("[LMTP] WARNING: could not find standard header/body separator (\\r\\n\\r\\n) in message. Raw headers field will be empty.")
	}

	messageContent, err := server.ParseMessage(bytes.NewReader(fullMessageBytes))
	if err != nil {
		return s.InternalError("failed to parse message: %v", err)
	}

	contentHash := helpers.HashContent(fullMessageBytes)
	s.Log("[LMTP] message parsed with content hash: %s", contentHash)

	// Parse message headers (this does not consume the body)
	mailHeader := mail.Header{Header: messageContent.Header}
	subject, _ := mailHeader.Subject()
	messageID, _ := mailHeader.MessageID()
	sentDate, _ := mailHeader.Date()
	inReplyTo, _ := mailHeader.MsgIDList("In-Reply-To")

	if sentDate.IsZero() {
		sentDate = time.Now()
		s.Log("[LMTP] no sent date found, using current time: %v", sentDate)
	} else {
		s.Log("[LMTP] message sent date: %v", sentDate)
	}

	bodyStructure := imapserver.ExtractBodyStructure(bytes.NewReader(buf.Bytes()))
	plaintextBody, err := helpers.ExtractPlaintextBody(messageContent)
	if err != nil {
		s.Log("[LMTP] Failed to extract plaintext body: %v", err)
		// The plaintext body is needed only for indexing, so we can ignore the error
	}

	recipients := helpers.ExtractRecipients(messageContent.Header)

	filePath, err := s.backend.uploader.StoreLocally(contentHash, fullMessageBytes)
	if err != nil {
		return s.InternalError("failed to save message to disk: %v", err)
	}
	s.Log("[LMTP] message stored locally at: %s", *filePath)

	// SIEVE script processing

	activeScript, err := s.backend.db.GetActiveScript(s.ctx, s.UserID())
	var result sieveengine.Result
	var mailboxName string

	// Create an adapter for the VacationOracle interface
	sieveVacOracle := &dbVacationOracle{
		db:     *s.backend.db,
		userID: s.UserID(),
		// s.sender is available if needed, but Sieve's VacationResponseAllowed gets originalSender
	}

	// Create the sieve context (used for both default and user scripts)
	sieveCtx := sieveengine.Context{
		EnvelopeFrom: s.sender.FullAddress(),
		EnvelopeTo:   s.User.Address.FullAddress(),
		Header:       messageContent.Header.Map(),
		Body:         *plaintextBody,
	}

	// Always run the default script first as a "before script"
	// The default script typically doesn't involve user-specific vacation persistence,
	// so we can pass a nil oracle. The SievePolicy will handle this gracefully.
	defaultSieveExecutor, defaultScriptErr := sieveengine.NewSieveExecutorWithOracle(defaultSieveScript, s.UserID(), nil)
	if defaultScriptErr != nil {
		s.Log("[LMTP] failed to create default sieve executor: %v", defaultScriptErr)
		// If we can't create a default sieve executor, use a simple keep action
		result = sieveengine.Result{Action: sieveengine.ActionKeep}
	} else {
		s.Log("[LMTP] message headers for SIEVE evaluation:")
		for key, values := range sieveCtx.Header {
			for _, value := range values {
				s.Log("[LMTP] Header: %s: %s", key, value)
			}
		}

		defaultResult, defaultEvalErr := defaultSieveExecutor.Evaluate(s.ctx, sieveCtx)
		if defaultEvalErr != nil {
			s.Log("[LMTP] default SIEVE evaluation error: %v", defaultEvalErr)
			// fallback: default to INBOX
			result = sieveengine.Result{Action: sieveengine.ActionKeep}
		} else {
			// Set the result from the default script
			result = defaultResult
			s.Log("[LMTP] default script result action: %v", result.Action)

			// Log more details about the action
			switch result.Action {
			case sieveengine.ActionFileInto:
				s.Log("[LMTP] default SIEVE fileinto: %s", result.Mailbox)
			case sieveengine.ActionRedirect:
				s.Log("[LMTP] default SIEVE redirect: %s", result.RedirectTo)
			case sieveengine.ActionDiscard:
				s.Log("[LMTP] default SIEVE discard")
			case sieveengine.ActionVacation:
				s.Log("[LMTP] default SIEVE vacation response triggered")
			case sieveengine.ActionKeep:
				s.Log("[LMTP] default SIEVE keep (deliver to INBOX)")
			}
		}
	}

	// If user has an active script, run it and let it override the resultAction
	if err == nil && activeScript != nil {
		s.Log("[LMTP] using user's active script: %s", activeScript.Name)
		userSieveExecutor, userScriptErr := sieveengine.NewSieveExecutorWithOracle(activeScript.Script, s.UserID(), sieveVacOracle)
		if userScriptErr != nil {
			s.Log("[LMTP] failed to create sieve executor from user script: %v", userScriptErr)
			// Keep the result from the default script
		} else {
			userResult, userEvalErr := userSieveExecutor.Evaluate(s.ctx, sieveCtx)
			if userEvalErr != nil {
				s.Log("[LMTP] user SIEVE evaluation error: %v", userEvalErr)
				// Keep the result from the default script
			} else {
				// Override the result with the user script result
				result = userResult
				s.Log("[LMTP] user script overrode result action: %v", result.Action)

				// Log more details about the action
				switch result.Action {
				case sieveengine.ActionFileInto:
					s.Log("[LMTP] user SIEVE fileinto: %s", result.Mailbox)
				case sieveengine.ActionRedirect:
					s.Log("[LMTP] user SIEVE redirect: %s", result.RedirectTo)
				case sieveengine.ActionDiscard:
					s.Log("[LMTP] user SIEVE discard")
				case sieveengine.ActionVacation:
					s.Log("[LMTP] user SIEVE vacation response triggered")
				case sieveengine.ActionKeep:
					s.Log("[LMTP] user SIEVE keep (deliver to INBOX)")
				}
			}
		}
	} else {
		if err != nil && err != consts.ErrDBNotFound {
			s.Log("[LMTP] failed to get active script: %v", err)
		} else {
			s.Log("[LMTP] no active script found, using only default script result")
		}
	}

	// Process the result
	s.Log("[LMTP] processing final SIEVE action: %v", result.Action)

	switch result.Action {
	case sieveengine.ActionDiscard:
		s.Log("[LMTP] message discarded by SIEVE - message will not be delivered")
		return nil

	case sieveengine.ActionFileInto:
		mailboxName = result.Mailbox
		s.Log("[LMTP] SIEVE fileinto action - delivering message to mailbox: %s", mailboxName)

	case sieveengine.ActionRedirect:
		s.Log("[LMTP] SIEVE redirect action - redirecting message to: %s", result.RedirectTo)

		// Send the message to the external relay if configured
		if s.backend.externalRelay != "" {
			s.Log("[LMTP] redirected message via external relay: %s", s.backend.externalRelay)
			err := s.sendToExternalRelay(s.sender.FullAddress(), result.RedirectTo, fullMessageBytes)
			if err != nil {
				s.Log("[LMTP] error sending redirected message to external relay: %v", err)
				s.Log("[LMTP] falling back to local delivery to INBOX")
				// Continue processing even if relay fails, store in INBOX as fallback
			} else {
				s.Log("[LMTP] successfully sent redirected message to %s via external relay %s",
					result.RedirectTo, s.backend.externalRelay)
				// Message was successfully relayed, no need to store it locally
				return nil
			}
		} else {
			s.Log("[LMTP] external relay not configured, storing message in INBOX")
		}

		// Fallback: store in INBOX if relay is not configured or fails
		mailboxName = consts.MailboxInbox

	case sieveengine.ActionVacation:
		s.Log("[LMTP] SIEVE vacation action - sending auto-response and delivering original message to INBOX")
		// Handle vacation response
		err := s.handleVacationResponse(result, messageContent)
		if err != nil {
			s.Log("[LMTP] error handling vacation response: %v", err)
			// Continue processing even if vacation response fails
		}
		// Store the original message in INBOX
		mailboxName = consts.MailboxInbox

	default:
		s.Log("[LMTP] SIEVE keep action (default) - delivering message to INBOX")
		mailboxName = consts.MailboxInbox
	}

	mailbox, err := s.backend.db.GetMailboxByName(s.ctx, s.UserID(), mailboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.Log("[LMTP] mailbox '%s' not found, falling back to INBOX", mailboxName)
			mailbox, err = s.backend.db.GetMailboxByName(s.ctx, s.UserID(), consts.MailboxInbox)
			if err != nil {
				return s.InternalError("failed to get INBOX mailbox: %v", err)
			}
		} else {
			return s.InternalError("failed to get mailbox '%s': %v", mailboxName, err)
		}
	}

	size := int64(len(fullMessageBytes))

	_, messageUID, err := s.backend.db.InsertMessage(s.ctx,
		&db.InsertMessageOptions{
			UserID:        s.UserID(),
			MailboxID:     mailbox.ID,
			MailboxName:   mailbox.Name,
			ContentHash:   contentHash, // The S3 key is the content hash of the message
			MessageID:     messageID,
			InternalDate:  time.Now(),
			Size:          size,
			Subject:       subject,
			PlaintextBody: *plaintextBody,
			SentDate:      sentDate,
			InReplyTo:     inReplyTo,
			BodyStructure: &bodyStructure,
			Recipients:    recipients,
			Flags:         []imap.Flag{}, // Explicitly set empty flags to mark as unread
			RawHeaders:    rawHeadersText,
		},
		db.PendingUpload{ // This struct is used to pass data to InsertMessage, not directly inserted into DB here
			ContentHash: contentHash,
			InstanceID:  s.backend.hostname,
			Size:        size,
		})
	if err != nil {
		_ = os.Remove(*filePath) // cleanup file on failure
		if err == consts.ErrDBUniqueViolation {
			// Message already exists, continue with the next message
			s.Log("[LMTP] message already exists in database (content hash: %s)", contentHash)
			return &smtp.SMTPError{
				Code:         541,
				EnhancedCode: smtp.EnhancedCode{5, 0, 1},
				Message:      "Message already exists",
			}
		}
		return s.InternalError("[LMTP] failed to save message: %v", err)
	}

	s.backend.uploader.NotifyUploadQueued()

	s.Log("[LMTP] saved with UID %d in mailbox '%s'", messageUID, mailbox.Name)
	return nil
}

func (s *LMTPSession) Reset() {
	// Acquire write lock to reset session state
	acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
	defer cancel()
	if !acquired {
		s.Log("[LMTP] failed to acquire write lock for Reset command")
		return
	}

	s.User = nil
	s.sender = nil
	s.mutex.Unlock()

	s.Log("[LMTP] session reset")
}

func (s *LMTPSession) Logout() error {
	// Check if this is a normal QUIT command or an abrupt connection close
	if s.conn != nil && s.conn.Conn() != nil {
		s.Log("[LMTP] session logout requested")
	} else {
		s.Log("[LMTP] client dropped connection")
	}

	// Acquire write lock for logout operations
	acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
	defer cancel()
	if !acquired {
		s.Log("[LMTP] failed to acquire write lock for Logout command")
		// Continue with logout even if we can't get the lock
	} else {
		// Clean up any session state if needed
		s.mutex.Unlock()
	}

	if s.cancel != nil {
		s.cancel()
		s.Log("[LMTP] session context canceled")
	}

	s.Log("[LMTP] session logout completed")
	return &smtp.SMTPError{
		Code:         221,
		EnhancedCode: smtp.EnhancedCode{2, 0, 0},
		Message:      "Closing transmission channel",
	}
}

func (s *LMTPSession) InternalError(format string, a ...interface{}) error {
	s.Log(format, a...)
	errorMsg := fmt.Sprintf(format, a...)
	s.Log("[LMTP] internal error: %s", errorMsg)
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
	if s.backend.externalRelay == "" {
		s.Log("[LMTP] external relay not configured, cannot send vacation response for sender: %s", s.sender.FullAddress())
		// Do not return error, as the Sieve engine might have already recorded the attempt.
		return nil
	}

	// Create the vacation response message
	var vacationFrom string
	if result.VacationFrom != "" {
		vacationFrom = result.VacationFrom
		s.Log("[LMTP] using custom vacation from address: %s", vacationFrom)
	} else {
		vacationFrom = s.User.Address.FullAddress()
		s.Log("[LMTP] using default vacation from address: %s", vacationFrom)
	}

	var vacationSubject string
	if result.VacationSubj != "" {
		vacationSubject = result.VacationSubj
		s.Log("[LMTP] using custom vacation subject: %s", vacationSubject)
	} else {
		vacationSubject = "Auto: Out of Office"
		s.Log("[LMTP] using default vacation subject: %s", vacationSubject)
	}

	// Get the original message ID for the In-Reply-To header
	originalHeader := mail.Header{Header: originalMessage.Header}
	originalMessageID, _ := originalHeader.MessageID()
	if originalMessageID != "" {
		s.Log("[LMTP] Using original message ID for In-Reply-To: %s", originalMessageID)
	}

	s.Log("[LMTP] Creating vacation response message")
	var vacationMessage bytes.Buffer
	var h message.Header
	h.Set("From", vacationFrom)
	h.Set("To", s.sender.FullAddress())
	h.Set("Subject", vacationSubject)
	messageID := fmt.Sprintf("<%d.vacation@%s>", time.Now().UnixNano(), s.HostName)
	h.Set("Message-ID", messageID)
	s.Log("[LMTP] Vacation message ID: %s", messageID)

	if originalMessageID != "" {
		h.Set("In-Reply-To", originalMessageID)
		h.Set("References", originalMessageID)
	}
	h.Set("Auto-Submitted", "auto-replied")
	h.Set("X-Auto-Response-Suppress", "All")
	h.Set("Date", time.Now().Format(time.RFC1123Z))

	w, err := message.CreateWriter(&vacationMessage, h)
	if err != nil {
		s.Log("[LMTP] Error creating message writer: %v", err)
		return fmt.Errorf("failed to create message writer: %w", err)
	}

	var textHeader message.Header
	textHeader.Set("Content-Type", "text/plain; charset=utf-8")
	textWriter, err := w.CreatePart(textHeader)
	if err != nil {
		s.Log("[LMTP] Error creating text part: %v", err)
		return fmt.Errorf("failed to create text part: %w", err)
	}

	s.Log("[LMTP] Adding vacation message body (length: %d bytes)", len(result.VacationMsg))
	_, err = textWriter.Write([]byte(result.VacationMsg))
	if err != nil {
		s.Log("[LMTP] Error writing vacation message body: %v", err)
		return fmt.Errorf("failed to write vacation message body: %w", err)
	}

	textWriter.Close()
	w.Close()

	sendErr := s.sendToExternalRelay(vacationFrom, s.sender.FullAddress(), vacationMessage.Bytes())
	if sendErr != nil {
		s.Log("[LMTP] error sending vacation response via external relay: %v", sendErr)
		// The Sieve engine's policy should have already recorded the response attempt.
		// Failure here is a delivery issue.
	} else {
		s.Log("[LMTP] sent vacation response to %s via external relay %s",
			s.sender.FullAddress(), s.backend.externalRelay)
	}

	// The recording of the vacation response is now handled by SievePolicy via VacationOracle
	return nil
}

// dbVacationOracle implements the sieveengine.VacationOracle interface using the database.
type dbVacationOracle struct {
	db     db.Database
	userID int64
}

// IsVacationResponseAllowed checks if a vacation response is allowed for the given original sender and handle.
func (o *dbVacationOracle) IsVacationResponseAllowed(ctx context.Context, userID int64, originalSender string, handle string, duration time.Duration) (bool, error) {
	// Note: Current db.HasRecentVacationResponse does not take 'handle'.
	// This might require DB schema/method changes or adapting how 'handle' is stored/checked.
	// For this example, we'll ignore 'handle' for the DB check, assuming the DB stores per (userID, originalSender).
	hasRecent, err := o.db.HasRecentVacationResponse(ctx, userID, originalSender, duration)
	if err != nil {
		return false, fmt.Errorf("checking db for recent vacation response: %w", err)
	}
	return !hasRecent, nil // Allowed if no recent response found
}

// RecordVacationResponseSent records that a vacation response has been sent.
func (o *dbVacationOracle) RecordVacationResponseSent(ctx context.Context, userID int64, originalSender string, handle string) error {
	// Note: Current db.RecordVacationResponse does not take 'handle'.
	// This might require DB schema/method changes or adapting how 'handle' is stored/recorded.
	// For this example, we'll ignore 'handle' for the DB recording.
	return o.db.RecordVacationResponse(ctx, userID, originalSender)
}
