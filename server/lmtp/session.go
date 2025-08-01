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
	s.Log("processing MAIL FROM command: %s", from)
	fromAddress, err := server.NewAddress(from)
	if err != nil {
		s.Log("invalid from address: %v", err)
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
		s.Log("failed to acquire write lock for Mail command")
		return &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 4, 5},
			Message:      "Server busy, try again later",
		}
	}

	s.sender = &fromAddress
	s.mutex.Unlock()

	s.Log("mail from=%s accepted", fromAddress.FullAddress())
	return nil
}

func (s *LMTPSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.Log("processing RCPT TO command: %s", to)
	toAddress, err := server.NewAddress(to)
	if err != nil {
		s.Log("invalid to address: %v", err)
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
		s.Log("ignoring address detail for lookup: %s -> %s", fullAddress, lookupAddress)
	}

	s.Log("looking up user ID for address: %s", lookupAddress)
	userId, err := s.backend.db.GetAccountIDByAddress(s.ctx, lookupAddress)
	if err != nil {
		s.Log("failed to get user ID by address: %v", err)
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
		s.Log("failed to acquire write lock for Rcpt command")
		return &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 4, 5},
			Message:      "Server busy, try again later",
		}
	}

	// Use the original address (with detail part) for the User object
	s.User = server.NewUser(toAddress, userId)
	s.mutex.Unlock()

	// Ensure default mailboxes (INBOX/Drafts/Sent/Spam/Trash) exist
	err = s.backend.db.CreateDefaultMailboxes(s.ctx, userId)
	if err != nil {
		return s.InternalError("failed to create default mailboxes: %v", err)
	}

	s.Log("recipient accepted: %s (UserID: %d)", fullAddress, userId)
	return nil
}

func (s *LMTPSession) Data(r io.Reader) error {
	// Acquire read lock for accessing session state during message processing
	acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
	defer cancel()
	if !acquired {
		s.Log("failed to acquire read lock for Data command")
		return &smtp.SMTPError{
			Code:         421,
			EnhancedCode: smtp.EnhancedCode{4, 4, 5},
			Message:      "Server busy, try again later",
		}
	}
	defer s.mutex.RUnlock()

	// Check if we have a valid sender and recipient
	if s.sender == nil || s.User == nil {
		s.Log("DATA command received without valid sender or recipient")
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
	s.Log("message data read successfully (%d bytes)", buf.Len())

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
		s.Log("WARNING: could not find standard header/body separator (\\r\\n\\r\\n) in message. Raw headers field will be empty.")
	}

	messageContent, err := server.ParseMessage(bytes.NewReader(fullMessageBytes))
	if err != nil {
		return s.InternalError("failed to parse message: %v", err)
	}

	contentHash := helpers.HashContent(fullMessageBytes)
	s.Log("message parsed with content hash: %s", contentHash)

	// Parse message headers (this does not consume the body)
	mailHeader := mail.Header{Header: messageContent.Header}
	subject, _ := mailHeader.Subject()
	messageID, _ := mailHeader.MessageID()
	sentDate, _ := mailHeader.Date()
	inReplyTo, _ := mailHeader.MsgIDList("In-Reply-To")

	if sentDate.IsZero() {
		sentDate = time.Now()
		s.Log("no sent date found, using current time: %v", sentDate)
	} else {
		s.Log("message sent date: %v", sentDate)
	}

	bodyStructureVal := imapserver.ExtractBodyStructure(bytes.NewReader(buf.Bytes()))
	bodyStructure := &bodyStructureVal
	plaintextBody, err := helpers.ExtractPlaintextBody(messageContent)
	if err != nil {
		s.Log("WARNING: failed to extract plaintext body: %v", err)
		// The plaintext body is needed only for indexing, so we can ignore the error
	}

	recipients := helpers.ExtractRecipients(messageContent.Header)

	filePath, err := s.backend.uploader.StoreLocally(contentHash, fullMessageBytes)
	if err != nil {
		return s.InternalError("failed to save message to disk: %v", err)
	}
	s.Log("message accepted locally at: %s", *filePath)

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
		s.Log("[SIEVE] WARNING: failed to create default sieve executor: %v", defaultScriptErr)
		// If we can't create a default sieve executor, use a simple keep action
		result = sieveengine.Result{Action: sieveengine.ActionKeep}
	} else {
		// SIEVE debugging information
		if s.backend.debug {
			s.Log("[SIEVE] message headers for evaluation:")
			for key, values := range sieveCtx.Header {
				for _, value := range values {
					s.Log("[SIEVE] header: %s: %s", key, value)
				}
			}
		}

		defaultResult, defaultEvalErr := defaultSieveExecutor.Evaluate(s.ctx, sieveCtx)
		if defaultEvalErr != nil {
			s.Log("[SIEVE] WARNING: default script evaluation error: %v", defaultEvalErr)
			// fallback: default to INBOX
			result = sieveengine.Result{Action: sieveengine.ActionKeep}
		} else {
			// Set the result from the default script
			result = defaultResult
			s.Log("[SIEVE] default script result action: %v", result.Action)

			// Log more details about the action
			switch result.Action {
			case sieveengine.ActionFileInto:
				s.Log("[SIEVE] default fileinto: %s", result.Mailbox)
			case sieveengine.ActionRedirect:
				s.Log("[SIEVE] default redirect: %s", result.RedirectTo)
			case sieveengine.ActionDiscard:
				s.Log("[SIEVE] default discard")
			case sieveengine.ActionVacation:
				s.Log("[SIEVE] default vacation response triggered")
			case sieveengine.ActionKeep:
				s.Log("[SIEVE] default keep (deliver to INBOX)")
			}
		}
	}

	// If user has an active script, run it and let it override the resultAction
	if err == nil && activeScript != nil {
		s.Log("[SIEVE] using user's active script: %s", activeScript.Name)
		userSieveExecutor, userScriptErr := sieveengine.NewSieveExecutorWithOracle(activeScript.Script, s.UserID(), sieveVacOracle)
		if userScriptErr != nil {
			s.Log("[SIEVE] WARNING: failed to create sieve executor from user script: %v", userScriptErr)
			// Keep the result from the default script
		} else {
			userResult, userEvalErr := userSieveExecutor.Evaluate(s.ctx, sieveCtx)
			if userEvalErr != nil {
				s.Log("[SIEVE] user script evaluation error: %v", userEvalErr)
				// Keep the result from the default script
			} else {
				// Override the result with the user script result
				result = userResult
				s.Log("[SIEVE] user script overrode result action: %v", result.Action)

				// Log more details about the action
				switch result.Action {
				case sieveengine.ActionFileInto:
					s.Log("[SIEVE] user fileinto: %s", result.Mailbox)
				case sieveengine.ActionRedirect:
					s.Log("[SIEVE] user redirect: %s", result.RedirectTo)
				case sieveengine.ActionDiscard:
					s.Log("[SIEVE] user discard")
				case sieveengine.ActionVacation:
					s.Log("[SIEVE] user vacation response triggered")
				case sieveengine.ActionKeep:
					s.Log("[SIEVE] user keep (deliver to INBOX)")
				}
			}
		}
	} else {
		if err != nil && err != consts.ErrDBNotFound {
			s.Log("[SIEVE] WARNING: failed to get active script: %v", err)
		} else {
			s.Log("[SIEVE] no active script found, using default script result")
		}
	}

	s.Log("[SIEVE] executing action: %v", result.Action)

	switch result.Action {
	case sieveengine.ActionDiscard:
		s.Log("[SIEVE] WARNING: message discarded - message will not be delivered")
		return nil

	case sieveengine.ActionFileInto:
		mailboxName = result.Mailbox
		if result.Copy {
			s.Log("[SIEVE] fileinto :copy action - delivering message to mailbox: %s and INBOX", mailboxName)

			// First save to the specified mailbox
			err := s.saveMessageToMailbox(mailboxName, messageContent, fullMessageBytes, contentHash,
				subject, messageID, sentDate, inReplyTo, bodyStructure, plaintextBody, recipients, rawHeadersText)
			if err != nil {
				return s.InternalError("failed to save message to specified mailbox: %v", err)
			}

			// Then save to INBOX (for the :copy functionality)
			s.Log("[SIEVE] saving copy to INBOX due to :copy modifier")

			// Call saveMessageToMailbox again for INBOX
			err = s.saveMessageToMailbox(consts.MailboxInbox, messageContent, fullMessageBytes, contentHash,
				subject, messageID, sentDate, inReplyTo, bodyStructure, plaintextBody, recipients, rawHeadersText)
			if err != nil {
				return s.InternalError("failed to save message copy to INBOX: %v", err)
			}

			// Success - both copies saved
			s.Log("message delivered according to fileinto :copy directive")
			return nil
		} else {
			s.Log("[SIEVE] fileinto action - delivering message to mailbox: %s", mailboxName)
		}

	case sieveengine.ActionRedirect:
		if result.Copy {
			s.Log("[SIEVE][REDIRECT] redirect :copy action - redirecting message to: %s (with local copy)", result.RedirectTo)
		} else {
			s.Log("[SIEVE][REDIRECT] redirect action - redirecting message to: %s", result.RedirectTo)
		}

		// Send the message to the external relay if configured
		if s.backend.externalRelay != "" {
			s.Log("[SIEVE][REDIRECT] redirected message via external relay: %s", s.backend.externalRelay)
			err := s.sendToExternalRelay(s.sender.FullAddress(), result.RedirectTo, fullMessageBytes)
			if err != nil {
				s.Log("[SIEVE][REDIRECT] WARNING: error sending redirected message to external relay, falling back to local INBOX delivery: %v", err)
				// Continue processing even if relay fails, store in INBOX as fallback
			} else {
				s.Log("[SIEVE][REDIRECT] successfully redirected message to %s via external relay %s",
					result.RedirectTo, s.backend.externalRelay)

				// If :copy is not specified and relay succeeded, we don't store the message locally
				if !result.Copy {
					s.Log("[SIEVE][REDIRECT] redirect without :copy - skipping local delivery")
					return nil
				}
				s.Log("[SIEVE][REDIRECT] redirect :copy - continuing with local delivery")
			}
		} else {
			s.Log("[SIEVE][REDIRECT] WARNING: redirect requested but external relay not configured, storing message in INBOX")
		}

		// Fallback: store in INBOX if relay is not configured or fails
		// Or if :copy is specified
		mailboxName = consts.MailboxInbox

	case sieveengine.ActionVacation:
		// Handle vacation response
		err := s.handleVacationResponse(result, messageContent)
		if err != nil {
			s.Log("[SIEVE] WARNING: error handling vacation response: %v", err)
			// Continue processing even if vacation response fails
		}
		// Store the original message in INBOX
		mailboxName = consts.MailboxInbox

	default:
		s.Log("[SIEVE] keep action (default) - delivering message to INBOX")
		mailboxName = consts.MailboxInbox
	}

	// Save the message to the determined mailbox (either the specified one or INBOX)
	err = s.saveMessageToMailbox(mailboxName, messageContent, fullMessageBytes, contentHash,
		subject, messageID, sentDate, inReplyTo, bodyStructure, plaintextBody, recipients, rawHeadersText)
	if err != nil {
		_ = os.Remove(*filePath) // cleanup file on failure
		if err.Error() == "message already exists: unique violation" {
			s.Log("WARNING: message already exists in database (content hash: %s)", contentHash)
			return &smtp.SMTPError{
				Code:         541,
				EnhancedCode: smtp.EnhancedCode{5, 0, 1},
				Message:      "Message already exists",
			}
		}
		return s.InternalError("failed to save message: %v", err)
	}

	s.Log("message delivered successfully to mailbox '%s'", mailboxName)
	return nil
}

func (s *LMTPSession) Reset() {
	// Acquire write lock to reset session state
	acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
	defer cancel()
	if !acquired {
		s.Log("WARNING: failed to acquire write lock for Reset command")
		return
	}

	s.User = nil
	s.sender = nil
	s.mutex.Unlock()

	s.Log("session reset")
}

func (s *LMTPSession) Logout() error {
	// Check if this is a normal QUIT command or an abrupt connection close
	if s.conn != nil && s.conn.Conn() != nil {
		s.Log("session logout requested")
	} else {
		s.Log("client dropped connection")
	}

	// Acquire write lock for logout operations
	acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
	defer cancel()
	if !acquired {
		s.Log("WARNING: failed to acquire write lock for Logout command")
		// Continue with logout even if we can't get the lock
	} else {
		// Clean up any session state if needed
		s.mutex.Unlock()
	}

	totalCount := s.backend.totalConnections.Add(-1)

	if s.cancel != nil {
		s.cancel()
	}

	s.Log("session logout completed (connections: total=%d)", totalCount)
	return &smtp.SMTPError{
		Code:         221,
		EnhancedCode: smtp.EnhancedCode{2, 0, 0},
		Message:      "Closing transmission channel",
	}
}

func (s *LMTPSession) InternalError(format string, a ...interface{}) error {
	s.Log(format, a...)
	errorMsg := fmt.Sprintf(format, a...)
	s.Log("INTERNAL ERROR: %s", errorMsg)
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
		s.Log("[SIEVE][VACATION] WARNING: external relay not configured, cannot send vacation response for sender: %s", s.sender.FullAddress())
		// Do not return error, as the Sieve engine might have already recorded the attempt.
		return nil
	}

	// Create the vacation response message
	var vacationFrom string
	if result.VacationFrom != "" {
		vacationFrom = result.VacationFrom
		s.Log("[SIEVE][VACATION] using custom vacation from address: %s", vacationFrom)
	} else {
		vacationFrom = s.User.Address.FullAddress()
		s.Log("[SIEVE][VACATION] using default vacation from address: %s", vacationFrom)
	}

	var vacationSubject string
	if result.VacationSubj != "" {
		vacationSubject = result.VacationSubj
		s.Log("[SIEVE][VACATION] using custom vacation subject: %s", vacationSubject)
	} else {
		vacationSubject = "Auto: Out of Office"
		s.Log("[SIEVE][VACATION] using default vacation subject: %s", vacationSubject)
	}

	// Get the original message ID for the In-Reply-To header
	originalHeader := mail.Header{Header: originalMessage.Header}
	originalMessageID, _ := originalHeader.MessageID()
	if originalMessageID != "" {
		s.Log("[SIEVE][VACATION] using original message ID for In-Reply-To: %s", originalMessageID)
	}

	s.Log("[SIEVE][VACATION] creating response message")
	var vacationMessage bytes.Buffer
	var h message.Header
	h.Set("From", vacationFrom)
	h.Set("To", s.sender.FullAddress())
	h.Set("Subject", vacationSubject)
	messageID := fmt.Sprintf("<%d.vacation@%s>", time.Now().UnixNano(), s.HostName)
	h.Set("Message-ID", messageID)
	s.Log("[SIEVE][VACATION] vacation message ID: %s", messageID)

	if originalMessageID != "" {
		h.Set("In-Reply-To", originalMessageID)
		h.Set("References", originalMessageID)
	}
	h.Set("Auto-Submitted", "auto-replied")
	h.Set("X-Auto-Response-Suppress", "All")
	h.Set("Date", time.Now().Format(time.RFC1123Z))

	w, err := message.CreateWriter(&vacationMessage, h)
	if err != nil {
		s.Log("[SIEVE][VACATION] WARNING: error creating message writer: %v", err)
		return fmt.Errorf("failed to create message writer: %w", err)
	}

	var textHeader message.Header
	textHeader.Set("Content-Type", "text/plain; charset=utf-8")
	textWriter, err := w.CreatePart(textHeader)
	if err != nil {
		s.Log("[SIEVE][VACATION] WARNING: error creating text part: %v", err)
		return fmt.Errorf("failed to create text part: %w", err)
	}

	s.Log("[SIEVE][VACATION] adding vacation message body (length: %d bytes)", len(result.VacationMsg))
	_, err = textWriter.Write([]byte(result.VacationMsg))
	if err != nil {
		s.Log("[SIEVE][VACATION] WARNING: error writing vacation message body: %v", err)
		return fmt.Errorf("failed to write vacation message body: %w", err)
	}

	textWriter.Close()
	w.Close()

	sendErr := s.sendToExternalRelay(vacationFrom, s.sender.FullAddress(), vacationMessage.Bytes())
	if sendErr != nil {
		s.Log("[SIEVE][VACATION] WARNING: error sending vacation response via external relay: %v", sendErr)
		// The Sieve engine's policy should have already recorded the response attempt.
		// Failure here is a delivery issue.
	} else {
		s.Log("[SIEVE][VACATION] sent vacation response to %s via external relay %s",
			s.sender.FullAddress(), s.backend.externalRelay)
	}

	// The recording of the vacation response is now handled by SievePolicy via VacationOracle
	return nil
}

// saveMessageToMailbox saves a message to the specified mailbox
func (s *LMTPSession) saveMessageToMailbox(mailboxName string, messageContent *message.Entity,
	fullMessageBytes []byte, contentHash string, subject string, messageID string,
	sentDate time.Time, inReplyTo []string, bodyStructure *imap.BodyStructure,
	plaintextBody *string, recipients []helpers.Recipient, rawHeadersText string) error {

	mailbox, err := s.backend.db.GetMailboxByName(s.ctx, s.UserID(), mailboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.Log("WARNING: mailbox '%s' not found, falling back to INBOX", mailboxName)
			mailbox, err = s.backend.db.GetMailboxByName(s.ctx, s.UserID(), consts.MailboxInbox)
			if err != nil {
				return fmt.Errorf("failed to get INBOX mailbox: %v", err)
			}
		} else {
			return fmt.Errorf("failed to get mailbox '%s': %v", mailboxName, err)
		}
	}

	size := int64(len(fullMessageBytes))

	_, messageUID, err := s.backend.db.InsertMessage(s.ctx,
		&db.InsertMessageOptions{
			UserID:        s.UserID(),
			MailboxID:     mailbox.ID,
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
		},
		db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  s.backend.hostname,
			Size:        size,
		})

	if err != nil {
		if err == consts.ErrDBUniqueViolation {
			s.Log("WARNING: message already exists in database (content hash: %s)", contentHash)
			return fmt.Errorf("message already exists: unique violation")
		}
		return fmt.Errorf("failed to save message: %v", err)
	}

	s.backend.uploader.NotifyUploadQueued()
	s.Log("message saved with UID %d in mailbox '%s'", messageUID, mailbox.Name)
	return nil
}
