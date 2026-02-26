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
	backend       *LMTPServerBackend
	sender        *server.Address
	recipientAddr *server.Address // Original recipient address (may include +detail)
	conn          *smtp.Conn
	cancel        context.CancelFunc
	ctx           context.Context
	mutex         sync.RWMutex
	mutexHelper   *server.MutexTimeoutHelper
	releaseConn   func() // Function to release connection from limiter
	useMasterDB   bool   // Pin session to master DB after a write to ensure consistency
	startTime     time.Time
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

	// Look up account ID by credential address (excluding deleted accounts)
	AccountID, err := s.backend.rdb.GetActiveAccountIDByAddressWithRetry(readCtx, lookupAddress)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			// User not found or account deleted - permanent failure
			s.DebugLog("user not found", "address", lookupAddress)
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 1, 1},
				Message:      "No such user here",
			}
		}
		// Database error (connection failure, timeout, etc.) - temporary failure
		s.WarnLog("database error during user lookup", "address", lookupAddress, "error", err)
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 4, 3},
			Message:      "Temporary failure, please try again later",
		}
	}

	// This is a potential write operation, so it must use the main context.
	// Ensure default mailboxes (INBOX/Drafts/Sent/Spam/Trash) exist. Use the resilient method.
	err = s.backend.rdb.CreateDefaultMailboxesWithRetry(s.ctx, AccountID)
	if err != nil {
		return s.InternalError("failed to create default mailboxes: %v", err)
	}

	// Get primary email address for this account
	// User.Address should always be the primary address (not the recipient with +alias)
	primaryAddr, err := s.backend.rdb.GetPrimaryEmailForAccountWithRetry(readCtx, AccountID)
	if err != nil {
		s.WarnLog("failed to get primary email", "account_id", AccountID, "error", err)
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 4, 3},
			Message:      "Temporary failure, please try again later",
		}
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
	s.User = server.NewUser(primaryAddr, AccountID) // Always use primary address

	// Construct envelope recipient address for Sieve:
	// - If original recipient has +detail, preserve it but use primary address domain
	// - This handles both direct delivery (user+detail@domain) and aliases (alias+detail@otherdomain)
	envelopeRecipient := toAddress
	if toAddress.Detail() != "" && toAddress.BaseAddress() != primaryAddr.BaseAddress() {
		// Alias with +detail: construct primaryUser+detail@primaryDomain
		primaryWithDetail, err := server.NewAddress(primaryAddr.LocalPart() + "+" + toAddress.Detail() + "@" + primaryAddr.Domain())
		if err != nil {
			// Fallback to original if construction fails
			s.WarnLog("failed to construct envelope address with detail", "error", err)
		} else {
			envelopeRecipient = primaryWithDetail
		}
	}
	s.recipientAddr = &envelopeRecipient // Store for Sieve envelope (with +detail preserved on primary address)

	// Pin the session to the master DB to prevent reading stale data from a replica.
	s.useMasterDB = true

	success = true

	// Log recipient acceptance with alias detection
	if fullAddress != primaryAddr.FullAddress() {
		s.DebugLog("recipient accepted", "recipient", fullAddress, "primary_address", primaryAddr.FullAddress(), "account_id", AccountID)
	} else {
		s.DebugLog("recipient accepted", "recipient", fullAddress, "account_id", AccountID)
	}
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
	} else if plaintextBodyResult == nil {
		// No plaintext or HTML body found in the message
		// Use empty string as fallback
		emptyStr := new(string)
		plaintextBody = emptyStr
	} else {
		plaintextBody = plaintextBodyResult
	}

	recipients := helpers.ExtractRecipients(messageContent.Header)

	// SIEVE script processing (BEFORE storing locally)
	// We need to run Sieve and apply header edits BEFORE storing the message,
	// so that the stored file has the modified headers

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
	// Use recipientAddr (original RCPT TO with +detail) for envelope, not primary address
	envelopeTo := s.User.Address.FullAddress()
	if s.recipientAddr != nil {
		envelopeTo = s.recipientAddr.FullAddress()
	}

	// Note: Header normalization is now handled by sieveengine.Evaluate()
	// to ensure consistent case-insensitive matching per RFC 5228 §2.6.2.1
	sieveCtx := sieveengine.Context{
		EnvelopeFrom: s.sender.FullAddress(),
		EnvelopeTo:   envelopeTo,
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
			s.WarnLog("default sieve script evaluation error", "error", defaultEvalErr)
			// fallback: default to INBOX
			result = sieveengine.Result{Action: sieveengine.ActionKeep}
		} else {
			metrics.SieveExecutions.WithLabelValues("lmtp", "success").Inc()
			// Set the result from the default script
			result = defaultResult

			// Log more details about the action
			switch result.Action {
			case sieveengine.ActionFileInto:
				s.InfoLog("default sieve fileinto", "mailbox", result.Mailbox, "copy", result.Copy, "create", result.CreateMailbox)
			case sieveengine.ActionRedirect:
				s.InfoLog("default sieve redirect", "redirect_to", result.RedirectTo, "copy", result.Copy)
			case sieveengine.ActionDiscard:
				s.InfoLog("default sieve discard")
			case sieveengine.ActionVacation:
				s.InfoLog("default sieve vacation response triggered")
			case sieveengine.ActionKeep:
				s.InfoLog("default sieve keep")
			}
		}
	} else {
		s.DebugLog("no default sieve executor available")
		result = sieveengine.Result{Action: sieveengine.ActionKeep}
	}

	// If user has an active script, run it and let it override the resultAction
	if err == nil && activeScript != nil {
		s.InfoLog("using user sieve script", "name", activeScript.Name, "script_id", activeScript.ID, "updated_at", activeScript.UpdatedAt.Format(time.RFC3339))
		// Try to get the user script from cache or create and cache it with metadata validation
		userSieveExecutor, userScriptErr := s.backend.sieveCache.GetOrCreateWithMetadata(
			activeScript.Script,
			activeScript.ID,
			activeScript.UpdatedAt,
			s.AccountID(),
			sieveVacOracle,
		)
		if userScriptErr != nil {
			s.WarnLog("failed to get/create sieve executor", "error", userScriptErr)
			// Keep the result from the default script
		} else {
			userResult, userEvalErr := userSieveExecutor.Evaluate(s.ctx, sieveCtx)
			if userEvalErr != nil {
				metrics.SieveExecutions.WithLabelValues("lmtp", "failure").Inc()
				s.WarnLog("user sieve script evaluation error", "error", userEvalErr)
				// Keep the result from the default script
			} else {
				metrics.SieveExecutions.WithLabelValues("lmtp", "success").Inc()

				// Merge user script result with default script result
				// If user script returns implicit keep (ActionKeep), preserve the default script's action
				// Otherwise, the user script overrides the default
				if userResult.Action == sieveengine.ActionKeep && result.Action != sieveengine.ActionKeep {
					s.InfoLog("user sieve implicit keep - preserving default script action", "default_action", result.Action)
					// Keep the default script result (don't override)
				} else {
					// User script has an explicit action, override the default
					result = userResult

					// Log more details about the action
					switch result.Action {
					case sieveengine.ActionFileInto:
						s.InfoLog("user sieve fileinto", "mailbox", result.Mailbox, "copy", result.Copy, "create", result.CreateMailbox)
					case sieveengine.ActionRedirect:
						s.InfoLog("user sieve redirect", "redirect_to", result.RedirectTo, "copy", result.Copy)
					case sieveengine.ActionDiscard:
						s.InfoLog("user sieve discard")
					case sieveengine.ActionVacation:
						s.InfoLog("user sieve vacation response triggered")
					case sieveengine.ActionKeep:
						s.InfoLog("user sieve explicit keep")
					}
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

	// Apply header edits if any (RFC 5293 - editheader extension)
	if len(result.HeaderEdits) > 0 {
		s.DebugLog("applying header edits", "count", len(result.HeaderEdits))
		modifiedBytes, err := sieveengine.ApplyHeaderEdits(fullMessageBytes, result.HeaderEdits)
		if err != nil {
			s.WarnLog("failed to apply header edits", "error", err)
			// Continue with original message on error
		} else {
			// Update fullMessageBytes with modified version
			fullMessageBytes = modifiedBytes
			// Recalculate content hash with modified message
			contentHash = helpers.HashContent(fullMessageBytes)
			// Re-parse message content for updated headers
			messageContent, err = server.ParseMessage(bytes.NewReader(fullMessageBytes))
			if err != nil {
				s.WarnLog("failed to re-parse message after header edits", "error", err)
				// Continue with what we have
			} else {
				// Update extracted header data
				mailHeader = mail.Header{Header: messageContent.Header}
				subject, _ = mailHeader.Subject()
				messageID, _ = mailHeader.MessageID()
				sentDate, _ = mailHeader.Date()
				inReplyTo, _ = mailHeader.MsgIDList("In-Reply-To")
				if sentDate.IsZero() {
					sentDate = time.Now()
				}
				// Update raw headers text
				headerEndIndex = bytes.Index(fullMessageBytes, []byte("\r\n\r\n"))
				if headerEndIndex != -1 {
					rawHeadersText = string(fullMessageBytes[:headerEndIndex])
				}
				s.DebugLog("message headers updated after edits", "content_hash", contentHash)
			}
		}
	}

	// Store message locally for background upload to S3
	// This happens AFTER Sieve processing and header edits, so we store the modified message
	// Check if file already exists to prevent race condition:
	// If a duplicate arrives while uploader is processing the first copy,
	// we don't want to overwrite/delete the file the uploader is reading.
	expectedPath := s.backend.uploader.FilePath(contentHash, s.AccountID())
	var filePath *string
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		// File doesn't exist, safe to write
		filePath, err = s.backend.uploader.StoreLocally(contentHash, s.AccountID(), fullMessageBytes)
		if err != nil {
			return s.InternalError("failed to save message to disk: %v", err)
		}
		s.DebugLog("message accepted locally", "path", *filePath)
	} else if err == nil {
		// File already exists (likely being processed by uploader or concurrent duplicate delivery)
		// Don't overwrite it, and don't set filePath so we won't try to delete it later
		filePath = nil
		s.DebugLog("message file already exists, skipping write (concurrent delivery)", "path", expectedPath)
	} else {
		// Stat error (permission issue, etc.)
		return s.InternalError("failed to check file existence: %v", err)
	}

	s.InfoLog("executing sieve action", "action", result.Action)

	switch result.Action {
	case sieveengine.ActionDiscard:
		s.InfoLog("sieve message discarded")
		return nil

	case sieveengine.ActionFileInto:
		mailboxName = result.Mailbox
		if result.Copy {
			s.InfoLog("sieve fileinto :copy - saving to both mailbox and inbox", "mailbox", mailboxName)

			// First save to the specified mailbox (with :create if specified)
			err := s.saveMessageToMailbox(mailboxName, fullMessageBytes, contentHash,
				subject, messageID, sentDate, inReplyTo, bodyStructure, plaintextBody, recipients, rawHeadersText, result.CreateMailbox)
			if err != nil {
				// Allow duplicates (message already in target mailbox)
				if !errors.Is(err, consts.ErrMessageExists) && !errors.Is(err, consts.ErrDBUniqueViolation) {
					return s.InternalError("failed to save message to specified mailbox: %v", err)
				}
				s.DebugLog("duplicate message in target mailbox, continuing", "mailbox", mailboxName)
			}

			// Then save to INBOX (for the :copy functionality)
			s.DebugLog("saving copy to inbox due to :copy modifier")

			// Call saveMessageToMailbox again for INBOX (no :create for INBOX - it always exists)
			err = s.saveMessageToMailbox(consts.MailboxInbox, fullMessageBytes, contentHash,
				subject, messageID, sentDate, inReplyTo, bodyStructure, plaintextBody, recipients, rawHeadersText, false)
			if err != nil {
				// Allow duplicates (message already in INBOX)
				if !errors.Is(err, consts.ErrMessageExists) && !errors.Is(err, consts.ErrDBUniqueViolation) {
					return s.InternalError("failed to save message copy to inbox: %v", err)
				}
				s.DebugLog("duplicate message in INBOX, continuing")
			}

			// Success - both copies saved
			s.InfoLog("message delivered according to fileinto :copy directive")
			return nil
		} else {
			s.InfoLog("sieve fileinto - saving to mailbox only", "mailbox", mailboxName)
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
	// For fileinto actions without :copy, pass the :create flag if specified
	createMailbox := result.Action == sieveengine.ActionFileInto && result.CreateMailbox
	err = s.saveMessageToMailbox(mailboxName, fullMessageBytes, contentHash,
		subject, messageID, sentDate, inReplyTo, bodyStructure, plaintextBody, recipients, rawHeadersText, createMailbox)
	if err != nil {
		// Handle duplicate messages (acceptable in LMTP - return success)
		if errors.Is(err, consts.ErrMessageExists) || errors.Is(err, consts.ErrDBUniqueViolation) {
			// For duplicates, NEVER delete the file. This prevents a race condition where:
			// 1. Message A arrives, writes file, INSERT succeeds, creates pending_upload
			// 2. Message B (duplicate) arrives, due to TOCTOU race also writes file
			// 3. Message B's INSERT fails as duplicate
			// 4. If Message B deletes the file, Message A's pending upload loses its source file
			//
			// The file will be cleaned up by the uploader's cleanupOrphanedFiles job
			// (runs every 5 minutes with 10-minute grace period) if it's truly orphaned.
			if filePath != nil {
				s.DebugLog("duplicate message detected, keeping file for potential pending upload", "content_hash", contentHash)
			}
			s.DebugLog("duplicate message accepted (already exists), skipping storage", "message_id", messageID)
			// Don't track as failure - duplicate is success
			metrics.MessageThroughput.WithLabelValues("lmtp", "delivered", "success").Inc()
			// Fall through to success path below (don't return error)
			// This ensures the message is accepted by LMTP even if it's a duplicate
		} else {
			// Cleanup local file on real failure
			if filePath != nil {
				_ = os.Remove(*filePath)
			}
			metrics.MessageThroughput.WithLabelValues("lmtp", "delivered", "failure").Inc()
			return s.InternalError("failed to save message: %v", err)
		}
	} else {
		// Track successful non-duplicate delivery
		metrics.MessageThroughput.WithLabelValues("lmtp", "delivered", "success").Inc()
	}

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

	metrics.ConnectionDuration.WithLabelValues("lmtp", s.backend.name, s.backend.hostname).Observe(time.Since(s.startTime).Seconds())

	// Decrement active connections (not total - total is cumulative)
	activeCount := s.backend.activeConnections.Add(-1)

	// Prometheus metrics - connection closed
	metrics.ConnectionsCurrent.WithLabelValues("lmtp", s.backend.name, s.backend.hostname).Dec()

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
		s.DebugLog("relay not configured, cannot send vacation response", "sender", s.sender.FullAddress())
		return nil
	}

	// RFC 5230 §4.5: Check suppression rules before sending vacation response.
	if reason := shouldSuppressVacation(s.sender, originalMessage); reason != "" {
		s.DebugLog("vacation suppressed", "reason", reason)
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
	h.Set("Content-Type", "text/plain; charset=utf-8")

	w, err := message.CreateWriter(&vacationMessage, h)
	if err != nil {
		s.WarnLog("error creating message writer", "error", err)
		return fmt.Errorf("failed to create message writer: %w", err)
	}

	s.DebugLog("adding vacation message body", "body_length", len(result.VacationMsg))
	_, err = w.Write([]byte(result.VacationMsg))
	if err != nil {
		w.Close()
		s.WarnLog("error writing vacation message body", "error", err)
		return fmt.Errorf("failed to write vacation message body: %w", err)
	}

	w.Close()

	// Send vacation response (relay queue existence checked at start of function)
	sendErr := s.sendToExternalRelay(vacationFrom, s.sender.FullAddress(), vacationMessage.Bytes())
	if sendErr != nil {
		s.WarnLog("error enqueuing vacation response", "error", sendErr)
		// The Sieve engine's policy should have already recorded the response attempt.
		// Failure here is a delivery issue.
		return fmt.Errorf("failed to enqueue vacation response: %w", sendErr)
	}
	s.InfoLog("queued vacation response for relay delivery", "to", s.sender.FullAddress())

	// The recording of the vacation response is now handled by SievePolicy via VacationOracle
	return nil
}

// saveMessageToMailbox saves a message to the specified mailbox
func (s *LMTPSession) saveMessageToMailbox(mailboxName string,
	fullMessageBytes []byte, contentHash string, subject string, messageID string,
	sentDate time.Time, inReplyTo []string, bodyStructure *imap.BodyStructure,
	plaintextBody *string, recipients []helpers.Recipient, rawHeadersText string, createMailbox bool) error {

	// Create a context for read operations that respects session pinning
	readCtx := s.ctx
	if s.useMasterDB {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	// If :create flag is set, use GetOrCreateMailboxByNameWithRetry
	var mailbox *db.DBMailbox
	var err error
	if createMailbox {
		s.DebugLog("creating mailbox if it doesn't exist", "mailbox", mailboxName)
		mailbox, err = s.backend.rdb.GetOrCreateMailboxByNameWithRetry(s.ctx, s.AccountID(), mailboxName)
		if err != nil {
			return fmt.Errorf("failed to get or create mailbox '%s': %v", mailboxName, err)
		}
		s.DebugLog("mailbox ready for delivery", "mailbox", mailboxName, "mailbox_id", mailbox.ID)
	} else {
		// Normal behavior: get mailbox, fallback to INBOX if not found
		mailbox, err = s.backend.rdb.GetMailboxByNameWithRetry(readCtx, s.AccountID(), mailboxName)
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
	}

	size := int64(len(fullMessageBytes))

	// User.Address is always the primary address (set during RCPT TO)
	// No need to query - it's already cached in the session
	_, messageUID, err := s.backend.rdb.InsertMessageWithRetry(s.ctx,
		&db.InsertMessageOptions{
			AccountID:          s.AccountID(),
			MailboxID:          mailbox.ID,
			S3Domain:           s.User.Domain(),
			S3Localpart:        s.User.LocalPart(),
			MailboxName:        mailbox.Name,
			ContentHash:        contentHash,
			MessageID:          messageID,
			InternalDate:       time.Now(),
			Size:               size,
			Subject:            subject,
			PlaintextBody:      *plaintextBody,
			SentDate:           sentDate,
			InReplyTo:          inReplyTo,
			BodyStructure:      bodyStructure,
			Recipients:         recipients,
			Flags:              []imap.Flag{}, // Explicitly set empty flags to mark as unread
			RawHeaders:         rawHeadersText,
			FTSSourceRetention: s.backend.ftsSourceRetention,
		},
		db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  s.backend.hostname,
			Size:        size,
			AccountID:   s.AccountID(),
		})

	if err != nil {
		// Handle duplicate messages (either pre-detected or from unique constraint violation)
		if errors.Is(err, consts.ErrMessageExists) || errors.Is(err, consts.ErrDBUniqueViolation) {
			s.WarnLog("duplicate message detected, skipping delivery", "content_hash", contentHash, "message_id", messageID)
			return fmt.Errorf("message already exists: %w", err)
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
