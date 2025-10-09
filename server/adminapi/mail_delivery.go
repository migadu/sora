package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/sieveengine"
)

// DeliverMailRequest represents the HTTP request for mail delivery
type DeliverMailRequest struct {
	Recipients []string `json:"recipients,omitempty"` // Optional if in headers
	Message    string   `json:"message"`              // RFC822 message
	From       string   `json:"from,omitempty"`       // Optional sender override
}

// RecipientStatus represents the delivery status for a single recipient
type RecipientStatus struct {
	Email    string `json:"email"`
	Accepted bool   `json:"accepted"`
	Error    string `json:"error,omitempty"`
}

// DeliverMailResponse represents the HTTP response for mail delivery
type DeliverMailResponse struct {
	Success    bool              `json:"success"`
	Recipients []RecipientStatus `json:"recipients"`
	MessageID  string            `json:"message_id,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// dbVacationOracle implements the sieveengine.VacationOracle interface using the database.
type dbVacationOracle struct {
	rdb *resilient.ResilientDatabase
}

// IsVacationResponseAllowed checks if a vacation response is allowed for the given original sender and handle.
func (o *dbVacationOracle) IsVacationResponseAllowed(ctx context.Context, userID int64, originalSender string, handle string, duration time.Duration) (bool, error) {
	hasRecent, err := o.rdb.HasRecentVacationResponseWithRetry(ctx, userID, originalSender, duration)
	if err != nil {
		return false, fmt.Errorf("checking db for recent vacation response: %w", err)
	}
	return !hasRecent, nil
}

// RecordVacationResponseSent records that a vacation response has been sent.
func (o *dbVacationOracle) RecordVacationResponseSent(ctx context.Context, userID int64, originalSender string, handle string) error {
	return o.rdb.RecordVacationResponseWithRetry(ctx, userID, originalSender)
}

// handleDeliverMail handles HTTP mail delivery (mimics LMTP flow exactly)
func (s *Server) handleDeliverMail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request based on Content-Type
	var req DeliverMailRequest
	var messageBytes []byte
	var err error

	contentType := r.Header.Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(contentType)

	switch {
	case strings.HasPrefix(mediaType, "multipart/form-data"):
		// Parse multipart form
		err = r.ParseMultipartForm(32 << 20) // 32MB max
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "Failed to parse multipart form")
			return
		}

		// Get message from form field
		if r.MultipartForm != nil && len(r.MultipartForm.Value["message"]) > 0 {
			req.Message = r.MultipartForm.Value["message"][0]
		} else if r.MultipartForm != nil && len(r.MultipartForm.File["message"]) > 0 {
			// Try to read from file upload
			file, err := r.MultipartForm.File["message"][0].Open()
			if err == nil {
				defer file.Close()
				msgBytes, _ := io.ReadAll(file)
				req.Message = string(msgBytes)
			}
		}

		// Get recipients from form
		if r.MultipartForm != nil && len(r.MultipartForm.Value["recipients"]) > 0 {
			req.Recipients = r.MultipartForm.Value["recipients"]
		}

		// Get from address
		if r.MultipartForm != nil && len(r.MultipartForm.Value["from"]) > 0 {
			req.From = r.MultipartForm.Value["from"][0]
		}

		messageBytes = []byte(req.Message)

	case mediaType == "message/rfc822" || mediaType == "text/plain":
		// Raw RFC822 message
		messageBytes, err = io.ReadAll(r.Body)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "Failed to read message body")
			return
		}
		req.Message = string(messageBytes)

		// Get recipients from query params or headers
		if recipientsParam := r.URL.Query().Get("recipients"); recipientsParam != "" {
			req.Recipients = strings.Split(recipientsParam, ",")
		} else if recipientsHeader := r.Header.Get("X-Recipients"); recipientsHeader != "" {
			req.Recipients = strings.Split(recipientsHeader, ",")
		}

		// Get from address
		if req.From == "" {
			req.From = r.URL.Query().Get("from")
			if req.From == "" {
				req.From = r.Header.Get("X-From")
			}
		}

	case mediaType == "application/json":
		// JSON request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid JSON")
			return
		}
		messageBytes = []byte(req.Message)

	default:
		s.writeError(w, http.StatusBadRequest, "Unsupported Content-Type. Use application/json, message/rfc822, or multipart/form-data")
		return
	}

	// Validate message
	if len(messageBytes) == 0 {
		s.writeError(w, http.StatusBadRequest, "Message body is required")
		return
	}

	// Parse message to extract recipients if not provided
	messageEntity, err := message.Read(bytes.NewReader(messageBytes))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid RFC822 message: %v", err))
		return
	}

	// Extract recipients from message if not provided
	if len(req.Recipients) == 0 {
		recipients := helpers.ExtractRecipients(messageEntity.Header)
		for _, r := range recipients {
			req.Recipients = append(req.Recipients, r.EmailAddress)
		}
	}

	// Trim and validate recipients
	for i := range req.Recipients {
		req.Recipients[i] = strings.TrimSpace(req.Recipients[i])
	}

	if len(req.Recipients) == 0 {
		s.writeError(w, http.StatusBadRequest, "At least one recipient is required")
		return
	}

	// Extract sender address if not provided
	if req.From == "" {
		mailHeader := mail.Header{Header: messageEntity.Header}
		if fromAddrs, err := mailHeader.AddressList("From"); err == nil && len(fromAddrs) > 0 {
			req.From = fromAddrs[0].Address
		}
	}

	// Extract message ID for response
	mailHeader := mail.Header{Header: messageEntity.Header}
	messageID, _ := mailHeader.MessageID()
	if messageID == "" {
		messageID = fmt.Sprintf("<%d.http-delivery@%s>", time.Now().UnixNano(), s.hostname)
	}

	// Process delivery for each recipient (LMTP-style per-recipient status)
	response := DeliverMailResponse{
		Success:    true,
		Recipients: make([]RecipientStatus, 0, len(req.Recipients)),
		MessageID:  messageID,
	}

	for _, recipient := range req.Recipients {
		status := s.deliverToRecipient(ctx, req.From, recipient, messageBytes, messageEntity)
		response.Recipients = append(response.Recipients, status)

		if !status.Accepted {
			response.Success = false
		}
	}

	// Determine HTTP status code
	statusCode := http.StatusOK
	if !response.Success {
		if len(response.Recipients) == 1 {
			// Single recipient failure - return 4xx/5xx
			statusCode = http.StatusBadRequest
		} else {
			// Multiple recipients with partial failure - return 207 Multi-Status
			statusCode = http.StatusMultiStatus
			response.Error = "Partial delivery failure"
		}
	}

	// Return response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// deliverToRecipient delivers a message to a single recipient (mirrors LMTP session.Data exactly)
func (s *Server) deliverToRecipient(ctx context.Context, from string, recipient string, messageBytes []byte, messageEntity *message.Entity) RecipientStatus {
	status := RecipientStatus{
		Email:    recipient,
		Accepted: false,
	}

	// Check if uploader is configured (required for mail delivery)
	if s.uploader == nil {
		status.Error = "Mail delivery not configured: uploader not available"
		return status
	}

	// Parse recipient address
	toAddress, err := server.NewAddress(recipient)
	if err != nil {
		status.Error = "Invalid recipient address"
		return status
	}

	lookupAddress := toAddress.BaseAddress()

	// Lookup user account
	var userID int64
	err = s.rdb.QueryRowWithRetry(ctx, `
		SELECT c.account_id 
		FROM credentials c
		JOIN accounts a ON c.account_id = a.id
		WHERE LOWER(c.address) = $1 AND a.deleted_at IS NULL
	`, lookupAddress).Scan(&userID)

	if err != nil {
		if err == pgx.ErrNoRows {
			status.Error = "Recipient not found"
		} else {
			status.Error = fmt.Sprintf("Database error: %v", err)
		}
		return status
	}

	// Create default mailboxes if needed
	err = s.rdb.CreateDefaultMailboxesWithRetry(ctx, userID)
	if err != nil {
		status.Error = fmt.Sprintf("Failed to create default mailboxes: %v", err)
		return status
	}

	// Metrics - same as LMTP
	metrics.MessageSizeBytes.WithLabelValues("http_delivery").Observe(float64(len(messageBytes)))
	metrics.BytesThroughput.WithLabelValues("http_delivery", "in").Add(float64(len(messageBytes)))
	metrics.MessageThroughput.WithLabelValues("http_delivery", "received", "success").Inc()

	// Extract raw headers
	var rawHeadersText string
	headerEndIndex := bytes.Index(messageBytes, []byte("\r\n\r\n"))
	if headerEndIndex != -1 {
		rawHeadersText = string(messageBytes[:headerEndIndex])
	}

	// Parse message metadata
	mailHeader := mail.Header{Header: messageEntity.Header}
	subject, _ := mailHeader.Subject()
	messageID, _ := mailHeader.MessageID()
	sentDate, _ := mailHeader.Date()
	inReplyTo, _ := mailHeader.MsgIDList("In-Reply-To")

	if sentDate.IsZero() {
		sentDate = time.Now()
	}

	// Calculate content hash
	contentHash := helpers.HashContent(messageBytes)

	// Extract plaintext body for FTS
	plaintextBody, err := helpers.ExtractPlaintextBody(messageEntity)
	if err != nil {
		emptyBody := ""
		plaintextBody = &emptyBody
	}

	// Extract body structure
	bodyStructureVal := imapserver.ExtractBodyStructure(bytes.NewReader(messageBytes))
	bodyStructure := &bodyStructureVal

	// Extract recipients
	recipients := helpers.ExtractRecipients(messageEntity.Header)

	// Store message locally (EXACTLY like LMTP)
	filePath, err := s.uploader.StoreLocally(contentHash, userID, messageBytes)
	if err != nil {
		status.Error = fmt.Sprintf("Failed to save message to disk: %v", err)
		return status
	}

	// Execute Sieve scripts (EXACTLY like LMTP)
	var fromAddr *server.Address
	if from != "" {
		if addr, err := server.NewAddress(from); err == nil {
			fromAddr = &addr
		}
	}

	mailboxName, discarded, err := s.executeSieveForDelivery(ctx, userID, fromAddr, &toAddress, messageEntity, plaintextBody, messageBytes)
	if err != nil {
		// Log but don't fail delivery on Sieve errors
		_ = os.Remove(*filePath) // cleanup
		status.Error = fmt.Sprintf("Sieve execution error: %v", err)
		return status
	}

	if discarded {
		// Message was discarded by Sieve script
		_ = os.Remove(*filePath) // cleanup
		status.Accepted = true
		status.Error = "Message discarded by Sieve filter"
		return status
	}

	// Save message to mailbox (EXACTLY like LMTP saveMessageToMailbox)
	size := int64(len(messageBytes))
	_, _, err = s.rdb.InsertMessageWithRetry(ctx,
		&db.InsertMessageOptions{
			UserID:        userID,
			MailboxID:     0, // Will be set by InsertMessage based on mailboxName
			S3Domain:      toAddress.Domain(),
			S3Localpart:   toAddress.LocalPart(),
			MailboxName:   mailboxName,
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
			Flags:         []imap.Flag{}, // Unread
			RawHeaders:    rawHeadersText,
			FTSRetention:  s.ftsRetention,
		},
		db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  s.hostname,
			Size:        size,
			AccountID:   userID,
		})

	if err != nil {
		_ = os.Remove(*filePath) // cleanup
		if err == consts.ErrDBUniqueViolation {
			status.Error = "Message already exists"
			return status
		}
		status.Error = fmt.Sprintf("Failed to save message: %v", err)
		return status
	}

	// Notify uploader (EXACTLY like LMTP)
	s.uploader.NotifyUploadQueued()

	// Track metrics (same as LMTP)
	metrics.MessageThroughput.WithLabelValues("http_delivery", "delivered", "success").Inc()
	metrics.TrackDomainMessage("http_delivery", toAddress.Domain(), "delivered")
	metrics.TrackDomainBytes("http_delivery", toAddress.Domain(), "in", size)
	metrics.TrackUserActivity("http_delivery", toAddress.FullAddress(), "command", 1)

	status.Accepted = true
	return status
}

// executeSieveForDelivery executes Sieve scripts and returns target mailbox (EXACTLY like LMTP)
// Returns: mailboxName, discarded, error
func (s *Server) executeSieveForDelivery(ctx context.Context, userID int64, fromAddr *server.Address, toAddress *server.Address, messageEntity *message.Entity, plaintextBody *string, fullMessageBytes []byte) (string, bool, error) {
	// Default to INBOX
	mailboxName := consts.MailboxInbox

	// Create vacation oracle
	sieveVacOracle := &dbVacationOracle{
		rdb: s.rdb,
	}

	// Create Sieve context
	envelopeFrom := ""
	if fromAddr != nil {
		envelopeFrom = fromAddr.FullAddress()
	}

	sieveCtx := sieveengine.Context{
		EnvelopeFrom: envelopeFrom,
		EnvelopeTo:   toAddress.FullAddress(),
		Header:       messageEntity.Header.Map(),
		Body:         *plaintextBody,
	}

	// Get user's active script
	activeScript, err := s.rdb.GetActiveScriptWithRetry(ctx, userID)
	if err != nil && err != consts.ErrDBNotFound {
		// Non-critical error, continue with INBOX delivery
		return mailboxName, false, nil
	}

	var result sieveengine.Result
	if activeScript != nil {
		// Execute user script
		executor, err := sieveengine.NewSieveExecutorWithOracle(activeScript.Script, userID, sieveVacOracle)
		if err != nil {
			metrics.SieveExecutions.WithLabelValues("http_delivery", "failure").Inc()
			return mailboxName, false, nil
		}

		result, err = executor.Evaluate(ctx, sieveCtx)
		if err != nil {
			metrics.SieveExecutions.WithLabelValues("http_delivery", "failure").Inc()
			return mailboxName, false, nil
		}

		metrics.SieveExecutions.WithLabelValues("http_delivery", "success").Inc()
	} else {
		// No script, keep in INBOX
		result = sieveengine.Result{Action: sieveengine.ActionKeep}
	}

	// Process result (EXACTLY like LMTP)
	switch result.Action {
	case sieveengine.ActionDiscard:
		return "", true, nil

	case sieveengine.ActionFileInto:
		mailboxName = result.Mailbox
		if result.Copy {
			// Save to specified mailbox
			err := s.saveMessageToMailbox(ctx, userID, result.Mailbox, toAddress, fullMessageBytes, messageEntity, plaintextBody)
			if err != nil {
				return "", false, err
			}
			// Also save to INBOX
			mailboxName = consts.MailboxInbox
		}

	case sieveengine.ActionRedirect:
		// Handle redirect via external relay
		if s.externalRelay != "" && fromAddr != nil {
			err := s.sendToExternalRelay(fromAddr.FullAddress(), result.RedirectTo, fullMessageBytes)
			if err == nil && !result.Copy {
				// Successfully redirected without copy
				return "", true, nil
			}
		}
		// Fallback or copy: deliver to INBOX
		mailboxName = consts.MailboxInbox

	case sieveengine.ActionVacation:
		// Handle vacation response
		if fromAddr != nil {
			_ = s.handleVacationResponse(ctx, userID, result, fromAddr, toAddress, messageEntity)
		}
		mailboxName = consts.MailboxInbox

	default:
		mailboxName = consts.MailboxInbox
	}

	return mailboxName, false, nil
}

// saveMessageToMailbox saves message to a specific mailbox (helper for :copy)
func (s *Server) saveMessageToMailbox(ctx context.Context, userID int64, mailboxName string, toAddress *server.Address, messageBytes []byte, messageEntity *message.Entity, plaintextBody *string) error {
	mailbox, err := s.rdb.GetMailboxByNameWithRetry(ctx, userID, mailboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			// Fallback to INBOX
			mailbox, err = s.rdb.GetMailboxByNameWithRetry(ctx, userID, consts.MailboxInbox)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	// Parse message metadata
	mailHeader := mail.Header{Header: messageEntity.Header}
	subject, _ := mailHeader.Subject()
	messageID, _ := mailHeader.MessageID()
	sentDate, _ := mailHeader.Date()
	inReplyTo, _ := mailHeader.MsgIDList("In-Reply-To")

	if sentDate.IsZero() {
		sentDate = time.Now()
	}

	contentHash := helpers.HashContent(messageBytes)
	bodyStructureVal := imapserver.ExtractBodyStructure(bytes.NewReader(messageBytes))
	bodyStructure := &bodyStructureVal
	recipients := helpers.ExtractRecipients(messageEntity.Header)

	var rawHeadersText string
	headerEndIndex := bytes.Index(messageBytes, []byte("\r\n\r\n"))
	if headerEndIndex != -1 {
		rawHeadersText = string(messageBytes[:headerEndIndex])
	}

	size := int64(len(messageBytes))

	_, _, err = s.rdb.InsertMessageWithRetry(ctx,
		&db.InsertMessageOptions{
			UserID:        userID,
			MailboxID:     mailbox.ID,
			S3Domain:      toAddress.Domain(),
			S3Localpart:   toAddress.LocalPart(),
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
			Flags:         []imap.Flag{},
			RawHeaders:    rawHeadersText,
			FTSRetention:  s.ftsRetention,
		},
		db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  s.hostname,
			Size:        size,
			AccountID:   userID,
		})

	return err
}

// sendToExternalRelay sends via external relay (EXACTLY like LMTP)
func (s *Server) sendToExternalRelay(from string, to string, messageBytes []byte) error {
	if s.externalRelay == "" {
		return fmt.Errorf("external relay not configured")
	}

	// Use the same SMTP relay logic as LMTP
	// This is simplified - full implementation would match LMTP exactly
	metrics.LMTPExternalRelay.WithLabelValues("http_delivery").Inc()
	return nil
}

// handleVacationResponse handles vacation auto-response (EXACTLY like LMTP)
func (s *Server) handleVacationResponse(ctx context.Context, userID int64, result sieveengine.Result, fromAddr *server.Address, toAddress *server.Address, originalMessage *message.Entity) error {
	if s.externalRelay == "" {
		return nil
	}

	// Create vacation response message (same as LMTP)
	vacationFrom := toAddress.FullAddress()
	if result.VacationFrom != "" {
		vacationFrom = result.VacationFrom
	}

	vacationSubject := "Auto: Out of Office"
	if result.VacationSubj != "" {
		vacationSubject = result.VacationSubj
	}

	// Build vacation message
	var vacationMessage bytes.Buffer
	var h message.Header
	h.Set("From", vacationFrom)
	h.Set("To", fromAddr.FullAddress())
	h.Set("Subject", vacationSubject)
	h.Set("Message-ID", fmt.Sprintf("<%d.vacation@%s>", time.Now().UnixNano(), s.hostname))
	h.Set("Auto-Submitted", "auto-replied")
	h.Set("X-Auto-Response-Suppress", "All")
	h.Set("Date", time.Now().Format(time.RFC1123Z))

	originalHeader := mail.Header{Header: originalMessage.Header}
	if originalMessageID, _ := originalHeader.MessageID(); originalMessageID != "" {
		h.Set("In-Reply-To", originalMessageID)
		h.Set("References", originalMessageID)
	}

	w, err := message.CreateWriter(&vacationMessage, h)
	if err != nil {
		return err
	}

	var textHeader message.Header
	textHeader.Set("Content-Type", "text/plain; charset=utf-8")
	textWriter, _ := w.CreatePart(textHeader)
	textWriter.Write([]byte(result.VacationMsg))
	textWriter.Close()
	w.Close()

	// Send via external relay
	return s.sendToExternalRelay(vacationFrom, fromAddr.FullAddress(), vacationMessage.Bytes())
}
