package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
)

// DeliverMailRequest represents the HTTP request for mail delivery
type DeliverMailRequest struct {
	Recipients  []string `json:"recipients,omitempty"`   // Optional if in headers
	Message     string   `json:"message"`                // RFC822 message
	From        string   `json:"from,omitempty"`         // Optional sender override
	UID         *uint32  `json:"uid,omitempty"`          // Optional: preserved UID for migration
	UIDValidity *uint32  `json:"uid_validity,omitempty"` // Optional: preserved UIDVALIDITY for migration
	MailboxName string   `json:"mailbox,omitempty"`      // Optional: target mailbox (bypasses Sieve)
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

// adminAPILogger implements the delivery.Logger interface for Admin API
type adminAPILogger struct {
	prefix string // e.g., "HTTP-DELIVERY [recipient@example.com]"
}

func (l *adminAPILogger) Log(format string, args ...any) {
	// Log with prefix to identify HTTP delivery path
	logger.Debug("Mail delivery", "msg", fmt.Sprintf(format, args...))
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
		status := s.deliverToRecipient(ctx, &req, recipient, messageBytes, messageEntity)
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

// deliverToRecipient delivers a message to a single recipient using the delivery package
func (s *Server) deliverToRecipient(ctx context.Context, req *DeliverMailRequest, recipient string, messageBytes []byte, _ *message.Entity) RecipientStatus {
	status := RecipientStatus{
		Email:    recipient,
		Accepted: false,
	}

	// Check if uploader is configured (required for mail delivery)
	if s.uploader == nil {
		status.Error = "Mail delivery not configured: uploader not available"
		return status
	}

	// Create logger with recipient prefix
	logger := &adminAPILogger{
		prefix: fmt.Sprintf("HTTP-DELIVERY to=%s", recipient),
	}

	// Create delivery context with relay queue
	vacationOracle := &delivery.VacationOracle{RDB: s.rdb}
	vacationHandler := &delivery.StandardVacationHandler{
		Hostname:   s.hostname,
		RelayQueue: s.relayQueue,
		Logger:     logger,
	}

	deliveryCtx := &delivery.DeliveryContext{
		Ctx:          ctx,
		RDB:          s.rdb,
		Uploader:     s.uploader,
		Hostname:     s.hostname,
		FTSRetention: s.ftsRetention,
		MetricsLabel: "http_delivery",
		Logger:       logger,
	}

	sieveExecutor := &delivery.StandardSieveExecutor{
		DeliveryCtx:     deliveryCtx,
		VacationOracle:  vacationOracle,
		VacationHandler: vacationHandler,
		RelayQueue:      s.relayQueue,
	}

	deliveryCtx.SieveExecutor = sieveExecutor

	logger.Log("starting delivery from=%s size=%d uid=%v", req.From, len(messageBytes), req.UID)

	// Lookup recipient
	recipientInfo, err := deliveryCtx.LookupRecipient(ctx, recipient)
	if err != nil {
		logger.Log("recipient lookup failed: %v", err)
		status.Error = err.Error()
		return status
	}

	logger.Log("recipient found AccountID=%d", recipientInfo.AccountID)

	// Set from address if provided
	if req.From != "" {
		if addr, parseErr := server.NewAddress(req.From); parseErr == nil {
			recipientInfo.FromAddress = &addr
		}
	}

	// Set preserved UID fields for migration
	recipientInfo.PreservedUID = req.UID
	recipientInfo.PreservedUIDVal = req.UIDValidity
	recipientInfo.TargetMailbox = req.MailboxName

	// Deliver message
	result, err := deliveryCtx.DeliverMessage(*recipientInfo, messageBytes)
	if err != nil {
		logger.Log("delivery failed: %v", err)
		status.Error = result.ErrorMessage
		return status
	}

	if result.Discarded {
		logger.Log("message discarded by Sieve filter")
		status.Accepted = true
		status.Error = "Message discarded by Sieve filter"
		return status
	}

	if result.Success {
		logger.Log("message delivered successfully to mailbox=%s uid=%d", result.MailboxName, result.MessageUID)
	}

	status.Accepted = result.Success
	return status
}
