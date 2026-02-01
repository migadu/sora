// Package delivery provides common message delivery functionality shared between
// LMTP and Admin API delivery paths.
package delivery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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
	"github.com/migadu/sora/server/uploader"
)

// DeliveryContext contains the context for message delivery operations.
type DeliveryContext struct {
	Ctx           context.Context
	RDB           *resilient.ResilientDatabase
	Uploader      *uploader.UploadWorker
	Hostname      string
	ExternalRelay string
	FTSRetention  time.Duration
	MetricsLabel  string // "lmtp" or "http_delivery"
	SieveExecutor SieveExecutor
	Logger        Logger
}

// Logger interface for logging delivery operations.
type Logger interface {
	Log(format string, args ...any)
}

// DeliveryResult contains the result of a delivery attempt.
type DeliveryResult struct {
	Success      bool
	Discarded    bool
	MailboxName  string
	MessageUID   uint32
	ErrorMessage string
}

// RecipientInfo contains information about the recipient.
type RecipientInfo struct {
	AccountID       int64
	Address         *server.Address // Primary address (for S3 keys, metrics, etc.)
	ToAddress       *server.Address // Recipient address as sent (may include +alias)
	FromAddress     *server.Address // Optional sender address
	PreservedUID    *uint32         // Optional: preserved UID for migration
	PreservedUIDVal *uint32         // Optional: preserved UIDVALIDITY for migration
	TargetMailbox   string          // Optional: target mailbox (bypasses Sieve)
}

// DeliverMessage is the main entry point for message delivery.
// It handles the complete delivery flow: parsing, Sieve execution, and storage.
func (d *DeliveryContext) DeliverMessage(recipient RecipientInfo, messageBytes []byte) (*DeliveryResult, error) {
	result := &DeliveryResult{
		Success:     false,
		Discarded:   false,
		MailboxName: consts.MailboxInbox,
	}

	// Parse message
	messageEntity, err := message.Read(bytes.NewReader(messageBytes))
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Invalid RFC822 message: %v", err)
		return result, err
	}

	// Collect metrics
	metrics.MessageSizeBytes.WithLabelValues(d.MetricsLabel).Observe(float64(len(messageBytes)))
	metrics.BytesThroughput.WithLabelValues(d.MetricsLabel, "in").Add(float64(len(messageBytes)))
	metrics.MessageThroughput.WithLabelValues(d.MetricsLabel, "received", "success").Inc()

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

	// Validate body structure to prevent panics during FETCH BODYSTRUCTURE
	if err := helpers.ValidateBodyStructure(bodyStructure); err != nil {
		// Log the validation error but create a safe fallback body structure
		d.Logger.Log("Invalid body structure detected, using fallback: %v", err)
		// Create a minimal valid body structure
		fallback := &imap.BodyStructureSinglePart{
			Type:     "text",
			Subtype:  "plain",
			Size:     uint32(len(messageBytes)),
			Extended: &imap.BodyStructureSinglePartExt{}, // Always populate Extended to match imapserver.ExtractBodyStructure behavior
		}
		var fallbackBS imap.BodyStructure = fallback
		bodyStructure = &fallbackBS
	}

	// Extract recipients
	recipients := helpers.ExtractRecipients(messageEntity.Header)

	// Store message locally for background upload to S3
	// Check if file already exists to prevent race condition:
	// If a duplicate arrives while uploader is processing the first copy,
	// we don't want to overwrite/delete the file the uploader is reading.
	expectedPath := d.Uploader.FilePath(contentHash, recipient.AccountID)
	var filePath *string
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		// File doesn't exist, safe to write
		filePath, err = d.Uploader.StoreLocally(contentHash, recipient.AccountID, messageBytes)
		if err != nil {
			result.ErrorMessage = fmt.Sprintf("Failed to save message to disk: %v", err)
			return result, err
		}
		d.Logger.Log("Message accepted locally, file written: %s", *filePath)
	} else if err == nil {
		// File already exists (likely being processed by uploader or concurrent duplicate delivery)
		// Don't overwrite it, and don't set filePath so we won't try to delete it later
		filePath = nil
		d.Logger.Log("Message file already exists, skipping write (concurrent delivery): %s", expectedPath)
	} else {
		// Stat error (permission issue, etc.)
		result.ErrorMessage = fmt.Sprintf("Failed to check file existence: %v", err)
		return result, fmt.Errorf("failed to check file existence: %w", err)
	}

	// Determine target mailbox
	var mailboxName string
	var discarded bool

	if recipient.TargetMailbox != "" {
		// Use explicit target mailbox (bypasses Sieve - for migrations)
		mailboxName = recipient.TargetMailbox
		discarded = false
	} else {
		// Execute Sieve scripts
		mailboxName, discarded, err = d.SieveExecutor.ExecuteSieve(
			d.Ctx,
			recipient,
			messageEntity,
			plaintextBody,
			messageBytes,
		)
		if err != nil {
			result.ErrorMessage = fmt.Sprintf("Sieve execution error: %v", err)
			return result, err
		}

		if discarded {
			result.Discarded = true
			result.Success = true
			return result, nil
		}
	}

	// Save message to mailbox
	size := int64(len(messageBytes))
	_, messageUID, err := d.RDB.InsertMessageWithRetry(d.Ctx,
		&db.InsertMessageOptions{
			AccountID:            recipient.AccountID,
			MailboxID:            0, // Will be set by InsertMessage based on mailboxName
			S3Domain:             recipient.Address.Domain(),
			S3Localpart:          recipient.Address.LocalPart(),
			MailboxName:          mailboxName,
			ContentHash:          contentHash,
			MessageID:            messageID,
			InternalDate:         time.Now(),
			Size:                 size,
			Subject:              subject,
			PlaintextBody:        *plaintextBody,
			SentDate:             sentDate,
			InReplyTo:            inReplyTo,
			BodyStructure:        bodyStructure,
			Recipients:           recipients,
			Flags:                []imap.Flag{}, // Unread
			RawHeaders:           rawHeadersText,
			FTSRetention:         d.FTSRetention,
			PreservedUID:         recipient.PreservedUID,
			PreservedUIDValidity: recipient.PreservedUIDVal,
		},
		db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  d.Hostname,
			Size:        size,
			AccountID:   recipient.AccountID,
		})

	if err != nil {
		// Handle duplicate messages (either pre-detected or from unique constraint violation)
		if errors.Is(err, consts.ErrMessageExists) || errors.Is(err, consts.ErrDBUniqueViolation) {
			// For duplicates, NEVER delete the file. This prevents a race condition where:
			// 1. Message A arrives, writes file, INSERT succeeds, creates pending_upload
			// 2. Message B (duplicate) arrives, due to TOCTOU race also writes file
			// 3. Message B's INSERT fails as duplicate
			// 4. If Message B deletes the file, Message A's pending upload loses its source file
			//
			// The file will be cleaned up by the uploader's cleanupOrphanedFiles job
			// (runs every 5 minutes with 10-minute grace period) if it's truly orphaned.
			// This is safer than trying to determine if a pending upload exists, because:
			// - The pending upload might be for a different account with the same content hash
			// - The pending upload check itself could race with upload completion
			if filePath != nil {
				d.Logger.Log("Duplicate message detected, keeping file for potential pending upload: %s", contentHash)
			}
			result.ErrorMessage = "Message already exists"
			// Don't notify uploader for duplicates
			return result, err
		}
		// For non-duplicate errors, always clean up the file
		if filePath != nil {
			_ = d.Uploader.RemoveLocalFile(*filePath)
		}
		result.ErrorMessage = fmt.Sprintf("Failed to save message: %v", err)
		return result, err
	}

	// Notify uploader
	d.Uploader.NotifyUploadQueued()

	// Track metrics
	metrics.MessageThroughput.WithLabelValues(d.MetricsLabel, "delivered", "success").Inc()
	metrics.TrackDomainMessage(d.MetricsLabel, recipient.Address.Domain(), "delivered")
	metrics.TrackDomainBytes(d.MetricsLabel, recipient.Address.Domain(), "in", size)
	metrics.TrackUserActivity(d.MetricsLabel, recipient.Address.FullAddress(), "command", 1)

	result.Success = true
	result.MailboxName = mailboxName
	result.MessageUID = uint32(messageUID)
	return result, nil
}

// LookupRecipient looks up a recipient's user ID by email address.
func (d *DeliveryContext) LookupRecipient(ctx context.Context, recipient string) (*RecipientInfo, error) {
	// Parse recipient address
	toAddress, err := server.NewAddress(recipient)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient address: %w", err)
	}

	lookupAddress := toAddress.BaseAddress()

	// Lookup user account and get primary address in one query
	// This finds the account by alias/recipient address, but returns the primary address
	var AccountID int64
	var primaryEmail string
	err = d.RDB.QueryRowWithRetry(ctx, `
		SELECT c.account_id, primary_cred.address
		FROM credentials c
		JOIN accounts a ON c.account_id = a.id
		JOIN credentials primary_cred ON primary_cred.account_id = c.account_id AND primary_cred.primary_identity = TRUE
		WHERE LOWER(c.address) = $1 AND a.deleted_at IS NULL
	`, lookupAddress).Scan(&AccountID, &primaryEmail)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("recipient not found: %s", recipient)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Parse primary email address
	primaryAddr, err := server.NewAddress(primaryEmail)
	if err != nil {
		return nil, fmt.Errorf("invalid primary email format in database: %w", err)
	}

	// Create default mailboxes if needed
	err = d.RDB.CreateDefaultMailboxesWithRetry(ctx, AccountID)
	if err != nil {
		return nil, fmt.Errorf("failed to create default mailboxes: %w", err)
	}

	return &RecipientInfo{
		AccountID: AccountID,
		Address:   &primaryAddr, // Primary address (for S3 keys, metrics, etc.)
		ToAddress: &toAddress,   // Recipient address as sent (may include +alias)
	}, nil
}

// SaveMessageToMailbox saves a message to a specific mailbox (helper for Sieve :copy).
func (d *DeliveryContext) SaveMessageToMailbox(ctx context.Context, recipient RecipientInfo, mailboxName string, messageBytes []byte, messageEntity *message.Entity, plaintextBody *string) error {
	mailbox, err := d.RDB.GetMailboxByNameWithRetry(ctx, recipient.AccountID, mailboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			// Fallback to INBOX
			mailbox, err = d.RDB.GetMailboxByNameWithRetry(ctx, recipient.AccountID, consts.MailboxInbox)
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

	_, _, err = d.RDB.InsertMessageWithRetry(ctx,
		&db.InsertMessageOptions{
			AccountID:     recipient.AccountID,
			MailboxID:     mailbox.ID,
			S3Domain:      recipient.Address.Domain(),
			S3Localpart:   recipient.Address.LocalPart(),
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
			FTSRetention:  d.FTSRetention,
		},
		db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  d.Hostname,
			Size:        size,
			AccountID:   recipient.AccountID,
		})

	return err
}

// ParseMessageReader reads and parses a message from an io.Reader.
func ParseMessageReader(r io.Reader) ([]byte, *message.Entity, error) {
	var buf bytes.Buffer
	_, err := io.Copy(&buf, r)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read message: %w", err)
	}

	messageBytes := buf.Bytes()
	messageEntity, err := message.Read(bytes.NewReader(messageBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse message: %w", err)
	}

	return messageBytes, messageEntity, nil
}
