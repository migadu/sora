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
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/uploader"
)

// DeliveryContext contains the context for message delivery operations.
type DeliveryContext struct {
	Ctx      context.Context
	RDB      *resilient.ResilientDatabase
	Uploader *uploader.UploadWorker
	// Hostname is this node's SMTP-visible name. It is published: the "by" clause of the
	// Received header this delivery stamps, and the domain of vacation Message-IDs.
	Hostname string
	// InstanceID is the upload-lease key written to pending_uploads.instance_id. It is
	// internal and must match what the upload worker heartbeats, or the cleaner reaps this
	// delivery's body before it reaches S3. Empty falls back to Hostname, which is what
	// callers that never split the two identities effectively used.
	InstanceID    string
	ExternalRelay string
	FTSRetention  time.Duration
	MetricsLabel  string // "lmtp" or "http_delivery"
	SieveExecutor SieveExecutor
	Logger        Logger
	OwnerResolver *resilient.OwnerResolver
}

// uploadInstanceID is the identity this delivery stamps on the pending_uploads row it
// creates. It falls back to Hostname so that a caller which has only ever had one name
// keeps the behaviour it had before the two were separated - the failure mode of getting
// this wrong is the cleaner deleting a message body that never reached S3, so the fallback
// is a value that is at least self-consistent for a single-node deployment.
func (d *DeliveryContext) uploadInstanceID() string {
	if d.InstanceID != "" {
		return d.InstanceID
	}
	return d.Hostname
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
	// DeliveryHash identifies the upstream submission (see db.InsertMessageOptions).
	// Set by DeliverMessage from the bytes as received; callers leave it empty.
	DeliveryHash string
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

	// Mail-loop detection + Delivered-To stamping (Postfix-style; see the LMTP path).
	// Skipped for the migration/Sieve-bypass path (TargetMailbox set): those imports
	// must preserve the original bytes/UIDs and commonly already carry a Delivered-To.
	// Reject a message in a Sora redirect loop (X-Sora-Loop marker + matching
	// Delivered-To), otherwise stamp the recipient address and re-parse.
	if recipient.Address != nil && recipient.TargetMailbox == "" {
		deliveredTo := recipient.Address.BaseAddress()
		if helpers.IsRedirectLoop(helpers.HeaderGetter(messageEntity.Header.Map()), deliveredTo) {
			result.ErrorMessage = "routing loop detected (Delivered-To)"
			return result, fmt.Errorf("mail loop detected for %s", deliveredTo)
		}
		// Identity of the upstream submission, used to absorb a retry of a delivery whose
		// acknowledgement was lost. MUST be taken over the bytes exactly as received: the
		// trace stamped below carries a per-attempt id and timestamp, so anything hashed
		// after it (content_hash included) differs on every attempt.
		recipient.DeliveryHash = helpers.HashContent(messageBytes)

		// Add our Received: trace for this delivery hop, then Delivered-To on top.
		received := helpers.BuildReceivedHeader("", d.Hostname, "HTTP", deliveredTo, idgen.New(), time.Now().Format(time.RFC1123Z))
		messageBytes = helpers.PrependRawHeader(messageBytes, received)
		messageBytes = helpers.PrependHeaderLine(messageBytes, helpers.DeliveredToHeader, deliveredTo)
		if messageEntity, err = message.Read(bytes.NewReader(messageBytes)); err != nil {
			result.ErrorMessage = fmt.Sprintf("Invalid RFC822 message after Delivered-To/Received: %v", err)
			return result, err
		}
	}

	// Extract plaintext body for FTS (also the body the Sieve evaluation sees)
	plaintextBody, err := helpers.ExtractPlaintextBody(messageEntity)
	if err != nil {
		emptyBody := ""
		plaintextBody = &emptyBody
	}

	// Safety guard: Reject if global staging limit is exceeded. Checked before Sieve runs,
	// so a rejected delivery cannot have redirected or auto-replied first.
	if d.Uploader.IsStagingLimitExceeded(int64(len(messageBytes))) {
		d.Logger.Log("Rejecting delivery due to upload staging size limit exceeded")
		result.ErrorMessage = "Insufficient system storage (staging limit reached)"
		return result, fmt.Errorf("staging limit exceeded")
	}

	// Determine target mailbox. Sieve runs BEFORE the message is hashed and stored, as it
	// does in the LMTP path: an editheader script rewrites the headers, and content_hash
	// (the S3 object key, cache key and upload-dedup key) must describe the bytes that are
	// actually stored.
	var mailboxName string
	var copyMailbox string     // Sieve `fileinto :copy` target, saved once the body is staged
	var sieveFlags []imap.Flag // flags set by the Sieve script (imap4flags, RFC 5232)

	if recipient.TargetMailbox != "" {
		// Use explicit target mailbox (bypasses Sieve - for migrations)
		mailboxName = recipient.TargetMailbox
	} else {
		// Execute Sieve scripts
		outcome, err := d.SieveExecutor.ExecuteSieve(
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

		if outcome.Discarded {
			result.Discarded = true
			result.Success = true
			return result, nil
		}

		mailboxName = outcome.MailboxName
		copyMailbox = outcome.CopyMailbox
		sieveFlags = outcome.Flags
		// Adopt any header edits the script made (RFC 5293) before anything is derived
		// from the message.
		messageBytes = outcome.MessageBytes
		messageEntity = outcome.MessageEntity
	}

	// Parse message metadata
	mailHeader := mail.Header{Header: messageEntity.Header}
	subject, _ := mailHeader.Subject()
	messageID, _ := mailHeader.MessageID()
	sentDate, _ := mailHeader.Date()
	inReplyTo, _ := mailHeader.MsgIDList("In-Reply-To")
	references, _ := mailHeader.MsgIDList("References")

	if sentDate.IsZero() {
		sentDate = time.Now()
	}

	// Calculate content hash
	contentHash := helpers.HashContent(messageBytes)

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
	// This happens AFTER Sieve processing and header edits, so we store the modified message
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

	// Sieve `fileinto :copy`: save the second copy now that the body is on disk, so its
	// pending_uploads row can never name a file that is not staged yet - the uploader
	// treats a missing local file as permanently lost content.
	if copyMailbox != "" {
		err := d.SaveMessageToMailbox(d.Ctx, recipient, copyMailbox, messageBytes, messageEntity, plaintextBody, sieveFlags)
		// A duplicate copy is an accepted delivery, as it is in LMTP: the copy is
		// already in the mailbox, so a resubmission must not fail the delivery.
		if err != nil && !errors.Is(err, consts.ErrMessageExists) && !errors.Is(err, consts.ErrDBUniqueViolation) {
			result.ErrorMessage = fmt.Sprintf("Failed to save Sieve :copy to %s: %v", copyMailbox, err)
			return result, err
		}
	}

	// Resolve the destination mailbox (supporting shared mailboxes owned by another
	// account), enforce the 'i' right, attribute the message to the mailbox owner, and
	// stage the already-saved body under the owner's path. The body was stored locally
	// under recipient.AccountID above.
	mailbox, destAccountID, destS3Domain, destS3Localpart, err := d.resolveOwnedTarget(d.Ctx, recipient, mailboxName, contentHash)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to resolve destination mailbox: %v", err)
		return result, err
	}

	// Save message to mailbox
	size := int64(len(messageBytes))
	_, messageUID, err := d.RDB.InsertMessageWithRetry(d.Ctx,
		&db.InsertMessageOptions{
			AccountID:            destAccountID,
			MailboxID:            mailbox.ID,
			S3Domain:             destS3Domain,
			S3Localpart:          destS3Localpart,
			MailboxName:          mailbox.Name,
			ContentHash:          contentHash,
			DeliveryHash:         recipient.DeliveryHash,
			MessageID:            messageID,
			InternalDate:         time.Now(),
			Size:                 size,
			Subject:              subject,
			PlaintextBody:        *plaintextBody,
			SentDate:             sentDate,
			InReplyTo:            inReplyTo,
			References:           references,
			BodyStructure:        bodyStructure,
			Recipients:           recipients,
			Flags:                sieveFlags, // Flags set by the Sieve script (imap4flags); empty -> unread
			FTSRetention:         d.FTSRetention,
			PreservedUID:         recipient.PreservedUID,
			PreservedUIDValidity: recipient.PreservedUIDVal,
		},
		db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  d.uploadInstanceID(),
			Size:        size,
			AccountID:   destAccountID,
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
			// A duplicate is an accepted delivery, as it is in LMTP: the message is
			// already in the mailbox, so a resubmission must not be reported as a
			// delivery failure.
			//
			// InsertMessage returns the existing row's UID alongside the duplicate
			// error, except on a unique-constraint violation: that aborts the
			// transaction before the row can be looked up, leaving the UID at 0.
			result.Success = true
			result.MailboxName = mailbox.Name
			result.MessageUID = uint32(messageUID)
			// Don't notify uploader for duplicates
			return result, nil
		}
		// DO NOT delete the local file on non-duplicate errors.
		//
		// The DB transaction may have committed before the error was returned to us
		// (e.g. a network timeout during the COMMIT acknowledgment — the server
		// committed but the ACK never reached sora). In that case:
		//   • The pending_uploads record IS in the database.
		//   • If we delete the file here, the uploader will retry 5 times with
		//     "no such file or directory", exhaust max_attempts, and the message
		//     is permanently lost (S3 status: MISSING) — exactly the incident that
		//     was reported (upload id=6197517, hash=66e220f4...).
		//
		// If the transaction truly rolled back (no pending_upload record), the file
		// will be cleaned up by cleanupOrphanedFiles after the 1-hour grace period.
		// That is a safe, conservative outcome — a harmless temporary orphan.
		//
		// Old code deleted the file here:
		//   _ = d.Uploader.RemoveLocalFile(*filePath)
		// That was the proximate cause of permanent message loss on transient DB errors.
		if filePath != nil {
			d.Logger.Log("Keeping local file after DB error (transaction may have committed): %s", *filePath)
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
	result.MailboxName = mailbox.Name // resolved mailbox (may be INBOX after an ACL-denied fallback)
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

// resolveOwnedTarget resolves mailboxName for the recipient, supporting shared
// mailboxes owned by another account. For a cross-account target it enforces the 'i'
// (insert) right (RFC 4314), falling back to the recipient's INBOX on denial, then
// resolves the destination OWNER's account id + S3 domain/localpart (via OwnerResolver)
// so the message is attributed to the mailbox owner rather than the recipient (B2), and
// — for a cross-account target — hardlinks the already-staged body to the owner's
// staging path so the uploader writes it under the owner's S3 path.
//
// The body MUST already be stored locally under recipient.AccountID (e.g. via
// Uploader.StoreLocally) before this is called. DeliverMessage's inline save and
// SaveMessageToMailbox both use this so the two paths cannot drift (e.g. one of them
// skipping the 'i' right check).
func (d *DeliveryContext) resolveOwnedTarget(ctx context.Context, recipient RecipientInfo, mailboxName, contentHash string) (mailbox *db.DBMailbox, destAccountID int64, destS3Domain, destS3Localpart string, err error) {
	mailbox, err = d.RDB.GetMailboxByNameWithRetry(ctx, recipient.AccountID, mailboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			// Fallback to INBOX
			mailbox, err = d.RDB.GetMailboxByNameWithRetry(ctx, recipient.AccountID, consts.MailboxInbox)
		}
		if err != nil {
			return nil, 0, "", "", err
		}
	}

	// Enforce the insert ('i') right for shared mailboxes owned by another account: a
	// SIEVE fileinto / delivery must not write into a mailbox the recipient can only
	// look up (RFC 4314). On denial (or check error) deliver to the recipient's INBOX.
	if mailbox.AccountID != recipient.AccountID {
		canInsert, permErr := d.RDB.CheckMailboxPermissionWithRetry(ctx, mailbox.ID, recipient.AccountID, db.ACLRightInsert)
		if permErr != nil || !canInsert {
			d.Logger.Log("delivery denied: no insert right on shared mailbox %q, delivering to INBOX (err=%v)", mailbox.Name, permErr)
			if mailbox, err = d.RDB.GetMailboxByNameWithRetry(ctx, recipient.AccountID, consts.MailboxInbox); err != nil {
				return nil, 0, "", "", err
			}
		}
	}

	// Lazy-init OwnerResolver for tests or contexts where it wasn't pre-populated.
	if d.OwnerResolver == nil {
		d.OwnerResolver = resilient.NewOwnerResolver(d.RDB)
	}

	destAccountID = mailbox.AccountID
	destS3Domain, destS3Localpart, err = d.OwnerResolver.ResolveDestinationOwner(ctx, destAccountID, recipient.AccountID, recipient.Address.Domain(), recipient.Address.LocalPart())
	if err != nil {
		return nil, 0, "", "", fmt.Errorf("failed to resolve owner for destination mailbox '%s': %v", mailbox.Name, err)
	}

	// For a cross-account target the body was staged under the recipient's account;
	// hardlink it to the owner's staging path so the uploader writes the body under the
	// owner's S3 path (B2).
	if destAccountID != recipient.AccountID {
		sourcePath := d.Uploader.FilePath(contentHash, recipient.AccountID)
		destPath := d.Uploader.FilePath(contentHash, destAccountID)
		if sourcePath != destPath {
			if linkErr := helpers.LinkOrCopyFile(sourcePath, destPath); linkErr != nil {
				d.Logger.Log("failed to stage local file for cross-account delivery: %v", linkErr)
			}
		}
	}

	return mailbox, destAccountID, destS3Domain, destS3Localpart, nil
}

// SaveMessageToMailbox saves a message to a specific mailbox (helper for Sieve :copy).
// flags carries any keywords/flags set by the Sieve script (imap4flags, RFC 5232).
func (d *DeliveryContext) SaveMessageToMailbox(ctx context.Context, recipient RecipientInfo, mailboxName string, messageBytes []byte, messageEntity *message.Entity, plaintextBody *string, flags []imap.Flag) error {
	contentHash := helpers.HashContent(messageBytes)

	mailbox, destAccountID, destS3Domain, destS3Localpart, err := d.resolveOwnedTarget(ctx, recipient, mailboxName, contentHash)
	if err != nil {
		return err
	}

	// Parse message metadata
	mailHeader := mail.Header{Header: messageEntity.Header}
	subject, _ := mailHeader.Subject()
	messageID, _ := mailHeader.MessageID()
	sentDate, _ := mailHeader.Date()
	inReplyTo, _ := mailHeader.MsgIDList("In-Reply-To")
	references, _ := mailHeader.MsgIDList("References")

	if sentDate.IsZero() {
		sentDate = time.Now()
	}

	bodyStructureVal := imapserver.ExtractBodyStructure(bytes.NewReader(messageBytes))
	bodyStructure := &bodyStructureVal
	recipients := helpers.ExtractRecipients(messageEntity.Header)

	size := int64(len(messageBytes))

	_, _, err = d.RDB.InsertMessageWithRetry(ctx,
		&db.InsertMessageOptions{
			AccountID:     destAccountID,
			MailboxID:     mailbox.ID,
			S3Domain:      destS3Domain,
			S3Localpart:   destS3Localpart,
			MailboxName:   mailbox.Name,
			ContentHash:   contentHash,
			DeliveryHash:  recipient.DeliveryHash,
			MessageID:     messageID,
			InternalDate:  time.Now(),
			Size:          size,
			Subject:       subject,
			PlaintextBody: *plaintextBody,
			SentDate:      sentDate,
			InReplyTo:     inReplyTo,
			References:    references,
			BodyStructure: bodyStructure,
			Recipients:    recipients,
			Flags:         flags,
			FTSRetention:  d.FTSRetention,
		},
		db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  d.uploadInstanceID(),
			Size:        size,
			AccountID:   destAccountID,
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
