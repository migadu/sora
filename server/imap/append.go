package imap

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
	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server"

	_ "github.com/emersion/go-message/charset"
)

// extractBodyStructureSafe wraps imapserver.ExtractBodyStructure with panic recovery and validation.
// Returns a default body structure if extraction fails or structure is invalid (e.g., multipart with no children).
func extractBodyStructureSafe(data []byte) imap.BodyStructure {
	defer func() {
		if r := recover(); r != nil {
			// Panic during body structure extraction, will use default below
		}
	}()

	bs := imapserver.ExtractBodyStructure(bytes.NewReader(data))
	if bs != nil {
		// Validate the extracted body structure
		if err := helpers.ValidateBodyStructure(&bs); err != nil {
			// Invalid structure (e.g., multipart with no children), use default
			return &imap.BodyStructureSinglePart{
				Type:     "text",
				Subtype:  "plain",
				Params:   map[string]string{"charset": "utf-8"},
				Extended: &imap.BodyStructureSinglePartExt{}, // Always populate Extended to match imapserver.ExtractBodyStructure behavior
			}
		}
		return bs
	}

	// Return default body structure for corrupted messages
	return &imap.BodyStructureSinglePart{
		Type:     "text",
		Subtype:  "plain",
		Params:   map[string]string{"charset": "utf-8"},
		Extended: &imap.BodyStructureSinglePartExt{}, // Always populate Extended to match imapserver.ExtractBodyStructure behavior
	}
}

func (s *IMAPSession) Append(mboxName string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	start := time.Now()
	recordMetrics := func(status string) {
		metrics.CommandsTotal.WithLabelValues("imap", "APPEND", status).Inc()
		metrics.CommandDuration.WithLabelValues("imap", "APPEND").Observe(time.Since(start).Seconds())
	}

	// Create a context that signals to use the master DB if the session is pinned.
	readCtx := s.ctx
	if s.useMasterDB.Load() {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	mailbox, err := s.server.rdb.GetMailboxByNameWithRetry(readCtx, s.AccountID(), mboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.DebugLog("mailbox does not exist", "mailbox", mboxName)
			imapErr := &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeTryCreate,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mboxName),
			}
			s.classifyAndTrackError("APPEND", err, imapErr)
			recordMetrics("failure")
			return nil, imapErr
		}
		s.classifyAndTrackError("APPEND", err, nil)
		recordMetrics("failure")
		return nil, s.internalError("failed to fetch mailbox '%s': %v", mboxName, err)
	}

	// Check ACL permissions - requires 'i' (insert) right
	hasInsertRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(readCtx, mailbox.ID, s.AccountID(), 'i')
	if err != nil {
		s.classifyAndTrackError("APPEND", err, nil)
		recordMetrics("failure")
		return nil, s.internalError("failed to check insert permission: %v", err)
	}
	if !hasInsertRight {
		s.DebugLog("user does not have insert permission", "mailbox", mboxName)
		imapErr := &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to append messages to this mailbox",
		}
		s.classifyAndTrackError("APPEND", nil, imapErr)
		recordMetrics("failure")
		return nil, imapErr
	}

	// Read the entire message into a buffer
	var buf bytes.Buffer
	if _, err = io.Copy(&buf, r); err != nil {
		// Network read errors during APPEND command are typically:
		// - unexpected EOF: client disconnected mid-transmission
		// - context canceled: timeout or shutdown
		// - connection reset: network interruption
		s.WarnLog("failed to read message data from network", "error", err, "bytes_read", buf.Len())
		s.classifyAndTrackError("APPEND", err, nil)
		// Bypass metric tracking for client socket timeouts so they don't skew our P99 durations
		return nil, s.internalError("failed to read message: %v", err)
	}

	// Reset the metric timer NOW. Network transmission from a slow client
	// can take 20+ seconds for a large payload, which artificially inflates
	// backend processing latency metrics.
	start = time.Now()

	// Use the full message bytes as received for hashing, size, and header extraction.
	fullMessageBytes := buf.Bytes()

	// Reject empty messages — a valid RFC 5322 message always has headers.
	// A 0-byte literal can occur from buggy clients or truncated connections
	// where io.Copy returns nil error but reads no data.
	if len(fullMessageBytes) == 0 {
		s.WarnLog("rejecting empty message APPEND (0 bytes)")
		recordMetrics("failure")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "empty message rejected: a message must contain at least headers",
		}
	}

	// Check if the message exceeds the configured APPENDLIMIT
	if s.server.appendLimit > 0 && int64(len(fullMessageBytes)) > s.server.appendLimit {
		s.DebugLog("message size exceeds APPENDLIMIT", "size", len(fullMessageBytes), "limit", s.server.appendLimit)
		s.classifyAndTrackError("APPEND", nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeTooBig})
		recordMetrics("failure")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeTooBig,
			Text: fmt.Sprintf("message size %d bytes exceeds maximum allowed size of %d bytes", len(fullMessageBytes), s.server.appendLimit),
		}
	}

	// Extract raw headers string.
	// Headers are typically terminated by a double CRLF (\r\n\r\n).
	var rawHeadersText string
	headerEndIndex := bytes.Index(fullMessageBytes, []byte("\r\n\r\n"))
	if headerEndIndex != -1 {
		rawHeadersText = string(fullMessageBytes[:headerEndIndex])
	} else {
		// Log if headers are not clearly separated. rawHeadersText will be empty.
		// This might indicate a malformed email or an email with only headers and no body separator.
		s.DebugLog("could not find standard header/body separator in message")
	}

	messageContent, err := server.ParseMessage(bytes.NewReader(fullMessageBytes))
	if err != nil {
		// ParseMessage can fail for severely malformed MIME (e.g., missing header colons).
		// IMAP APPEND must still accept the message — the raw bytes are stored in S3 as-is.
		// We continue with degraded metadata (empty subject, no FTS, etc.).
		s.DebugLog("failed to parse message, continuing with degraded metadata", "error", err)
	}

	contentHash := helpers.HashContent(fullMessageBytes)

	// Parse message headers (this does not consume the body)
	var subject, messageID string
	var sentDate time.Time
	var inReplyTo []string
	var actualPlaintextBody string
	var recipients []helpers.Recipient

	if messageContent != nil {
		mailHeader := mail.Header{Header: messageContent.Header}
		subject, _ = mailHeader.Subject()
		messageID, _ = mailHeader.MessageID()
		sentDate, _ = mailHeader.Date()
		inReplyTo, _ = mailHeader.MsgIDList("In-Reply-To")

		if len(inReplyTo) == 0 {
			inReplyTo = nil
		}

		extractedPlaintext, extractErr := helpers.ExtractPlaintextBody(messageContent)
		if extractErr != nil {
			s.DebugLog("failed to extract plaintext body, using empty string", "error", extractErr)
		} else if extractedPlaintext != nil {
			actualPlaintextBody = *extractedPlaintext
		}

		recipients = helpers.ExtractRecipients(messageContent.Header)
	}

	// RFC 3501 §6.3.11: when the APPEND command supplies an explicit date-time,
	// that value MUST be used as INTERNALDATE regardless of the message's own
	// Date: header.  The Date: header value is kept separately as SentDate.
	internalDate := options.Time // APPEND command date-time (may be zero)
	if internalDate.IsZero() {
		internalDate = sentDate // fall back to message's Date: header
	}
	if internalDate.IsZero() {
		internalDate = time.Now() // last-resort: current time
	}
	// sentDate is kept as-is (from the message's Date: header) for SentDate.
	// If the message had no Date: header at all, align SentDate with internalDate.
	if sentDate.IsZero() {
		sentDate = internalDate
	}

	// Extract body structure with panic recovery for malformed messages
	bodyStructure := extractBodyStructureSafe(buf.Bytes())

	// Store message locally for background upload to S3
	// Check if file already exists to prevent race condition:
	// If a duplicate APPEND arrives while uploader is processing the first copy,
	// we don't want to overwrite/delete the file the uploader is reading.
	if s.server.uploader == nil {
		recordMetrics("failure")
		return nil, s.internalError("uploader not configured - cannot store message")
	}
	expectedPath := s.server.uploader.FilePath(contentHash, s.AccountID())
	var filePath *string
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		// File doesn't exist, safe to write
		filePath, err = s.server.uploader.StoreLocally(contentHash, s.AccountID(), fullMessageBytes)
		if err != nil {
			recordMetrics("failure")
			return nil, s.internalError("failed to save message to disk: %v", err)
		}
		s.DebugLog("message accepted locally", "path", *filePath)
	} else if err == nil {
		// File already exists (likely being processed by uploader or concurrent duplicate APPEND)
		// Don't overwrite it, and don't set filePath so we won't try to delete it later
		filePath = nil
		s.DebugLog("message file already exists, skipping write (concurrent APPEND)", "path", expectedPath)
	} else {
		// Stat error (permission issue, etc.)
		recordMetrics("failure")
		return nil, s.internalError("failed to check file existence: %v", err)
	}

	size := int64(len(fullMessageBytes))

	// User.Address is always the primary address (set during LOGIN)
	// No need to query - it's already cached in the session
	// Sanitize flags to remove invalid values (e.g., NIL, NULL, empty strings)
	// This prevents protocol errors like "Keyword used without being in FLAGS: NIL"
	sanitizedFlags := helpers.SanitizeFlags(options.Flags)

	// RFC 3501 §2.3.2: \Recent is a session flag — it must NOT be stored
	// permanently.  It is tracked per-session via lastHighestUID / NumRecent in
	// SELECT.  Storing it in the database bitfield causes every future FETCH
	// FLAGS response to show \Recent, which is a protocol violation.
	appendFlags := sanitizedFlags

	_, messageUID, err := s.server.rdb.InsertMessageWithRetry(s.ctx,
		&db.InsertMessageOptions{
			AccountID:     s.AccountID(),
			MailboxID:     mailbox.ID,
			S3Domain:      s.Session.User.Domain(),
			S3Localpart:   s.Session.User.LocalPart(),
			MailboxName:   mailbox.Name,
			ContentHash:   contentHash,
			MessageID:     messageID,
			Flags:         appendFlags,
			InternalDate:  internalDate, // RFC 3501 §6.3.11: APPEND date-time takes precedence
			Size:          size,
			Subject:       subject,
			PlaintextBody: actualPlaintextBody,
			SentDate:      sentDate,
			InReplyTo:     inReplyTo,
			BodyStructure: &bodyStructure,
			Recipients:    recipients,
			RawHeaders:    rawHeadersText,
			FTSRetention:  s.server.ftsRetention,
		},
		db.PendingUpload{
			InstanceID:  s.server.hostname,
			ContentHash: contentHash,
			Size:        size,
			AccountID:   s.AccountID(),
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
			if filePath != nil {
				s.DebugLog("duplicate message detected, keeping file for potential pending upload", "content_hash", contentHash)
			}
			s.DebugLog("duplicate message detected, skipping upload", "messageID", messageID, "existing_uid", messageUID)
			// Return success with existing UID - don't notify uploader
			recordMetrics("success")
			return &imap.AppendData{
				UID:         imap.UID(messageUID),
				UIDValidity: mailbox.UIDValidity,
			}, nil
		}
		// Never delete the local file on error. The uploader's
		// cleanupOrphanedFiles job (runs every 5 min, 1h grace period)
		// already checks PendingUploadExists before removing any file.
		// Deleting here is dangerous: if the transaction silently
		// committed (e.g. commit ambiguity on timeout), the upload
		// worker still needs this file to complete the S3 upload.
		if filePath != nil {
			s.DebugLog("keeping file for cleanup job after error", "content_hash", contentHash)
		}
		recordMetrics("failure")
		return nil, s.internalError("failed to insert message metadata: %v", err)
	}

	// Before updating the session state, check if the context is still valid
	// and then update the session state under mutex protection
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted after message insertion")
		// We've already inserted the message successfully, so still return success
		recordMetrics("success")
		return &imap.AppendData{
			UID:         imap.UID(messageUID),
			UIDValidity: mailbox.UIDValidity,
		}, nil
	}

	// Notify the uploader BEFORE acquiring the session write lock.
	// NotifyUploadQueued can block in synchronous-upload test mode (EnableSyncUpload),
	// and the poll goroutine must be able to acquire the write lock during that time.
	// If we notified inside the lock, the poll goroutine would time out waiting,
	// return a server-bug error, and the go-imap library would close the connection.
	s.server.uploader.NotifyUploadQueued()

	// Update the session's message count and notify the tracker if needed
	acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.DebugLog("failed to acquire write lock within timeout")
		recordMetrics("success")
		return &imap.AppendData{
			UID:         imap.UID(messageUID),
			UIDValidity: mailbox.UIDValidity,
		}, nil
	}
	defer release()

	// Pin this session to the master DB to ensure read-your-writes consistency.
	s.useMasterDB.Store(true)

	// After re-acquiring the lock, check again if the context is still valid
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted during mutex acquisition")
		recordMetrics("success")
		return &imap.AppendData{
			UID:         imap.UID(messageUID),
			UIDValidity: mailbox.UIDValidity,
		}, nil
	}

	// NOTE: We intentionally do NOT update currentNumMessages or the tracker here.
	// The InsertMessageWithRetry call above runs outside the session lock. Between
	// its return and us acquiring the write lock, a concurrent Poll (from the
	// go-imap write goroutine) can run and sync the session count from the DB.
	// If we also Add(1) here, we double-count the message, causing session_count
	// to be 1 ahead of db_count — leading to missed_old_expunges BYE.
	//
	// Instead, we let Poll naturally discover the new message via the DB's
	// mailbox_stats.message_count (updated by the INSERT trigger) and call
	// QueueNumMessages to update the tracker. The EXISTS notification reaches
	// the client during the next Poll cycle (typically immediate, as the
	// go-imap write goroutine polls after each command response).

	metrics.MessageThroughput.WithLabelValues("imap", "appended", "success").Inc()

	// Track domain and user command activity - APPEND is storage intensive!
	if s.IMAPUser != nil {
		metrics.TrackDomainCommand("imap", s.IMAPUser.Address.Domain(), "APPEND")
		metrics.TrackUserActivity("imap", s.IMAPUser.Address.FullAddress(), "command", 1)
		metrics.TrackDomainBytes("imap", s.IMAPUser.Address.Domain(), "in", int64(buf.Len()))
		metrics.TrackDomainMessage("imap", s.IMAPUser.Address.Domain(), "appended")
	}

	// Track for session summary
	s.messagesAppended.Add(1)

	s.DebugLog("successfully appended message", "mailbox", mboxName, "uid", messageUID, "uidvalidity", mailbox.UIDValidity)

	recordMetrics("success")
	return &imap.AppendData{
		UID:         imap.UID(messageUID),
		UIDValidity: mailbox.UIDValidity,
	}, nil
}
