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
				Type:    "text",
				Subtype: "plain",
				Params:  map[string]string{"charset": "utf-8"},
			}
		}
		return bs
	}

	// Return default body structure for corrupted messages
	return &imap.BodyStructureSinglePart{
		Type:    "text",
		Subtype: "plain",
		Params:  map[string]string{"charset": "utf-8"},
	}
}

func (s *IMAPSession) Append(mboxName string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	start := time.Now()
	success := false
	defer func() {
		status := "failure"
		if success {
			status = "success"
		}
		metrics.CommandsTotal.WithLabelValues("imap", "APPEND", status).Inc()
		metrics.CommandDuration.WithLabelValues("imap", "APPEND").Observe(time.Since(start).Seconds())
	}()

	// Create a context that signals to use the master DB if the session is pinned.
	readCtx := s.ctx
	if s.useMasterDB {
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
			return nil, imapErr
		}
		s.classifyAndTrackError("APPEND", err, nil)
		return nil, s.internalError("failed to fetch mailbox '%s': %v", mboxName, err)
	}

	// Check ACL permissions - requires 'i' (insert) right
	hasInsertRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(readCtx, mailbox.ID, s.AccountID(), 'i')
	if err != nil {
		s.classifyAndTrackError("APPEND", err, nil)
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
		return nil, imapErr
	}

	// Read the entire message into a buffer
	var buf bytes.Buffer
	if _, err = io.Copy(&buf, r); err != nil {
		s.classifyAndTrackError("APPEND", err, nil)
		return nil, s.internalError("failed to read message: %v", err)
	}

	// Use the full message bytes as received for hashing, size, and header extraction.
	fullMessageBytes := buf.Bytes()

	// Check if the message exceeds the configured APPENDLIMIT
	if s.server.appendLimit > 0 && int64(len(fullMessageBytes)) > s.server.appendLimit {
		s.DebugLog("message size exceeds APPENDLIMIT", "size", len(fullMessageBytes), "limit", s.server.appendLimit)
		s.classifyAndTrackError("APPEND", nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeTooBig})
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
		return nil, s.internalError("failed to parse message: %v", err)
	}

	contentHash := helpers.HashContent(fullMessageBytes)

	// Parse message headers (this does not consume the body)
	mailHeader := mail.Header{Header: messageContent.Header}
	subject, _ := mailHeader.Subject()
	messageID, _ := mailHeader.MessageID()
	sentDate, _ := mailHeader.Date()
	inReplyTo, _ := mailHeader.MsgIDList("In-Reply-To")

	if len(inReplyTo) == 0 {
		inReplyTo = nil
	}

	if sentDate.IsZero() {
		if !options.Time.IsZero() {
			sentDate = options.Time
		} else {
			sentDate = time.Now()
		}
	}

	// Extract body structure with panic recovery for malformed messages
	bodyStructure := extractBodyStructureSafe(buf.Bytes())

	extractedPlaintext, err := helpers.ExtractPlaintextBody(messageContent)
	var actualPlaintextBody string
	if err != nil {
		s.DebugLog("failed to extract plaintext body, using empty string", "error", err)
		// Continue with the append operation even if plaintext body extraction fails,
		// actualPlaintextBody is already initialized to an empty string.
	} else if extractedPlaintext != nil {
		actualPlaintextBody = *extractedPlaintext
	}

	recipients := helpers.ExtractRecipients(messageContent.Header)

	filePath, err := s.server.uploader.StoreLocally(contentHash, s.AccountID(), fullMessageBytes)
	if err != nil {
		return nil, s.internalError("failed to save message to disk: %v", err)
	}

	size := int64(len(fullMessageBytes))

	// User.Address is always the primary address (set during LOGIN)
	// No need to query - it's already cached in the session
	// Sanitize flags to remove invalid values (e.g., NIL, NULL, empty strings)
	// This prevents protocol errors like "Keyword used without being in FLAGS: NIL"
	sanitizedFlags := helpers.SanitizeFlags(options.Flags)

	// Add \Recent flag to newly appended messages
	appendFlags := make([]imap.Flag, len(sanitizedFlags))
	copy(appendFlags, sanitizedFlags)
	appendFlags = append(appendFlags, imap.Flag("\\Recent"))

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
			InternalDate:  sentDate, // Best we can is set to message's sent date
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
			_ = os.Remove(*filePath) // Cleanup file
			s.DebugLog("duplicate message detected, skipping upload", "messageID", messageID, "existing_uid", messageUID)
			// Return success with existing UID - don't notify uploader
			success = true
			return &imap.AppendData{
				UID:         imap.UID(messageUID),
				UIDValidity: mailbox.UIDValidity,
			}, nil
		}
		// For other errors, cleanup and return error
		_ = os.Remove(*filePath)
		return nil, s.internalError("failed to insert message metadata: %v", err)
	}

	// Before updating the session state, check if the context is still valid
	// and then update the session state under mutex protection
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted after message insertion")
		// We've already inserted the message successfully, so still return success
		success = true
		return &imap.AppendData{
			UID:         imap.UID(messageUID),
			UIDValidity: mailbox.UIDValidity,
		}, nil
	}

	// Update the session's message count and notify the tracker if needed
	acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.DebugLog("failed to acquire write lock within timeout")
		success = true
		return &imap.AppendData{
			UID:         imap.UID(messageUID),
			UIDValidity: mailbox.UIDValidity,
		}, nil
	}
	defer release()

	// Pin this session to the master DB to ensure read-your-writes consistency.
	s.useMasterDB = true

	// After re-acquiring the lock, check again if the context is still valid
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted during mutex acquisition")
		success = true
		return &imap.AppendData{
			UID:         imap.UID(messageUID),
			UIDValidity: mailbox.UIDValidity,
		}, nil
	}

	// Update session state if this message was appended to the currently selected mailbox
	if s.selectedMailbox != nil && s.selectedMailbox.ID == mailbox.ID {
		// Query the actual message count from the database instead of incrementing,
		// because the append operation may have deleted a conflicting draft (net change = 0).
		// This fixes the Thunderbird draft replacement issue where clients repeatedly save
		// drafts with the same Message-ID, causing the old draft to be deleted.
		// See test: TestIMAP_AppendOperation/Draft_Replacement_-_Same_Message-ID
		oldCount := s.currentNumMessages.Load()
		actualCount, _, err := s.server.rdb.GetMailboxMessageCountAndSizeSumWithRetry(s.ctx, mailbox.ID)
		if err != nil {
			s.DebugLog("failed to get message count after append", "error", err)
			// Fall back to incrementing, which may be incorrect but prevents complete failure
			actualCount = int(s.currentNumMessages.Add(1))
		} else {
			s.currentNumMessages.Store(uint32(actualCount))
		}

		// Only queue if the count increased
		// NOTE: QueueNumMessages() only accepts increases - it panics on decreases or equal values
		// Also, QueueNumMessages panics if the new count is less than the tracker's internal count,
		// which can happen if there's a desync between s.currentNumMessages and tracker.numMessages.
		if s.mailboxTracker != nil && uint32(actualCount) > oldCount {
			panicOccurred := false
			func() {
				defer func() {
					if r := recover(); r != nil {
						panicOccurred = true
						s.WarnLog("tracker desync detected when updating after append",
							"error", r,
							"old_count", oldCount,
							"new_count", actualCount,
							"mailbox_id", mailbox.ID)
					}
				}()
				s.mailboxTracker.QueueNumMessages(uint32(actualCount))
			}()

			// If tracker update failed due to desync, other sessions won't be notified
			// of the new message. Log this clearly so it's visible in monitoring.
			// The APPEND itself succeeded, so we don't fail the operation.
			// The next IDLE/Poll will reconcile the state.
			if panicOccurred {
				s.WarnLog("append succeeded but tracker notification failed - other sessions may not see new message until next poll",
					"mailbox_id", mailbox.ID,
					"message_uid", messageUID)
			}
		} else if s.mailboxTracker == nil {
			// This would indicate an inconsistent state if a mailbox is selected but has no tracker.
			s.DebugLog("inconsistent state: mailbox selected but tracker is nil", "mailbox_id", s.selectedMailbox.ID)
		} else if actualCount > 0 && uint32(actualCount) == oldCount {
			// Draft replacement case - count didn't change
			s.DebugLog("message count unchanged after append (draft replacement)", "count", actualCount)
		}
	}

	metrics.MessageThroughput.WithLabelValues("imap", "appended", "success").Inc()

	s.server.uploader.NotifyUploadQueued()

	// Track domain and user command activity - APPEND is storage intensive!
	if s.IMAPUser != nil {
		metrics.TrackDomainCommand("imap", s.IMAPUser.Address.Domain(), "APPEND")
		metrics.TrackUserActivity("imap", s.IMAPUser.Address.FullAddress(), "command", 1)
		metrics.TrackDomainBytes("imap", s.IMAPUser.Address.Domain(), "in", int64(buf.Len()))
		metrics.TrackDomainMessage("imap", s.IMAPUser.Address.Domain(), "appended")
	}

	success = true

	s.DebugLog("successfully appended message", "mailbox", mboxName, "uid", messageUID, "uidvalidity", mailbox.UIDValidity)

	return &imap.AppendData{
		UID:         imap.UID(messageUID),
		UIDValidity: mailbox.UIDValidity,
	}, nil
}
