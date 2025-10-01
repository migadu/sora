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

	mailbox, err := s.server.rdb.GetMailboxByNameWithRetry(readCtx, s.UserID(), mboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.Log("[APPEND] mailbox '%s' does not exist", mboxName)
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
		s.Log("[APPEND] message size %d bytes exceeds APPENDLIMIT of %d bytes", len(fullMessageBytes), s.server.appendLimit)
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
		s.Log("[APPEND] Could not find standard header/body separator (\\r\\n\\r\\n) in message. Raw headers field will be empty.")
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

	bodyStructure := imapserver.ExtractBodyStructure(bytes.NewReader(buf.Bytes()))

	extractedPlaintext, err := helpers.ExtractPlaintextBody(messageContent)
	var actualPlaintextBody string
	if err != nil {
		s.Log("[APPEND] failed to extract plaintext body: %v. Using empty string for database.", err)
		// Continue with the append operation even if plaintext body extraction fails,
		// actualPlaintextBody is already initialized to an empty string.
	} else if extractedPlaintext != nil {
		actualPlaintextBody = *extractedPlaintext
	}

	recipients := helpers.ExtractRecipients(messageContent.Header)

	filePath, err := s.server.uploader.StoreLocally(contentHash, s.UserID(), fullMessageBytes)
	if err != nil {
		return nil, s.internalError("failed to save message to disk: %v", err)
	}

	size := int64(len(fullMessageBytes))

	// Add \Recent flag to newly appended messages
	appendFlags := make([]imap.Flag, len(options.Flags))
	copy(appendFlags, options.Flags)
	appendFlags = append(appendFlags, imap.Flag("\\Recent"))

	_, messageUID, err := s.server.rdb.InsertMessageWithRetry(s.ctx,
		&db.InsertMessageOptions{
			UserID:        s.UserID(),
			MailboxID:     mailbox.ID,
			S3Domain:      s.IMAPUser.Address.Domain(),
			S3Localpart:   s.IMAPUser.Address.LocalPart(),
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
			AccountID:   s.UserID(),
		})
	if err != nil {
		_ = os.Remove(*filePath) // cleanup file on failure
		if errors.Is(err, consts.ErrDBUniqueViolation) {
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeAlreadyExists,
				Text: "message already exists",
			}
		}
		return nil, s.internalError("failed to insert message metadata: %v", err)
	}

	// Before updating the session state, check if the context is still valid
	// and then update the session state under mutex protection
	if s.ctx.Err() != nil {
		s.Log("[APPEND] request aborted after message insertion, aborting session state update")
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
		s.Log("[APPEND] Failed to acquire write lock within timeout, returning success without session state update")
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
		s.Log("[APPEND] request aborted during mutex acquisition, aborting session state update")
		success = true
		return &imap.AppendData{
			UID:         imap.UID(messageUID),
			UIDValidity: mailbox.UIDValidity,
		}, nil
	}

	// Update session state if this message was appended to the currently selected mailbox
	if s.selectedMailbox != nil && s.selectedMailbox.ID == mailbox.ID {
		// Atomically increment the count for the selected mailbox
		newCount := s.currentNumMessages.Add(1)
		if s.mailboxTracker != nil {
			s.mailboxTracker.QueueNumMessages(newCount)
		} else {
			// This would indicate an inconsistent state if a mailbox is selected but has no tracker.
			s.Log("[APPEND] Inconsistent state: selectedMailbox ID %d is set, but mailboxTracker is nil.", s.selectedMailbox.ID)
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
	return &imap.AppendData{
		UID:         imap.UID(messageUID),
		UIDValidity: mailbox.UIDValidity,
	}, nil
}
