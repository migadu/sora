package imap

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/server"

	_ "github.com/emersion/go-message/charset"
)

func (s *IMAPSession) Append(mboxName string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	mailbox, err := s.server.db.GetMailboxByName(s.ctx, s.UserID(), mboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.Log("[APPEND] mailbox '%s' does not exist", mboxName)
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mboxName),
			}
		}
		return nil, s.internalError("failed to fetch mailbox '%s': %v", mboxName, err)
	}

	// Read the entire message into a buffer
	var buf bytes.Buffer
	if _, err = io.Copy(&buf, r); err != nil {
		return nil, s.internalError("failed to read message: %v", err)
	}

	// Use the full message bytes as received for hashing, size, and header extraction.
	fullMessageBytes := buf.Bytes()

	// Check if the message exceeds the configured APPENDLIMIT
	if s.server.appendLimit > 0 && int64(len(fullMessageBytes)) > s.server.appendLimit {
		s.Log("[APPEND] message size %d bytes exceeds APPENDLIMIT of %d bytes", len(fullMessageBytes), s.server.appendLimit)
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
		sentDate = options.Time
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

	filePath, err := s.server.uploader.StoreLocally(contentHash, fullMessageBytes)
	if err != nil {
		return nil, s.internalError("failed to save message to disk: %v", err)
	}

	size := int64(len(fullMessageBytes))

	_, messageUID, err := s.server.db.InsertMessage(s.ctx,
		&db.InsertMessageOptions{
			UserID:        s.UserID(),
			MailboxID:     mailbox.ID,
			MailboxName:   mailbox.Name,
			ContentHash:   contentHash,
			MessageID:     messageID,
			Flags:         options.Flags,
			InternalDate:  options.Time,
			Size:          size,
			Subject:       subject,
			PlaintextBody: actualPlaintextBody,
			SentDate:      sentDate,
			InReplyTo:     inReplyTo,
			BodyStructure: &bodyStructure,
			Recipients:    recipients,
			RawHeaders:    rawHeadersText,
		},
		db.PendingUpload{
			InstanceID:  s.server.hostname,
			ContentHash: contentHash,
			Size:        size,
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

	// If the message was appended to the currently selected mailbox,
	// update the session's message count and notify the tracker.
	// This requires protecting access to session state like s.selectedMailbox.
	s.mutex.Lock()
	if s.selectedMailbox != nil && s.selectedMailbox.ID == mailbox.ID {
		s.currentNumMessages++ // Increment the count for the selected mailbox
		if s.mailboxTracker != nil {
			s.mailboxTracker.QueueNumMessages(s.currentNumMessages)
		} else {
			// This would indicate an inconsistent state if a mailbox is selected but has no tracker.
			s.Log("[APPEND] Inconsistent state: selectedMailbox ID %d is set, but mailboxTracker is nil.", s.selectedMailbox.ID)
		}
	}
	s.mutex.Unlock()

	s.server.uploader.NotifyUploadQueued()

	return &imap.AppendData{
		UID:         imap.UID(messageUID),
		UIDValidity: mailbox.UIDValidity,
	}, nil
}
