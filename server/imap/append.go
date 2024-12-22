package imap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/google/uuid"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/server"
)

func (s *IMAPSession) Append(mboxName string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	var result *imap.AppendData
	var err error

	ctx := context.Background()

	pathComponents := strings.Split(mboxName, string(consts.MailboxDelimiter))
	mailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.UserID(), pathComponents)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
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
	_, err = io.Copy(&buf, r)
	if err != nil {
		return nil, s.internalError("failed to read message: %v", err)
	}

	parseReader := bytes.NewReader(buf.Bytes())

	messageContent, err := server.ParseMessage(parseReader)
	if err != nil {
		return nil, s.internalError("failed to parse message: %v", err)
	}

	// Define the append operation that will be retried
	operation := func() error {
		// Create a new copy of the buffer for each attempt
		appendBuf := bytes.NewBuffer(buf.Bytes())
		result, err = s.appendSingle(ctx, mailbox, messageContent, appendBuf, options)
		if err != nil {
			if err == consts.ErrInternalError ||
				err == consts.ErrMalformedMessage {
				return backoff.Permanent(&backoff.PermanentError{Err: err})
			}
			if err == consts.ErrMessageExists {
				log.Printf("Message already exists: %v, ignoring", err)
				return nil
			}
			log.Printf("Append operation failed: %v", err)
			return err
		}
		return nil
	}

	// TODO: Make this configurable
	// Set up exponential backoff
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = 500 * time.Millisecond
	expBackoff.MaxInterval = 10 * time.Second
	expBackoff.MaxElapsedTime = 1 * time.Minute

	// Run the operation with retries
	if err := backoff.Retry(operation, expBackoff); err != nil {
		if errors.Is(err, backoff.Permanent(&backoff.PermanentError{Err: err})) {
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeAlreadyExists,
				Text: fmt.Sprintf("message already exists: %v", err),
			}
		}
		// If retries fail, return the last error
		return nil, s.internalError("failed to append message: %v", err)
	}

	// TODO: Update the mailbox's last poll time
	// s.mailbox.lastPollAt = time.Now()

	// If successful, return the AppendData
	return result, nil
}

// Actual logic for appending a single message to the mailbox
func (s *IMAPSession) appendSingle(ctx context.Context, mbox *db.DBMailbox, messageContent *message.Entity, buf *bytes.Buffer, options *imap.AppendOptions) (*imap.AppendData, error) {
	bufSize := int64(buf.Len())
	s3UploadBuf := bytes.NewBuffer(buf.Bytes())

	// Parse message headers (this does not consume the body)
	mailHeader := mail.Header{Header: messageContent.Header}
	subject, _ := mailHeader.Subject()
	messageID, _ := mailHeader.MessageID()
	sentDate, _ := mailHeader.Date()
	inReplyTo, _ := mailHeader.MsgIDList("In-Reply-To")

	if sentDate.IsZero() {
		sentDate = options.Time
	}

	bodyStructure := imapserver.ExtractBodyStructure(bytes.NewReader(buf.Bytes()))

	plaintextBody, err := helpers.ExtractPlaintextBody(messageContent)
	if err != nil {
		log.Printf("Failed to extract plaintext body: %v", err)
		return nil, consts.ErrMalformedMessage
	}

	// log.Println("Plaintext body:", *plaintextBody)
	recipients := db.ExtractRecipients(messageContent.Header)
	// Generate a new UUID for the message
	uuidKey := uuid.New()

	messageUID, err := s.server.db.InsertMessage(ctx, mbox.ID, uuidKey, messageID, options.Flags, options.Time, bufSize, subject, plaintextBody, sentDate, inReplyTo, s3UploadBuf, &bodyStructure, &recipients, func(uid uuid.UUID, s3Buf *bytes.Buffer, s3BufSize int64) error {
		s3DestKey := server.S3Key(s.Domain(), s.LocalPart(), uid)
		return s.server.s3.SaveMessage(s3DestKey, s3Buf, s3BufSize)
	})
	if err != nil {
		if err == consts.ErrDBUniqueViolation {
			// Message already exists, continue with the next message
			return nil, consts.ErrMessageExists
		}
		return nil, consts.ErrInternalError
	}

	appendData := &imap.AppendData{
		UID:         imap.UID(messageUID),
		UIDValidity: mbox.UIDValidity,
	}

	return appendData, nil
}
