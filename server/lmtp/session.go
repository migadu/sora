package lmtp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/emersion/go-message/mail"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/server"
)

type LMTPSession struct {
	server.Session
	backend *LMTPServerBackend
	sender  *server.Address
	conn    *smtp.Conn
}

func (s *LMTPSession) Mail(from string, opts *smtp.MailOptions) error {
	fromAddress, err := server.NewAddress(from)
	if err != nil {
		s.Log("Invalid from address: %v", err)
		return &smtp.SMTPError{
			Code:         553,
			EnhancedCode: smtp.EnhancedCode{5, 1, 7},
			Message:      "Invalid sender",
		}
	}
	s.sender = &fromAddress
	s.Log("Mail from=%s", fromAddress.FullAddress())
	return nil
}

func (s *LMTPSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	toAddress, err := server.NewAddress(to)
	if err != nil {
		s.Log("Invalid to address: %v", err)
		return &smtp.SMTPError{
			Code:         513,
			EnhancedCode: smtp.EnhancedCode{5, 0, 1}, // TODO: Check the correct code
			Message:      "Invalid recipient",
		}
	}
	userId, err := s.backend.db.GetUserIDByAddress(context.Background(), toAddress.FullAddress())
	if err != nil {
		s.Log("Failed to get user ID by address: %v", err)
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 0, 2}, // TODO: Check the correct code
			Message:      "No such user here",
		}
	}
	s.User = server.NewUser(toAddress, userId)
	s.Log("Rcpt to=%s", toAddress.FullAddress())
	return nil
}

func (s *LMTPSession) Data(r io.Reader) error {
	// Read the entire message into a buffer
	var buf bytes.Buffer
	_, err := io.Copy(&buf, r)
	if err != nil {
		return s.internalError("failed to read message: %v", err)
	}

	bufSize := int64(buf.Len())
	s3UploadBuf := bytes.NewBuffer(buf.Bytes())
	parseBuf := bytes.NewReader(buf.Bytes())

	messageContent, err := server.ParseMessage(parseBuf)
	if err != nil {
		// TODO: End the session?
		return s.internalError("failed to parse message: %v", err)
	}

	// Parse message headers (this does not consume the body)
	mailHeader := mail.Header{Header: messageContent.Header}
	subject, _ := mailHeader.Subject()
	messageID, _ := mailHeader.MessageID()
	sentDate, _ := mailHeader.Date()
	inReplyTo, _ := mailHeader.MsgIDList("In-Reply-To")

	if sentDate.IsZero() {
		sentDate = time.Now()
	}

	bodyStructure := imapserver.ExtractBodyStructure(bytes.NewReader(buf.Bytes()))

	plaintextBody, err := helpers.ExtractPlaintextBody(messageContent)
	if err != nil {
		log.Printf("Failed to extract plaintext body: %v", err)
		return &smtp.SMTPError{
			Code:         554,
			EnhancedCode: smtp.EnhancedCode{5, 6, 0}, // TODO: Check the correct code
			Message:      "Malformed message",
		}
	}

	recipients := db.ExtractRecipients(messageContent.Header)
	uuidKey := uuid.New()

	// TODO: SIEVE filtering
	// Assume the message goes always to the INBOX
	mbox, err := s.backend.db.GetMailboxByName(context.Background(), s.UserID(), consts.MAILBOX_INBOX)
	if err != nil {
		return s.internalError("failed to get mailbox: %v", err)
	}

	// Save the message to the database
	messageUID, err := s.backend.db.InsertMessage(context.Background(), mbox.ID, uuidKey, messageID, []imap.Flag{}, time.Now(), bufSize, subject, plaintextBody, sentDate, inReplyTo, s3UploadBuf, &bodyStructure, &recipients, func(uid uuid.UUID, s3Buf *bytes.Buffer, s3BufSize int64) error {
		// Save the message to S3
		s3DestKey := server.S3Key(s.Domain(), s.LocalPart(), uid)
		return s.backend.s3.SaveMessage(s3DestKey, s3Buf, s3BufSize)
	})
	if err != nil {
		if err == consts.ErrDBUniqueViolation {
			// Message already exists, continue with the next message
			return &smtp.SMTPError{
				Code:         541,
				EnhancedCode: smtp.EnhancedCode{5, 0, 1}, // TODO: Check the correct code
				Message:      "Message already exists",
			}
		}
		return s.internalError("failed to save message: %v", err)
	}

	s.Log("Message saved with UID %d", messageUID)
	return nil
}

func (s *LMTPSession) Reset() {
	s.User = nil
	s.sender = nil
	s.Log("Reset")
}

func (s *LMTPSession) Logout() error {
	s.Log("Logout")
	//TODO: Do we really need to return an error to terminate the session?
	return &smtp.SMTPError{
		Code:         221,
		EnhancedCode: smtp.EnhancedCode{2, 0, 0},
		Message:      "Closing transmission channel",
	}
}

func (s *LMTPSession) internalError(format string, a ...interface{}) error {
	s.Log(format, a...)
	return &smtp.SMTPError{
		Code:         421,
		EnhancedCode: smtp.EnhancedCode{4, 4, 2},
		Message:      fmt.Sprintf(format, a...),
	}
}
