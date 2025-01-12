package imap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/google/uuid"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server"
)

func (s *IMAPSession) Fetch(w *imapserver.FetchWriter, seqSet imap.NumSet, options *imap.FetchOptions) error {
	ctx := context.Background()

	seqSet = s.mailbox.decodeNumSet(seqSet)

	messages, err := s.server.db.GetMessagesBySeqSet(ctx, s.mailbox.ID, seqSet)
	if err != nil {
		return s.internalError("failed to retrieve messages: %v", err)
	}

	for _, msg := range messages {
		if err := s.fetchMessage(w, &msg, options); err != nil {
			return err
		}
	}

	return nil
}

func (s *IMAPSession) fetchMessage(w *imapserver.FetchWriter, msg *db.Message, options *imap.FetchOptions) error {
	m := w.CreateMessage(s.mailbox.sessionTracker.EncodeSeqNum(msg.Seq))
	if m == nil {
		return s.internalError("failed to begin message for UID %d", msg.UID)
	}

	if err := s.writeBasicMessageData(m, msg, options); err != nil {
		return err
	}

	if options.Envelope {
		if err := s.writeEnvelope(m, msg.UID, msg.MailboxID); err != nil {
			return err
		}
	}

	if options.BodyStructure != nil {
		if err := s.writeBodyStructure(m, msg.UID, msg.MailboxID); err != nil {
			return err
		}
	}

	if len(options.BodySection) > 0 || len(options.BinarySection) > 0 || len(options.BinarySectionSize) > 0 {
		s3UUIDKey, err := uuid.Parse(msg.StorageUUID)
		if err != nil {
			return s.internalError("failed to parse message UUID: %v", err)
		}
		s3Key := server.S3Key(s.Domain(), s.LocalPart(), s3UUIDKey)

		log.Printf("Fetching message body for UID %d", msg.UID)
		bodyReader, err := s.server.s3.GetMessage(s3Key)
		if err != nil {
			return s.internalError("failed to retrieve message body for UID %d from S3: %v", msg.UID, err)
		}
		defer bodyReader.Close()
		log.Printf("Retrieved message body for UID %d", msg.UID)

		bodyData, err := io.ReadAll(bodyReader)
		if err != nil {
			return s.internalError("failed to read message body for UID %d: %v", msg.UID, err)
		}

		if len(options.BodySection) > 0 {
			if err := s.handleBodySections(m, bodyData, options); err != nil {
				return err
			}
		}

		if len(options.BinarySection) > 0 {
			if err := s.handleBinarySections(m, bodyData, options); err != nil {
				return err
			}
		}

		if len(options.BinarySectionSize) > 0 {
			if err := s.handleBinarySectionSize(m, bodyData, options); err != nil {
				return err
			}
		}
	}

	// TODO: Fetch ModSeq (if CONDSTORE is supported)

	if err := m.Close(); err != nil {
		return fmt.Errorf("failed to end message for UID %d: %v", msg.UID, err)
	}

	return nil
}

// Fetch helper to write basic message data (FLAGS, UID, INTERNALDATE, RFC822.SIZE)
func (s *IMAPSession) writeBasicMessageData(m *imapserver.FetchResponseWriter, msg *db.Message, options *imap.FetchOptions) error {
	if options.Flags {
		m.WriteFlags(db.BitwiseToFlags(msg.BitwiseFlags))
	}
	if options.UID {
		m.WriteUID(msg.UID)
	}
	if options.InternalDate {
		m.WriteInternalDate(msg.InternalDate)
	}
	if options.RFC822Size {
		m.WriteRFC822Size(int64(msg.Size))
	}
	return nil
}

// Fetch helper to write the envelope for a message
func (s *IMAPSession) writeEnvelope(m *imapserver.FetchResponseWriter, messageUID imap.UID, mailboxID int) error {
	ctx := context.Background()
	envelope, err := s.server.db.GetMessageEnvelope(ctx, messageUID, mailboxID)
	if err != nil {
		return s.internalError("failed to retrieve envelope for message UID %d: %v", messageUID, err)
	}
	m.WriteEnvelope(envelope)
	return nil
}

// Fetch helper to write the body structure for a message
func (s *IMAPSession) writeBodyStructure(m *imapserver.FetchResponseWriter, messageUID imap.UID, mailboxID int) error {
	ctx := context.Background()
	bodyStructure, err := s.server.db.GetMessageBodyStructure(ctx, messageUID, mailboxID)
	if err != nil {
		return s.internalError("failed to retrieve body structure for message UID %d: %v", messageUID, err)
	}
	m.WriteBodyStructure(*bodyStructure)
	return nil
}

// Fetch helper to handle BINARY sections for a message
func (s *IMAPSession) handleBinarySections(w *imapserver.FetchResponseWriter, bodyData []byte, options *imap.FetchOptions) error {
	for _, section := range options.BinarySection {
		buf := imapserver.ExtractBinarySection(bytes.NewReader(bodyData), section)
		wc := w.WriteBinarySection(section, int64(len(buf)))
		_, writeErr := wc.Write(buf)
		closeErr := wc.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

// Fetch helper to handle BINARY.SIZE sections for a message
func (s *IMAPSession) handleBinarySectionSize(w *imapserver.FetchResponseWriter, bodyData []byte, options *imap.FetchOptions) error {
	for _, section := range options.BinarySectionSize {
		n := imapserver.ExtractBinarySectionSize(bytes.NewReader(bodyData), section)
		w.WriteBinarySectionSize(section, n)
	}
	return nil
}

// Fetch helper to handle BODY sections for a message
func (s *IMAPSession) handleBodySections(w *imapserver.FetchResponseWriter, bodyData []byte, options *imap.FetchOptions) error {
	for _, section := range options.BodySection {
		buf := imapserver.ExtractBodySection(bytes.NewReader(bodyData), section)
		wc := w.WriteBodySection(section, int64(len(buf)))
		_, writeErr := wc.Write(buf)
		closeErr := wc.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
