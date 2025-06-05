package imap

import (
	"bytes"
	"fmt"
	"io"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/db"
)

func (s *IMAPSession) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	s.mutex.Lock()
	if s.selectedMailbox == nil {
		s.mutex.Unlock()
		s.Log("[FETCH] no mailbox selected")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "No mailbox selected",
		}
	}
	selectedMailboxID := s.selectedMailbox.ID
	decodedNumSet := s.decodeNumSet(numSet)
	s.mutex.Unlock()

	messages, err := s.server.db.GetMessagesByNumSet(s.ctx, selectedMailboxID, decodedNumSet)
	if err != nil {
		return s.internalError("failed to retrieve messages: %v", err)
	}
	if len(messages) == 0 {
		return nil
	}

	// // CONDSTORE filtering - does not require s.mutex
	// _, hasCondStore := s.server.caps[imap.CapCondStore]
	// if hasCondStore && options.ChangedSince > 0 {
	// 	s.Log("[FETCH] CONDSTORE: FETCH with CHANGEDSINCE %d", options.ChangedSince)
	// 	var filteredMessages []db.Message

	// 	for _, msg := range messages {
	// 		var highestModSeq int64
	// 		highestModSeq = msg.CreatedModSeq

	// 		if msg.UpdatedModSeq != nil && *msg.UpdatedModSeq > highestModSeq {
	// 			highestModSeq = *msg.UpdatedModSeq
	// 		}

	// 		if msg.ExpungedModSeq != nil && *msg.ExpungedModSeq > highestModSeq {
	// 			highestModSeq = *msg.ExpungedModSeq
	// 		}

	// 		if uint64(highestModSeq) > options.ChangedSince {
	// 			s.Log("[FETCH] CONDSTORE: Including message UID %d with MODSEQ %d > CHANGEDSINCE %d",
	// 				msg.UID, highestModSeq, options.ChangedSince)
	// 			filteredMessages = append(filteredMessages, msg)
	// 		} else {
	// 			s.Log("[FETCH] CONDSTORE: Skipping message UID %d with MODSEQ %d <= CHANGEDSINCE %d",
	// 				msg.UID, highestModSeq, options.ChangedSince)
	// 		}
	// 	}

	// 	messages = filteredMessages
	// }

	for _, msg := range messages {
		s.mutex.Lock()
		sessionTrackerSnapshot := s.sessionTracker
		if s.selectedMailbox == nil || s.selectedMailbox.ID != selectedMailboxID || sessionTrackerSnapshot == nil {
			s.mutex.Unlock()
			s.Log("[FETCH] mailbox unselected or changed during FETCH loop, aborting further messages.")
			return nil
		}
		s.mutex.Unlock()

		if err := s.fetchMessage(w, &msg, options, selectedMailboxID, sessionTrackerSnapshot); err != nil {
			return err
		}
	}
	return nil
}

func (s *IMAPSession) fetchMessage(w *imapserver.FetchWriter, msg *db.Message, options *imap.FetchOptions, selectedMailboxID int64, sessionTracker *imapserver.SessionTracker) error {
	s.Log("[FETCH] fetching message UID %d SEQNUM %d", msg.UID, msg.Seq)
	encodedSeqNum := sessionTracker.EncodeSeqNum(msg.Seq)

	if encodedSeqNum == 0 {
		return nil
	}

	markSeen := false
	for _, bs := range options.BodySection {
		if !bs.Peek {
			markSeen = true
			break
		}
	}
	if markSeen {
		newFlagsComplete, _, err := s.server.db.AddMessageFlags(s.ctx, msg.UID, selectedMailboxID, []imap.Flag{imap.FlagSeen})
		if err != nil {
			s.Log("[FETCH] failed to set \\Seen flag for message UID %d: %v", msg.UID, err)
		} else {
			systemFlags, customKeywords := db.SplitFlags(newFlagsComplete)
			msg.BitwiseFlags = db.FlagsToBitwise(systemFlags)
			msg.CustomFlags = customKeywords
		}
	}

	m := w.CreateMessage(encodedSeqNum)
	if m == nil {
		// This indicates an issue with the imapserver library or FetchWriter.
		return fmt.Errorf("imapserver: FetchWriter.CreateMessage returned nil for seq %d (UID %d)", encodedSeqNum, msg.UID)
	}
	// Ensure m.Close() is called for this message, even if errors occur mid-processing.
	defer func() {
		if closeErr := m.Close(); closeErr != nil {
			s.Log("[FETCH] error closing FetchResponseWriter for UID %d (seq %d): %v", msg.UID, encodedSeqNum, closeErr)
		}
	}()

	if err := s.writeBasicMessageData(m, msg, options); err != nil {
		return err
	}

	if !msg.IsUploaded {
		s.Log("[FETCH] UID %d is not yet uploaded, returning flags only", msg.UID)
		return nil
	}

	if options.Envelope {
		if err := s.writeEnvelope(m, msg.UID, selectedMailboxID); err != nil {
			return err
		}
	}

	if options.BodyStructure != nil {
		if err := s.writeBodyStructure(m, &msg.BodyStructure); err != nil {
			return err
		}
	}

	if len(options.BodySection) > 0 || len(options.BinarySection) > 0 || len(options.BinarySectionSize) > 0 {
		var bodyData []byte
		var err error
		bodyData, err = s.getMessageBody(msg)
		if err != nil {
			s.Log("[FETCH] Failed to get message body for UID %d: %v", msg.UID, err)
		}

		if len(options.BodySection) > 0 {
			if err := s.handleBodySections(m, bodyData, options, msg, selectedMailboxID); err != nil {
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

	// if options.ModSeq {
	// 	var highestModSeq int64
	// 	highestModSeq = msg.CreatedModSeq

	// 	if msg.UpdatedModSeq != nil && *msg.UpdatedModSeq > highestModSeq {
	// 		highestModSeq = *msg.UpdatedModSeq
	// 	}

	// 	if msg.ExpungedModSeq != nil && *msg.ExpungedModSeq > highestModSeq {
	// 		highestModSeq = *msg.ExpungedModSeq
	// 	}

	// 	s.Log("[FETCH] writing MODSEQ %d for message UID %d", highestModSeq, msg.UID)

	// 	m.WriteModSeq(uint64(highestModSeq))
	// }

	return nil
}

// Fetch helper to write basic message data (FLAGS, UID, INTERNALDATE, RFC822.SIZE)
func (s *IMAPSession) writeBasicMessageData(m *imapserver.FetchResponseWriter, msg *db.Message, options *imap.FetchOptions) error {
	if options.Flags {
		allFlags := db.BitwiseToFlags(msg.BitwiseFlags) // System flags

		for _, customFlag := range msg.CustomFlags {
			allFlags = append(allFlags, imap.Flag(customFlag))
		}
		m.WriteFlags(allFlags)
	}
	if options.UID {
		m.WriteUID(msg.UID)
	}
	if options.InternalDate {
		m.WriteInternalDate(msg.InternalDate.UTC())
	}
	if options.RFC822Size {
		m.WriteRFC822Size(int64(msg.Size))
	}
	return nil
}

// Fetch helper to write the envelope for a message
func (s *IMAPSession) writeEnvelope(m *imapserver.FetchResponseWriter, messageUID imap.UID, mailboxID int64) error {
	envelope, err := s.server.db.GetMessageEnvelope(s.ctx, messageUID, mailboxID)
	if err != nil {
		return s.internalError("failed to retrieve envelope for message UID %d: %v", messageUID, err)
	}
	m.WriteEnvelope(envelope)
	return nil
}

// Fetch helper to write the body structure for a message
func (s *IMAPSession) writeBodyStructure(m *imapserver.FetchResponseWriter, bodyStructure *imap.BodyStructure) error {
	m.WriteBodyStructure(*bodyStructure) // Use the already deserialized BodyStructure
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
func (s *IMAPSession) handleBodySections(w *imapserver.FetchResponseWriter, bodyData []byte, options *imap.FetchOptions, msg *db.Message, selectedMailboxID int64) error {
	for _, section := range options.BodySection {
		var sectionContent []byte

		// Check if this is a request for the main BODY[HEADER] (i.e., section specifier is HEADER and part is empty)
		isMainHeaderRequest := section.Specifier == imap.PartSpecifierHeader && (len(section.Part) == 0)

		// Check if this is a request for the main BODY[TEXT] (i.e., section specifier is TEXT and part is empty)
		isMainBodyTextRequest := section.Specifier == imap.PartSpecifierText && (len(section.Part) == 0)

		if isMainHeaderRequest {
			// Attempt to use the pre-extracted headers from message_contents
			headersText, dbErr := s.server.db.GetMessageHeaders(s.ctx, msg.UID, selectedMailboxID)
			if dbErr == nil && headersText != "" {
				sectionContent = []byte(headersText)
				s.Log("[FETCH] UID %d: Served BODY[HEADER] from message_contents.headers", msg.UID)
			} else {
				if dbErr != nil {
					s.Log("[FETCH] UID %d: Failed to get headers from DB for BODY[HEADER] ('%v'). Falling back to raw extraction.", msg.UID, dbErr)
				} else {
					s.Log("[FETCH] UID %d: Headers from DB for BODY[HEADER] are empty. Falling back to raw extraction.", msg.UID)
				}
				if bodyData != nil {
					sectionContent = imapserver.ExtractBodySection(bytes.NewReader(bodyData), section)
				} else {
					s.Log("[FETCH] UID %d: Cannot fall back to raw extraction for BODY[HEADER] because raw bodyData is nil.", msg.UID)
					sectionContent = []byte{} // IMAP expects NIL or empty literal for missing part
				}
			}
		} else if isMainBodyTextRequest {
			// Attempt to use the pre-extracted text_body from message_contents
			textBody, dbErr := s.server.db.GetMessageTextBody(s.ctx, msg.UID, selectedMailboxID)
			if dbErr == nil {
				sectionContent = []byte(textBody)
				s.Log("[FETCH] UID %d: Served BODY[TEXT] from message_contents.text_body", msg.UID)
			} else {
				// Log the error and fall back to extracting from the raw message body (bodyData)
				s.Log("[FETCH] UID %d: Failed to get text_body from DB for BODY[TEXT] ('%v'). Falling back to raw extraction.", msg.UID, dbErr)
				if bodyData != nil {
					sectionContent = imapserver.ExtractBodySection(bytes.NewReader(bodyData), section)
				} else {
					s.Log("[FETCH] UID %d: Cannot fall back to raw extraction for BODY[TEXT] because raw bodyData is nil.", msg.UID)
					sectionContent = []byte{} // IMAP expects NIL or empty literal for missing part
				}
			}
		} else {
			// For all other body sections (e.g., BODY[HEADER], BODY[1.MIME], BODY[<n>.TEXT])
			// use the raw message data and the library's extraction logic.
			if bodyData != nil {
				sectionContent = imapserver.ExtractBodySection(bytes.NewReader(bodyData), section)
			} else {
				s.Log("[FETCH] UID %d: Cannot extract body section %v because raw bodyData is nil.", msg.UID, section)
				sectionContent = []byte{} // IMAP expects NIL or empty literal for missing part
			}
		}

		wc := w.WriteBodySection(section, int64(len(sectionContent)))
		_, writeErr := wc.Write(sectionContent)
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

func (s *IMAPSession) getMessageBody(msg *db.Message) ([]byte, error) {
	if msg.IsUploaded {
		// Try cache first
		data, err := s.server.cache.Get(msg.ContentHash)
		if err == nil && data != nil {
			s.Log("[FETCH] cache hit for UID %d", msg.UID)
			return data, nil
		}

		// Fallback to S3
		s.Log("[FETCH] cache miss fetching UID %d from S3 (%s)", msg.UID, msg.ContentHash)
		reader, err := s.server.s3.Get(msg.ContentHash)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve message UID %d from S3: %v", msg.UID, err)
		}
		defer reader.Close()
		data, err = io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		_ = s.server.cache.Put(msg.ContentHash, data)
		return data, nil
	}

	// If not uploaded to S3, fetch from local disk
	s.Log("[FETCH] fetching not yet uploaded message UID %d from disk", msg.UID)
	data, err := s.server.uploader.GetLocalFile(msg.ContentHash)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve message UID %d from disk: %v", msg.UID, err)
	}
	if data == nil {
		return nil, fmt.Errorf("message UID %d not found on disk", msg.UID)
	}
	return data, nil
}
