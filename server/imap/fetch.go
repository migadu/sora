package imap

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/textproto"
	"github.com/migadu/sora/db"

	tp "net/textproto"
)

const crlf = "\r\n"

func extractPartial(b []byte, partial *imap.SectionPartial) []byte {
	if partial == nil {
		return b
	}

	end := partial.Offset + partial.Size
	if partial.Offset > int64(len(b)) {
		return nil
	}
	if end > int64(len(b)) {
		end = int64(len(b))
	}
	return b[partial.Offset:end]
}

func (s *IMAPSession) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	// First, safely read necessary session state and decode the sequence numbers all within a single read lock
	var selectedMailboxID int64
	var sessionTrackerSnapshot *imapserver.SessionTracker
	var decodedNumSet imap.NumSet

	// Acquire read mutex to safely read all session state in one go
	acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.Log("[FETCH] Failed to acquire read lock within timeout")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}
	defer cancel()

	if s.selectedMailbox == nil {
		s.mutex.RUnlock()
		s.Log("[FETCH] no mailbox selected")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "No mailbox selected",
		}
	}

	selectedMailboxID = s.selectedMailbox.ID
	sessionTrackerSnapshot = s.sessionTracker
	
	// Capture modseq before unlocking
	modSeqSnapshot := s.currentHighestModSeq.Load()
	
	// Use our helper method that assumes the mutex is held (read lock is sufficient here)
	decodedNumSet = s.decodeNumSetLocked(numSet)
	s.mutex.RUnlock()
	
	messages, err := s.server.db.GetMessagesByNumSet(s.ctx, selectedMailboxID, decodedNumSet)
	if err != nil {
		return s.internalError("failed to retrieve messages: %v", err)
	}
	
	// Check if mailbox changed during our operation
	if modSeqSnapshot > 0 && s.currentHighestModSeq.Load() > modSeqSnapshot {
		s.Log("[FETCH] WARNING: Mailbox changed during FETCH operation (modseq %d -> %d)", 
			modSeqSnapshot, s.currentHighestModSeq.Load())
		// For sequence sets, this could mean we fetched wrong messages
		if _, isSeqSet := numSet.(imap.SeqSet); isSeqSet {
			// Re-decode and re-fetch to ensure consistency
			decodedNumSet = s.decodeNumSet(numSet)
			messages, err = s.server.db.GetMessagesByNumSet(s.ctx, selectedMailboxID, decodedNumSet)
			if err != nil {
				return s.internalError("failed to retrieve messages: %v", err)
			}
		}
	}
	
	if len(messages) == 0 {
		return nil
	}

	// CONDSTORE functionality - only process if capability is enabled
	if s.server.caps.Has(imap.CapCondStore) && options.ChangedSince > 0 {
		s.Log("[FETCH] CONDSTORE: FETCH with CHANGEDSINCE %d", options.ChangedSince)
		var filteredMessages []db.Message

		for _, msg := range messages {
			var highestModSeq int64
			highestModSeq = msg.CreatedModSeq

			if msg.UpdatedModSeq != nil && *msg.UpdatedModSeq > highestModSeq {
				highestModSeq = *msg.UpdatedModSeq
			}

			if msg.ExpungedModSeq != nil && *msg.ExpungedModSeq > highestModSeq {
				highestModSeq = *msg.ExpungedModSeq
			}

			if uint64(highestModSeq) > options.ChangedSince {
				s.Log("[FETCH] CONDSTORE: Including message UID %d with MODSEQ %d > CHANGEDSINCE %d",
					msg.UID, highestModSeq, options.ChangedSince)
				filteredMessages = append(filteredMessages, msg)
			} else {
				s.Log("[FETCH] CONDSTORE: Skipping message UID %d with MODSEQ %d <= CHANGEDSINCE %d",
					msg.UID, highestModSeq, options.ChangedSince)
			}
		}

		messages = filteredMessages
	}

	// We don't need to check mailbox validity again since we'll use the snapshot consistently
	// and will detect any issues with the individual message sequence numbers

	if sessionTrackerSnapshot == nil {
		s.Log("[FETCH] session tracker is nil, cannot process messages")
		return nil
	}

	// Process all messages without repeatedly acquiring the mutex
	for _, msg := range messages {
		// Use the previously captured sessionTrackerSnapshot for all messages
		if err := s.writeMessageFetchData(w, &msg, options, selectedMailboxID, sessionTrackerSnapshot); err != nil {
			return err
		}
	}
	return nil
}

// writeMessageFetchData handles writing all FETCH data items for a single message.
func (s *IMAPSession) writeMessageFetchData(w *imapserver.FetchWriter, msg *db.Message, options *imap.FetchOptions, selectedMailboxID int64, sessionTracker *imapserver.SessionTracker) error {
	s.Log("[FETCH] fetching message UID %d SEQNUM %d", msg.UID, msg.Seq)
	encodedSeqNum := sessionTracker.EncodeSeqNum(msg.Seq)

	if encodedSeqNum == 0 {
		// The sequence number from the database doesn't map to a valid client sequence number
		// This can happen when the mailbox has been modified by another session
		s.Log("[FETCH] Skipping message UID %d with unmappable sequence number %d", msg.UID, msg.Seq)
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

	// Declare bodyData and a flag to track if it has been fetched.
	// These will be passed by pointer to handlers so they can lazily load it once if needed.
	var bodyData []byte
	var bodyDataFetched bool

	if len(options.BodySection) > 0 || len(options.BinarySection) > 0 || len(options.BinarySectionSize) > 0 {
		if len(options.BodySection) > 0 {
			if err := s.handleBodySections(m, &bodyData, &bodyDataFetched, options, msg, selectedMailboxID); err != nil {
				return err
			}
		}

		if len(options.BinarySection) > 0 {
			if err := s.handleBinarySections(m, &bodyData, &bodyDataFetched, options, msg); err != nil {
				return err
			}
		}

		if len(options.BinarySectionSize) > 0 {
			if err := s.handleBinarySectionSize(m, &bodyData, &bodyDataFetched, options, msg); err != nil {
				return err
			}
		}
	}

	if options.ModSeq {
		var highestModSeq int64
		highestModSeq = msg.CreatedModSeq

		if msg.UpdatedModSeq != nil && *msg.UpdatedModSeq > highestModSeq {
			highestModSeq = *msg.UpdatedModSeq
		}

		if msg.ExpungedModSeq != nil && *msg.ExpungedModSeq > highestModSeq {
			highestModSeq = *msg.ExpungedModSeq
		}

		s.Log("[FETCH] writing MODSEQ %d for message UID %d", highestModSeq, msg.UID)

		m.WriteModSeq(uint64(highestModSeq))
	}

	return nil
}

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

func (s *IMAPSession) writeEnvelope(m *imapserver.FetchResponseWriter, messageUID imap.UID, mailboxID int64) error {
	envelope, err := s.server.db.GetMessageEnvelope(s.ctx, messageUID, mailboxID)
	if err != nil {
		return s.internalError("failed to retrieve envelope for message UID %d: %v", messageUID, err)
	}
	m.WriteEnvelope(envelope)
	return nil
}

func (s *IMAPSession) writeBodyStructure(m *imapserver.FetchResponseWriter, bodyStructure *imap.BodyStructure) error {
	m.WriteBodyStructure(*bodyStructure) // Use the already deserialized BodyStructure
	return nil
}

func (s *IMAPSession) ensureBodyDataLoaded(msg *db.Message, bodyData *[]byte, bodyDataFetched *bool) error {
	if !*bodyDataFetched {
		var fetchErr error
		*bodyData, fetchErr = s.getMessageBody(msg)
		*bodyDataFetched = true // Mark as fetched even if error or nil data, to prevent re-fetching.
		if fetchErr != nil {
			s.Log("[FETCH] UID %d: Failed to get message body: %v", msg.UID, fetchErr)
			return fetchErr // Propagate error to allow handlers to decide how to proceed (e.g., return NIL)
		}
	}
	return nil
}

func (s *IMAPSession) handleBinarySections(w *imapserver.FetchResponseWriter, bodyData *[]byte, bodyDataFetched *bool, options *imap.FetchOptions, msg *db.Message) error {
	if err := s.ensureBodyDataLoaded(msg, bodyData, bodyDataFetched); err != nil {
		// Logged in ensureBodyDataLoaded. If bodyData is nil or error occurred, subsequent ops will handle it.
	}

	for _, section := range options.BinarySection {
		var buf []byte
		if *bodyData != nil { // Only extract if bodyData was successfully loaded
			buf = imapserver.ExtractBinarySection(bytes.NewReader(*bodyData), section)
		}
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

func (s *IMAPSession) handleBinarySectionSize(w *imapserver.FetchResponseWriter, bodyData *[]byte, bodyDataFetched *bool, options *imap.FetchOptions, msg *db.Message) error {
	if err := s.ensureBodyDataLoaded(msg, bodyData, bodyDataFetched); err != nil {
		// Logged in ensureBodyDataLoaded.
	}

	for _, section := range options.BinarySectionSize {
		var n uint32
		if *bodyData != nil { // Only extract if bodyData was successfully loaded
			n = imapserver.ExtractBinarySectionSize(bytes.NewReader(*bodyData), section)

		}
		w.WriteBinarySectionSize(section, n)
	}
	return nil
}

func (s *IMAPSession) handleBodySections(w *imapserver.FetchResponseWriter, bodyData *[]byte, bodyDataFetched *bool, options *imap.FetchOptions, msg *db.Message, selectedMailboxID int64) error {
	for _, section := range options.BodySection {
		var sectionContent []byte
		var extractionErr error // For errors from imapserver.Extract... functions
		satisfiedFromDB := false

		// Is this a request for specific header fields of the main message? (e.g., BODY[HEADER.FIELDS (SUBJECT FROM)])
		isHeaderFieldsRequest := section.Specifier == imap.PartSpecifierHeader && len(section.HeaderFields) > 0 && len(section.Part) == 0

		// Is this a request for all headers of the main message? (e.g., BODY[HEADER])
		isAllHeadersRequest := section.Specifier == imap.PartSpecifierHeader && len(section.HeaderFields) == 0 && len(section.HeaderFieldsNot) == 0 && len(section.Part) == 0

		// Is this a request for the main body text? (e.g., BODY[TEXT])
		isMainBodyTextRequest := section.Specifier == imap.PartSpecifierText && (len(section.Part) == 0)

		if isHeaderFieldsRequest {
			headersText, dbErr := s.server.db.GetMessageHeaders(s.ctx, msg.UID, selectedMailboxID)
			if dbErr == nil && headersText != "" {
				// Ensure headersText is a valid block for parsing, ending with \r\n if not empty.
				headerBlockToParse := headersText
				if !strings.HasSuffix(headerBlockToParse, crlf) && headerBlockToParse != "" {
					headerBlockToParse += crlf
				}
				parsedDBHeader, parseErr := textproto.ReadHeader(bufio.NewReader(bytes.NewReader([]byte(headerBlockToParse))))
				if parseErr == nil {
					sectionContent, extractionErr = extractRequestedHeaders(parsedDBHeader, section)
					if extractionErr == nil && section.Partial != nil {
						sectionContent = extractPartial(sectionContent, section.Partial)
					}
					satisfiedFromDB = true
					s.Log("[FETCH] UID %d: Served BODY[HEADER.FIELDS (...)] from message_contents.headers", msg.UID)
				} else {
					s.Log("[FETCH] UID %d: Error parsing DB headers for HEADER.FIELDS: %v. Falling back.", msg.UID, parseErr)
					extractionErr = parseErr // Signal to fallback to full body parsing
				}
			} else {
				if dbErr != nil {
					s.Log("[FETCH] UID %d: Failed to get headers from DB for BODY[HEADER.FIELDS] ('%v'). Falling back.", msg.UID, dbErr)
					extractionErr = dbErr // Signal to fallback
				} else {
					s.Log("[FETCH] UID %d: Headers from DB for BODY[HEADER.FIELDS] are empty. Falling back.", msg.UID)
					// extractionErr remains nil, fallback will happen due to !satisfiedFromDB
				}
			}
		} else if isAllHeadersRequest {
			headersText, dbErr := s.server.db.GetMessageHeaders(s.ctx, msg.UID, selectedMailboxID)
			if dbErr == nil && headersText != "" {
				// headersText from DB is the block of headers.
				// It might be "H1:V1" or "H1:V1\r\nH2:V2".
				// We need to ensure its own last line ends with crlf, then add the final separator crlf.
				if !strings.HasSuffix(headersText, crlf) {
					headersText += crlf
				}
				sectionContent = []byte(headersText + crlf)
				if section.Partial != nil {
					sectionContent = extractPartial(sectionContent, section.Partial)
				}
				satisfiedFromDB = true
				s.Log("[FETCH] UID %d: Served BODY[HEADER] from message_contents.headers", msg.UID)
			} else {
				if dbErr != nil {
					s.Log("[FETCH] UID %d: Failed to get headers from DB for BODY[HEADER] ('%v'). Falling back.", msg.UID, dbErr)
				} else {
					s.Log("[FETCH] UID %d: Headers from DB for BODY[HEADER] are empty. Falling back.", msg.UID)
				}
			}
		} else if isMainBodyTextRequest {
			// Attempt to serve BODY[TEXT] from the pre-extracted text_body in the database.
			textBody, dbErr := s.server.db.GetMessageTextBody(s.ctx, msg.UID, selectedMailboxID)

			if dbErr == nil { // DB fetch successful, textBody might be empty or populated.
				isSuspectDueToEncoding := false
				if textBody != "" { // Only suspect if non-empty and potentially encoded.
					if bodyStructureHasEncodedText(msg.BodyStructure) {
						s.Log("[FETCH] UID %d: BODY[TEXT] from DB is non-empty, and original message structure contains encoded text parts. Suspect, will fall back to ensure decoding.", msg.UID)
						isSuspectDueToEncoding = true
					}
				}

				if !isSuspectDueToEncoding {
					sectionContent = []byte(textBody)
					if section.Partial != nil {
						sectionContent = extractPartial(sectionContent, section.Partial)
					}
					satisfiedFromDB = true
					s.Log("[FETCH] UID %d: Served BODY[TEXT] from message_contents.text_body.", msg.UID)
				} else {
					// isSuspectDueToEncoding is true. Fallback will be triggered by satisfiedFromDB = false.
					s.Log("[FETCH] UID %d: text_body from DB for BODY[TEXT] is suspect due to original encoding. Falling back.", msg.UID)
				}
			} else { // dbErr != nil
				s.Log("[FETCH] UID %d: Failed to get text_body from DB for BODY[TEXT] ('%v'). Falling back.", msg.UID, dbErr)
				// satisfiedFromDB remains false. Fallback will occur.
			}
		}

		// Fallback or other section types
		// If not satisfied from DB, or if there was an error extracting from DB-sourced content (extractionErr != nil),
		// or if it's a complex section type that always requires full body.
		if !satisfiedFromDB || extractionErr != nil {
			if loadErr := s.ensureBodyDataLoaded(msg, bodyData, bodyDataFetched); loadErr != nil {
				s.Log("[FETCH] UID %d: Error ensuring body data loaded for section %v: %v", msg.UID, section, loadErr)
				// sectionContent will be nil, handled below
			}

			if *bodyData != nil { // Only extract if bodyData was successfully loaded
				sectionContent = imapserver.ExtractBodySection(bytes.NewReader(*bodyData), section) // section is *FetchItemBodySection
			} else {
				s.Log("[FETCH] UID %d: Body data is nil for section %v. Returning empty.", msg.UID, section)
				// sectionContent remains nil, will be set to []byte{} below
			}
		}

		if sectionContent == nil { // Ensure not nil for WriteBodySection
			sectionContent = []byte{}
		}

		wc := w.WriteBodySection(section, int64(len(sectionContent))) // section is *FetchItemBodySection
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

// extractRequestedHeaders filters headers from a parsedDBHeader based on the section criteria.
// It constructs a new textproto.Header containing only the desired fields and then writes it.
// This approach preserves the original raw formatting of the selected header lines.
func extractRequestedHeaders(parsedDBHeader textproto.Header, section *imap.FetchItemBodySection) ([]byte, error) {
	var rawLinesToOutput [][]byte // Collect raw lines in the desired output order

	// Create a set of fields to exclude for quick lookup (canonical keys)
	excludeSet := make(map[string]struct{})
	for _, notField := range section.HeaderFieldsNot {
		excludeSet[tp.CanonicalMIMEHeaderKey(notField)] = struct{}{}
	}

	if len(section.HeaderFields) > 0 {
		// Specific fields requested. Output in the order requested by the client.
		// Keep track of canonical keys already processed to handle cases like ("Subject", "subject") in request.
		processedCanonicalRequestKeys := make(map[string]struct{})

		for _, reqKey := range section.HeaderFields {
			canonicalReqKey := tp.CanonicalMIMEHeaderKey(reqKey)

			if _, alreadyProcessed := processedCanonicalRequestKeys[canonicalReqKey]; alreadyProcessed {
				continue // Already handled all instances of this canonical key due to a previous request (e.g., "SUBJECT" after "Subject")
			}
			if _, exclude := excludeSet[canonicalReqKey]; exclude {
				processedCanonicalRequestKeys[canonicalReqKey] = struct{}{} // Mark as skipped
				continue
			}

			// FieldsByKey iterates over all occurrences of a header with the given canonical key.
			// These occurrences are iterated in their original relative order from the message.
			fieldsIterator := parsedDBHeader.FieldsByKey(canonicalReqKey)
			for fieldsIterator.Next() {
				// The key from fieldsIterator.Key() is already canonical.
				rawLine, err := fieldsIterator.Raw()
				if err != nil {
					return nil, fmt.Errorf("error getting raw header line for %s: %w", fieldsIterator.Key(), err)
				}
				rawLinesToOutput = append(rawLinesToOutput, rawLine)
			}
			processedCanonicalRequestKeys[canonicalReqKey] = struct{}{}
		}
	} else {
		// All fields requested (e.g., BODY[HEADER.FIELDS ()] or BODY[HEADER]).
		// textproto.Header.Fields() iterates in the original message order.
		fieldsIterator := parsedDBHeader.Fields()
		for fieldsIterator.Next() {
			canonicalKey := fieldsIterator.Key() // Key() from iterator is already canonical
			if _, exclude := excludeSet[canonicalKey]; exclude {
				continue
			}
			rawLine, err := fieldsIterator.Raw()
			if err != nil {
				return nil, fmt.Errorf("error getting raw header line for %s: %w", canonicalKey, err)
			}
			rawLinesToOutput = append(rawLinesToOutput, rawLine)
		}
	}

	// Construct the new Header object by adding raw lines in reverse order
	// so that WriteHeader outputs them in the correct (original/requested) order.
	var newHdr textproto.Header
	for i := len(rawLinesToOutput) - 1; i >= 0; i-- {
		newHdr.AddRaw(rawLinesToOutput[i]) // AddRaw prepends effectively due to WriteHeader's behavior
	}

	var buf bytes.Buffer
	if err := textproto.WriteHeader(&buf, newHdr); err != nil {
		return nil, fmt.Errorf("failed to write filtered header: %w", err)
	}

	return buf.Bytes(), nil
}

// bodyStructureHasEncodedText checks if any text part (text/plain, text/html, etc.)
// within the given body structure uses base64 or quoted-printable encoding.
// This is used to determine if a pre-extracted text_body from the database
// might be undecoded raw content.
func bodyStructureHasEncodedText(bs imap.BodyStructure) bool {
	if bs == nil {
		return false
	}
	switch b := bs.(type) {
	case *imap.BodyStructureSinglePart:
		// Check if it's a text part and uses an encoding that needs decoding for BODY[TEXT].
		// b.MediaType() returns "type/subtype" in lowercase.
		if strings.HasPrefix(b.MediaType(), "text/") &&
			(strings.EqualFold(b.Encoding, "base64") || strings.EqualFold(b.Encoding, "quoted-printable")) {
			return true
		}
	case *imap.BodyStructureMultiPart:
		// Recursively check parts of a multipart message.
		for _, childPart := range b.Children {
			if bodyStructureHasEncodedText(childPart) { // Recurse
				return true
			}
		}
	}
	return false
}
