package imap

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/textproto"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"

	tp "net/textproto"

	"github.com/migadu/sora/pkg/metrics"
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
	start := time.Now()
	success := false
	defer func() {
		status := "failure"
		if success {
			status = "success"
		}
		metrics.CommandsTotal.WithLabelValues("imap", "FETCH", status).Inc()
		metrics.CommandDuration.WithLabelValues("imap", "FETCH").Observe(time.Since(start).Seconds())
	}()

	// First, safely read necessary session state and decode the sequence numbers all within a single read lock
	var selectedMailboxID int64
	var sessionTrackerSnapshot *imapserver.SessionTracker
	var decodedNumSet imap.NumSet

	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.WarnLog("failed to acquire read lock within timeout")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}

	if s.selectedMailbox == nil {
		release()
		s.DebugLog("no mailbox selected")
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
	release()

	messages, err := s.server.rdb.GetMessagesByNumSetWithRetry(s.ctx, selectedMailboxID, decodedNumSet)
	if err != nil {
		return s.internalError("failed to retrieve messages: %v", err)
	}

	// Check if mailbox changed during our operation
	if modSeqSnapshot > 0 && s.currentHighestModSeq.Load() > modSeqSnapshot {
		s.WarnLog("mailbox changed during FETCH operation", "old_modseq", modSeqSnapshot, "new_modseq", s.currentHighestModSeq.Load())
		// For sequence sets, this could mean we fetched wrong messages
		if _, isSeqSet := numSet.(imap.SeqSet); isSeqSet {
			// Re-decode and re-fetch to ensure consistency
			decodedNumSet = s.decodeNumSet(numSet) // This will re-lock, but it's a rare case
			messages, err = s.server.rdb.GetMessagesByNumSetWithRetry(s.ctx, selectedMailboxID, decodedNumSet)
			if err != nil {
				return s.internalError("failed to retrieve messages: %v", err)
			}
		}
	}

	if len(messages) == 0 {
		success = true
		return nil
	}

	// CONDSTORE functionality - only process if capability is enabled
	if s.GetCapabilities().Has(imap.CapCondStore) && options.ChangedSince > 0 {
		s.DebugLog("CONDSTORE FETCH with CHANGEDSINCE", "changed_since", options.ChangedSince)
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
				s.DebugLog("CONDSTORE including message", "uid", msg.UID, "modseq", highestModSeq, "changed_since", options.ChangedSince)
				filteredMessages = append(filteredMessages, msg)
			} else {
				s.DebugLog("CONDSTORE skipping message", "uid", msg.UID, "modseq", highestModSeq, "changed_since", options.ChangedSince)
			}
		}

		messages = filteredMessages
	}

	// We don't need to check mailbox validity again since we'll use the snapshot consistently
	// and will detect any issues with the individual message sequence numbers

	if sessionTrackerSnapshot == nil {
		s.DebugLog("session tracker is nil, cannot process messages")
		return nil
	}

	// Process all messages without repeatedly acquiring the mutex
	var totalBytesFetched int64
	for _, msg := range messages {
		totalBytesFetched += int64(msg.Size)
		metrics.MessageThroughput.WithLabelValues("imap", "fetched", "success").Inc()
		if s.IMAPUser != nil {
			metrics.TrackDomainMessage("imap", s.IMAPUser.Domain(), "fetched")
		}
		// Use the previously captured sessionTrackerSnapshot for all messages
		if err := s.writeMessageFetchData(w, &msg, options, selectedMailboxID, sessionTrackerSnapshot); err != nil {
			return err
		}
	}

	if s.IMAPUser != nil {
		metrics.TrackDomainBytes("imap", s.IMAPUser.Domain(), "out", totalBytesFetched)
	}

	success = true
	return nil
}

// writeMessageFetchData handles writing all FETCH data items for a single message.
func (s *IMAPSession) writeMessageFetchData(w *imapserver.FetchWriter, msg *db.Message, options *imap.FetchOptions, selectedMailboxID int64, sessionTracker *imapserver.SessionTracker) error {
	s.DebugLog("fetching message", "uid", msg.UID, "seq", msg.Seq)
	encodedSeqNum := sessionTracker.EncodeSeqNum(msg.Seq)

	if encodedSeqNum == 0 {
		// The sequence number from the database doesn't map to a valid client sequence number
		// This can happen when the mailbox has been modified by another session
		s.DebugLog("skipping message with unmappable sequence number", "uid", msg.UID, "seq", msg.Seq)
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
		newFlagsComplete, _, err := s.server.rdb.AddMessageFlagsWithRetry(s.ctx, msg.UID, selectedMailboxID, []imap.Flag{imap.FlagSeen})
		if err != nil {
			s.DebugLog("failed to set seen flag", "uid", msg.UID, "error", err)
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
			s.DebugLog("error closing FetchResponseWriter", "uid", msg.UID, "seq", encodedSeqNum, "error", closeErr)
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

	// Defer memory cleanup for this message's body data
	defer func() {
		if bodyDataFetched && bodyData != nil && s.memTracker != nil {
			s.memTracker.Free(int64(len(bodyData)))
		}
	}()

	if len(options.BodySection) > 0 || len(options.BinarySection) > 0 || len(options.BinarySectionSize) > 0 {
		if len(options.BodySection) > 0 {
			if err := s.handleBodySections(m, &bodyData, &bodyDataFetched, options, msg, selectedMailboxID); err != nil {
				return err
			}
		}

		if len(options.BinarySection) > 0 {
			if s.GetCapabilities().Has(imap.CapBinary) {
				if err := s.handleBinarySections(m, &bodyData, &bodyDataFetched, options, msg); err != nil {
					return err
				}
			} else {
				s.DebugLog("BINARY section requests ignored due to capability filtering")
			}
		}

		if len(options.BinarySectionSize) > 0 {
			if s.GetCapabilities().Has(imap.CapBinary) {
				if err := s.handleBinarySectionSize(m, &bodyData, &bodyDataFetched, options, msg); err != nil {
					return err
				}
			} else {
				s.DebugLog("BINARY section size requests ignored due to capability filtering")
			}
		}
	}

	if s.GetCapabilities().Has(imap.CapCondStore) && options.ModSeq {
		var highestModSeq int64
		highestModSeq = msg.CreatedModSeq

		if msg.UpdatedModSeq != nil && *msg.UpdatedModSeq > highestModSeq {
			highestModSeq = *msg.UpdatedModSeq
		}

		if msg.ExpungedModSeq != nil && *msg.ExpungedModSeq > highestModSeq {
			highestModSeq = *msg.ExpungedModSeq
		}

		s.DebugLog("writing MODSEQ", "modseq", highestModSeq, "uid", msg.UID)

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
		// Sanitize flags to remove invalid values (NIL, NULL, etc.) that may have been
		// stored in the database before validation was added
		allFlags = helpers.SanitizeFlags(allFlags)

		// Filter flags to only include those announced during SELECT (RFC 3501 Section 7.2.6)
		// "Any flags that are in a message but not in the FLAGS response MUST NOT be returned in a FETCH FLAGS response"
		if s.announcedFlags != nil {
			filteredFlags := make([]imap.Flag, 0, len(allFlags))
			for _, flag := range allFlags {
				if _, announced := s.announcedFlags[flag]; announced {
					filteredFlags = append(filteredFlags, flag)
				}
			}
			allFlags = filteredFlags
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
	envelope, err := s.server.rdb.GetMessageEnvelopeWithRetry(s.ctx, messageUID, mailboxID)
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
			s.DebugLog("failed to get message body", "uid", msg.UID, "error", fetchErr)
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

		if isHeaderFieldsRequest {
			headersText, dbErr := s.server.rdb.GetMessageHeadersWithRetry(s.ctx, msg.UID, selectedMailboxID)
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
					s.DebugLog("served BODY HEADER.FIELDS from database", "uid", msg.UID)
				} else {
					s.DebugLog("error parsing DB headers for HEADER.FIELDS, falling back", "uid", msg.UID, "error", parseErr)
					extractionErr = parseErr // Signal to fallback to full body parsing
				}
			} else {
				if dbErr != nil {
					s.DebugLog("failed to get headers from DB for BODY HEADER.FIELDS, falling back", "uid", msg.UID, "error", dbErr)
					extractionErr = dbErr // Signal to fallback
				} else {
					s.DebugLog("headers from DB for BODY HEADER.FIELDS are empty, falling back", "uid", msg.UID)
					// extractionErr remains nil, fallback will happen due to !satisfiedFromDB
				}
			}
		} else if isAllHeadersRequest {
			headersText, dbErr := s.server.rdb.GetMessageHeadersWithRetry(s.ctx, msg.UID, selectedMailboxID)
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
				s.DebugLog("served BODY HEADER from database", "uid", msg.UID)
			} else {
				if dbErr != nil {
					s.DebugLog("failed to get headers from DB for BODY HEADER, falling back", "uid", msg.UID, "error", dbErr)
				} else {
					s.DebugLog("headers from DB for BODY HEADER are empty, falling back", "uid", msg.UID)
				}
			}
		}
		// Note: We do NOT serve BODY[TEXT] from the database's text_body field.
		// The text_body field contains decoded plaintext for search/indexing purposes only.
		// BODY[TEXT] must return the raw encoded body as it appears in the original message,
		// which requires fetching and parsing the full message body.

		// Fallback or other section types
		// If not satisfied from DB, or if there was an error extracting from DB-sourced content (extractionErr != nil),
		// or if it's a complex section type that always requires full body.
		if !satisfiedFromDB || extractionErr != nil {
			if loadErr := s.ensureBodyDataLoaded(msg, bodyData, bodyDataFetched); loadErr != nil {
				s.DebugLog("error ensuring body data loaded", "uid", msg.UID, "error", loadErr)
				// sectionContent will be nil, handled below
			}

			if *bodyData != nil { // Only extract if bodyData was successfully loaded
				sectionContent = imapserver.ExtractBodySection(bytes.NewReader(*bodyData), section) // section is *FetchItemBodySection
			} else {
				s.DebugLog("body data is nil, returning empty", "uid", msg.UID)
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
			s.DebugLog("cache hit", "uid", msg.UID)
			// Track memory usage for cached data
			if s.memTracker != nil {
				if allocErr := s.memTracker.Allocate(int64(len(data))); allocErr != nil {
					metrics.SessionMemoryLimitExceeded.WithLabelValues("imap").Inc()
					return nil, fmt.Errorf("session memory limit exceeded: %v", allocErr)
				}
			}
			return data, nil
		}

		// Fallback to S3
		s.DebugLog("cache miss, fetching from S3", "uid", msg.UID, "content_hash", msg.ContentHash)
		// Use the stored S3 key components from the message record to prevent race conditions
		// if the user's primary email has changed since the message was stored.
		if msg.S3Domain == "" || msg.S3Localpart == "" {
			return nil, fmt.Errorf("message UID %d is missing S3 key information", msg.UID)
		}
		s3Key := helpers.NewS3Key(msg.S3Domain, msg.S3Localpart, msg.ContentHash)

		reader, err := s.server.s3.GetWithRetry(s.server.appCtx, s3Key)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve message UID %d from S3: %v", msg.UID, err)
		}
		defer reader.Close()
		data, err = io.ReadAll(reader)
		if err != nil {
			return nil, err
		}

		// Track memory usage for S3 data
		if s.memTracker != nil {
			if allocErr := s.memTracker.Allocate(int64(len(data))); allocErr != nil {
				metrics.SessionMemoryLimitExceeded.WithLabelValues("imap").Inc()
				return nil, fmt.Errorf("session memory limit exceeded: %v", allocErr)
			}
		}

		_ = s.server.cache.Put(msg.ContentHash, data)
		return data, nil
	}

	// If not uploaded to S3, fetch from local disk
	s.DebugLog("fetching not yet uploaded message from disk", "uid", msg.UID)
	filePath := s.server.uploader.FilePath(msg.ContentHash, msg.AccountID)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve message UID %d from disk: %v", msg.UID, err)
	}
	if data == nil {
		return nil, fmt.Errorf("message UID %d not found on disk", msg.UID)
	}

	// Track memory usage for disk data
	if s.memTracker != nil {
		if allocErr := s.memTracker.Allocate(int64(len(data))); allocErr != nil {
			metrics.SessionMemoryLimitExceeded.WithLabelValues("imap").Inc()
			return nil, fmt.Errorf("session memory limit exceeded: %v", allocErr)
		}
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
