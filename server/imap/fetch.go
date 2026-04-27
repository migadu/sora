package imap

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/storage"

	"github.com/migadu/sora/pkg/metrics"
)

// safeExtractBodySection wraps imapserver.ExtractBodySection with panic recovery.
// For BODY[] requests on malformed messages, returns the full body data.
// This follows the email server principle: store and return what you have, let the client handle parsing.
func safeExtractBodySection(bodyData []byte, section *imap.FetchItemBodySection) []byte {
	// Capture panics from the MIME parser
	defer func() {
		if recover() != nil {
			// MIME parser panicked - this is rare but handled
		}
	}()

	// Try to extract the requested section
	result := imapserver.ExtractBodySection(bytes.NewReader(bodyData), section)

	// For BODY[] (full message), if extraction returns empty but we have body data,
	// it means MIME parsing failed silently. Return the raw body so clients can see the content.
	// For other sections (BODY[TEXT], BODY[1], etc.), empty is valid (part doesn't exist).
	if len(result) == 0 && len(section.Part) == 0 && section.Specifier == imap.PartSpecifierNone && len(bodyData) > 0 {
		return bodyData
	}

	return result
}

// safeExtractBinarySection wraps imapserver.ExtractBinarySection with panic recovery.
func safeExtractBinarySection(bodyData []byte, section *imap.FetchItemBinarySection) []byte {
	defer func() {
		if recover() != nil {
			// MIME parser panicked - return empty
		}
	}()

	return imapserver.ExtractBinarySection(bytes.NewReader(bodyData), section)
}

// safeExtractBinarySectionSize wraps imapserver.ExtractBinarySectionSize with panic recovery.
func safeExtractBinarySectionSize(bodyData []byte, section *imap.FetchItemBinarySectionSize) uint32 {
	defer func() {
		if recover() != nil {
			// MIME parser panicked - return 0
		}
	}()

	return imapserver.ExtractBinarySectionSize(bytes.NewReader(bodyData), section)
}

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
	recordMetrics := func(status string) {
		metrics.CommandsTotal.WithLabelValues("imap", "FETCH", status).Inc()
		metrics.CommandDuration.WithLabelValues("imap", "FETCH").Observe(time.Since(start).Seconds())
	}

	// First, safely read necessary session state and decode the sequence numbers all within a single read lock
	var selectedMailboxID int64
	var sessionTrackerSnapshot *imapserver.SessionTracker
	var decodedNumSet imap.NumSet

	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.WarnLog("failed to acquire read lock within timeout")
		recordMetrics("failure")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}

	if s.selectedMailbox == nil {
		release()
		s.DebugLog("no mailbox selected")
		recordMetrics("failure")
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

	needsBodyStructure := options.BodyStructure != nil

	// Check if mailbox changed IMMEDIATELY after acquiring the read lock.
	if modSeqSnapshot > 0 && s.currentHighestModSeq.Load() > modSeqSnapshot {
		s.WarnLog("mailbox changed during FETCH operation startup", "old_modseq", modSeqSnapshot, "new_modseq", s.currentHighestModSeq.Load())
		if _, isSeqSet := numSet.(imap.SeqSet); isSeqSet {
			// Re-decode to ensure consistency before we lock-in the streaming pipeline
			decodedNumSet = s.decodeNumSet(numSet)
		}
	}

	// Determine if this FETCH implicitly marks messages as \Seen (any non-PEEK body section)
	markSeen := false
	for _, bs := range options.BodySection {
		if !bs.Peek {
			markSeen = true
			break
		}
	}

	if sessionTrackerSnapshot == nil {
		s.DebugLog("session tracker is nil, cannot process messages")
		return nil
	}

	var totalBytesFetched int64
	var writeErr error

	cb := func(messages []db.Message) error {
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

		if len(messages) == 0 {
			return nil
		}

		if markSeen {
			var uidsToMarkSeen []imap.UID
			for _, msg := range messages {
				seen := false
				systemFlags, _ := db.SplitFlags(db.BitwiseToFlags(msg.BitwiseFlags))
				for _, flag := range systemFlags {
					if flag == imap.FlagSeen {
						seen = true
						break
					}
				}
				if !seen {
					uidsToMarkSeen = append(uidsToMarkSeen, msg.UID)
				}
			}

			if len(uidsToMarkSeen) > 0 {
				_, err := s.server.rdb.AddMessageFlagsBatchWithRetry(s.ctx, uidsToMarkSeen, selectedMailboxID, []imap.Flag{imap.FlagSeen})
				if err != nil {
					s.DebugLog("failed to batch mark messages as seen", "error", err)
				} else {
					// Update in-memory models immediately so the fetch response has the flag
					for i := range messages {
						seen := false
						flags := db.BitwiseToFlags(messages[i].BitwiseFlags)
						for _, f := range flags {
							if f == imap.FlagSeen {
								seen = true
								break
							}
						}
						if !seen {
							messages[i].BitwiseFlags = db.FlagsToBitwise(append(flags, imap.FlagSeen))
						}
					}
				}
			}
		}

		for _, msg := range messages {
			totalBytesFetched += int64(msg.Size)
			metrics.MessageThroughput.WithLabelValues("imap", "fetched", "success").Inc()
			if s.IMAPUser != nil {
				metrics.TrackDomainMessage("imap", s.IMAPUser.Domain(), "fetched")
			}
			// Use the previously captured sessionTrackerSnapshot for all messages
			if err := s.writeMessageFetchData(w, &msg, options, selectedMailboxID, sessionTrackerSnapshot); err != nil {
				writeErr = err
				return err
			}
		}
		return nil
	}

	err := s.server.rdb.StreamMessagesByNumSetWithRetry(s.ctx, selectedMailboxID, decodedNumSet, cb, needsBodyStructure)
	if writeErr != nil {
		// Bypass explicit metric tracking for socket disconnections, identically to pre-streaming behavior
		return writeErr
	}
	if err != nil {
		recordMetrics("failure")
		return s.internalError("failed to retrieve messages: %v", err)
	}

	if s.IMAPUser != nil {
		metrics.TrackDomainBytes("imap", s.IMAPUser.Domain(), "out", totalBytesFetched)
	}

	recordMetrics("success")
	return nil
}

// writeMessageFetchData handles writing all FETCH data items for a single message.
func (s *IMAPSession) writeMessageFetchData(w *imapserver.FetchWriter, msg *db.Message, options *imap.FetchOptions, selectedMailboxID int64, sessionTracker *imapserver.SessionTracker) error {
	s.DebugLog("fetching message", "uid", msg.UID, "seq", msg.Seq)

	// ARCHITECTURE DECISION: Use database sequence numbers directly, not sessionTracker.EncodeSeqNum().
	//
	// Sequence numbers are computed dynamically via ROW_NUMBER() OVER (ORDER BY uid) at query time,
	// ensuring they always reflect the canonical mailbox state without relying on cached tables.
	//
	// Why NOT EncodeSeqNum:
	//   1. EncodeSeqNum is designed for in-memory servers that track deltas from a snapshot.
	//      Our server uses PostgreSQL as the authority — applying EncodeSeqNum on top of
	//      dynamically-computed sequences causes off-by-one errors.
	//   2. The go-imap MailboxTracker/SessionTracker pair translates from an initial snapshot
	//      through in-flight expunges.  Our database queries already compute correct positions,
	//      making the tracker layer redundant for sequence number translation.
	//
	// Trade-off: if a concurrent EXPUNGE changes sequence positions between the DB query and the
	// response write, the seqnums in THIS response may not match the client's pre-expunge
	// view.  The Poll mechanism detects desyncs and forces a reconnection (BYE) in extreme
	// cases.  In practice this race is rare because expunge notifications are delivered to
	// clients before subsequent FETCH responses via the go-imap write goroutine's poll cycle.
	//
	// This design is validated by TestIMAP_SequenceNumberConsistency_* in
	// integration_tests/imap/sequence_number_consistency_test.go.
	seqNum := msg.Seq

	if seqNum == 0 {
		// Sequence number should never be 0 for valid messages
		s.DebugLog("skipping message with invalid sequence number", "uid", msg.UID, "seq", msg.Seq)
		return nil
	}

	// Removed individual markSeen logic here because it is now batched before iteration.

	m := w.CreateMessage(seqNum)
	if m == nil {
		// This indicates an issue with the imapserver library or FetchWriter.
		return fmt.Errorf("imapserver: FetchWriter.CreateMessage returned nil for seq %d (UID %d)", seqNum, msg.UID)
	}
	// Ensure m.Close() is called for this message, even if errors occur mid-processing.
	defer func() {
		if closeErr := m.Close(); closeErr != nil {
			s.DebugLog("error closing FetchResponseWriter", "uid", msg.UID, "seq", seqNum, "error", closeErr)
		}
	}()

	if err := s.writeBasicMessageData(m, msg, options); err != nil {
		return err
	}

	if options.Envelope {
		if err := s.writeEnvelope(m, msg); err != nil {
			return err
		}
	}
	if options.BodyStructure != nil {
		var bs *imap.BodyStructure

		// Use pre-loaded body structure from the bulk query if available,
		// otherwise lazy-fetch it (fallback for code paths that don't pre-load).
		if msg.BodyStructure != nil {
			bs = msg.BodyStructure
		} else {
			var err error
			bs, err = s.server.rdb.GetMessageBodyStructureWithRetry(s.ctx, msg.UID, selectedMailboxID)
			if err != nil {
				s.WarnLog("failed to fetch body structure, using fallback", "uid", msg.UID, "error", err)
				fallback := &imap.BodyStructureSinglePart{
					Type:     "text",
					Subtype:  "plain",
					Size:     uint32(msg.Size),
					Extended: &imap.BodyStructureSinglePartExt{},
				}
				var fallbackBS imap.BodyStructure = fallback
				bs = &fallbackBS
			}
		}

		if options.BodyStructure.Extended {
			extended := ensureExtendedBodyStructure(*bs)
			bs = &extended
		}
		if err := s.writeBodyStructure(m, bs); err != nil {
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

func (s *IMAPSession) writeEnvelope(m *imapserver.FetchResponseWriter, msg *db.Message) error {
	envelope, err := db.BuildEnvelope(msg)
	if err != nil {
		return s.internalError("failed to build envelope for message UID %d: %v", msg.UID, err)
	}
	m.WriteEnvelope(envelope)
	return nil
}

// ensureExtendedBodyStructure ensures that the Extended field is populated
// for both single-part and multi-part body structures. This is needed because
// older messages in the database may not have the Extended field populated,
// but clients requesting BODYSTRUCTURE (extended) require it.
func ensureExtendedBodyStructure(bs imap.BodyStructure) imap.BodyStructure {
	switch v := bs.(type) {
	case *imap.BodyStructureSinglePart:
		if v.Extended == nil {
			// Create a minimal extended structure
			v.Extended = &imap.BodyStructureSinglePartExt{
				Disposition: nil, // Unknown
				Language:    nil, // Unknown
				Location:    "",  // Unknown
			}
		}
		return v
	case *imap.BodyStructureMultiPart:
		if v.Extended == nil {
			// Create a minimal extended structure
			v.Extended = &imap.BodyStructureMultiPartExt{
				Params:      make(map[string]string), // Empty params
				Disposition: nil,                     // Unknown
				Language:    nil,                     // Unknown
				Location:    "",                      // Unknown
			}
		}
		// Recursively ensure children also have Extended fields
		for i, child := range v.Children {
			v.Children[i] = ensureExtendedBodyStructure(child)
		}
		return v
	default:
		return bs
	}
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
		// Graceful degradation: return empty binary sections instead of failing the
		// entire multi-message FETCH. This prevents one broken message (missing S3
		// content, etc.) from making the whole mailbox listing fail for webmail clients.
		s.WarnLog("failed to load message body, returning empty binary sections", "uid", msg.UID, "error", err)
	}

	for _, section := range options.BinarySection {
		var buf []byte
		if *bodyData != nil {
			buf = safeExtractBinarySection(*bodyData, section)
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
		// Graceful degradation: return zero sizes instead of failing the entire FETCH.
		s.WarnLog("failed to load message body, returning zero binary section sizes", "uid", msg.UID, "error", err)
	}

	for _, section := range options.BinarySectionSize {
		var n uint32
		if *bodyData != nil {
			n = safeExtractBinarySectionSize(*bodyData, section)
		}
		w.WriteBinarySectionSize(section, n)
	}
	return nil
}

func (s *IMAPSession) handleBodySections(w *imapserver.FetchResponseWriter, bodyData *[]byte, bodyDataFetched *bool, options *imap.FetchOptions, msg *db.Message, selectedMailboxID int64) error {
	for _, section := range options.BodySection {
		var sectionContent []byte

		if loadErr := s.ensureBodyDataLoaded(msg, bodyData, bodyDataFetched); loadErr != nil {
			// Graceful degradation: return empty body sections instead of failing
			// the entire multi-message FETCH. This prevents one broken message
			// (missing S3 content, 0-byte message, etc.) from making the whole
			// mailbox listing fail for webmail clients like Roundcube/SOGo.
			s.WarnLog("failed to load message body, returning empty body section", "uid", msg.UID, "error", loadErr)
		}

		if *bodyData != nil { // Only extract if bodyData was successfully loaded
			// Extract section. If MIME parsing fails/panics, safeExtractBodySection handles it gracefully.
			// We return whatever the extractor gives us - email servers should be transparent conduits.
			sectionContent = safeExtractBodySection(*bodyData, section)
		} else {
			s.DebugLog("body data is nil, returning empty", "uid", msg.UID)
			// sectionContent remains nil, will be set to []byte{} below
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
		// Try cache first (nil-safe: cache is optional and not configured in tests).
		if s.server.cache != nil {
			if cacheData, cacheErr := s.server.cache.Get(msg.ContentHash); cacheErr == nil && cacheData != nil {
				// Validate cached data is not empty — a 0-byte cache file would
				// otherwise be served as a "hit", returning an empty body to the
				// client.  Fall through to S3 so the real content can be fetched.
				if len(cacheData) == 0 {
					s.WarnLog("cache contains empty body, falling through to S3", "uid", msg.UID, "content_hash", msg.ContentHash)
				} else {
					s.DebugLog("cache hit", "uid", msg.UID)
					if s.memTracker != nil {
						if allocErr := s.memTracker.Allocate(int64(len(cacheData))); allocErr != nil {
							metrics.SessionMemoryLimitExceeded.WithLabelValues("imap", s.server.name, s.server.hostname).Inc()
							return nil, fmt.Errorf("session memory limit exceeded: %v", allocErr)
						}
					}
					return cacheData, nil
				}
			}
		}

		// Fallback to S3
		s.DebugLog("cache miss, fetching from S3", "uid", msg.UID, "content_hash", msg.ContentHash)
		// Use the stored S3 key components from the message record to prevent race conditions
		// if the user's primary email has changed since the message was stored.
		if msg.S3Domain == "" || msg.S3Localpart == "" {
			return nil, fmt.Errorf("message UID %d is missing S3 key information", msg.UID)
		}
		s3Key := helpers.NewS3Key(msg.S3Domain, msg.S3Localpart, msg.ContentHash)

		// s3GetWithRetryPanic wraps GetWithRetry so that a nil-client panic
		// (e.g. in test environments using &storage.S3Storage{}) is converted
		// to an error rather than propagating and killing the connection goroutine.
		var reader io.ReadCloser
		var s3GetErr error
		func() {
			defer func() {
				if r := recover(); r != nil {
					s3GetErr = fmt.Errorf("S3 get panicked: %v", r)
				}
			}()
			reader, s3GetErr = s.server.s3.GetWithRetry(s.server.appCtx, s3Key)
		}()
		if s3GetErr != nil {
			s.DebugLog("S3 GetWithRetry failed", "uid", msg.UID, "s3_key", s3Key, "error", s3GetErr)
			// S3 is unavailable — fall back to the local disk file if the uploader
			// still has it.  This covers test environments (where S3 is a no-op stub)
			// and transient S3 outages where the upload worker has not yet run.
			if s.server.uploader != nil {
				filePath := s.server.uploader.FilePath(msg.ContentHash, msg.AccountID)
				if diskData, diskErr := os.ReadFile(filePath); diskErr == nil {
					s.DebugLog("S3 unavailable, served from local disk", "uid", msg.UID)
					return diskData, nil
				}
			}
			return nil, fmt.Errorf("message UID %d: %w: %v", msg.UID, storage.ErrRetrieveFailed, s3GetErr)
		}
		defer reader.Close()
		data, err := io.ReadAll(reader)
		if err != nil {
			s.DebugLog("failed to read S3 response", "uid", msg.UID, "error", err)
			return nil, err
		}

		// Validate we got data
		if len(data) == 0 {
			s.WarnLog("S3 returned empty data", "uid", msg.UID, "s3_key", s3Key, "expected_size", msg.Size,
				"get_breaker_state", s.server.s3.GetGetBreakerState())
			return nil, fmt.Errorf("message UID %d (expected %d bytes): %w", msg.UID, msg.Size, storage.ErrEmptyData)
		}

		s.DebugLog("successfully fetched from S3", "uid", msg.UID, "size", len(data))

		// Track memory usage for S3 data
		if s.memTracker != nil {
			if allocErr := s.memTracker.Allocate(int64(len(data))); allocErr != nil {
				metrics.SessionMemoryLimitExceeded.WithLabelValues("imap", s.server.name, s.server.hostname).Inc()
				return nil, fmt.Errorf("session memory limit exceeded: %v", allocErr)
			}
		}

		// Store in cache if available (nil-safe).
		if s.server.cache != nil {
			_ = s.server.cache.Put(msg.ContentHash, data)
		}
		return data, nil
	}

	// If not uploaded to S3, fetch from local disk
	if s.server.uploader == nil {
		return nil, fmt.Errorf("message UID %d not yet uploaded and no uploader configured", msg.UID)
	}
	s.DebugLog("fetching not yet uploaded message from disk", "uid", msg.UID)
	filePath := s.server.uploader.FilePath(msg.ContentHash, msg.AccountID)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("message UID %d from disk: %w: %v", msg.UID, storage.ErrRetrieveFailed, err)
	}
	if data == nil {
		return nil, fmt.Errorf("message UID %d not found on disk", msg.UID)
	}

	// Track memory usage for disk data
	if s.memTracker != nil {
		if allocErr := s.memTracker.Allocate(int64(len(data))); allocErr != nil {
			metrics.SessionMemoryLimitExceeded.WithLabelValues("imap", s.server.name, s.server.hostname).Inc()
			return nil, fmt.Errorf("session memory limit exceeded: %v", allocErr)
		}
	}

	return data, nil
}
