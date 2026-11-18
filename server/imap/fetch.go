package imap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"

	"github.com/migadu/sora/pkg/metrics"
)

// errBodyTransientlyUnavailable marks a message body that exists (or will shortly) but
// cannot be retrieved from this node right now. Two causes feed it, both transient:
//   - not yet uploaded: staged for upload, not on local disk here and not in S3 yet
//     (the upload worker will land it shortly); see bodyUploadStillPending.
//   - S3 unavailable: the message is uploaded but S3 is unreachable (network/timeout/
//     5xx/circuit-open) — distinct from a 404/NoSuchKey, which is permanent loss.
//
// The FETCH is answered with NO [UNAVAILABLE] so the client retries, rather than being
// handed an empty body it might act on destructively (e.g. an automated consumer that
// deletes a message after a "successful" but empty read). The wrapping error text
// carries the specific cause for logging.
var errBodyTransientlyUnavailable = errors.New("message body temporarily unavailable")

// bodyOverBudgetError marks a message body of size octets the session memory
// budget (session_memory_limit) cannot hold. The FETCH is answered as for a
// section copy the budget refuses (sectionMemoryRefused), not with an empty
// body. The size is the body's as read when the message has none recorded.
type bodyOverBudgetError struct{ size int }

func (e *bodyOverBudgetError) Error() string {
	return fmt.Sprintf("message body of %d bytes exceeds the session memory budget", e.size)
}

// bodyFetchRetry* tune the bounded retry of the S3 read on the not-yet-uploaded path.
// They absorb the read-before-write race where the background S3 PUT lands shortly after
// the FETCH (e.g. a cross-node delivery still uploading). The wait is only ever spent
// when an upload is still pending (loadMessageBody gates on bodyUploadStillPending), so a
// body that is never coming is not waited on; and because a transient result aborts the
// FETCH command, at most one message per command pays it. FETCH clients tolerate this, so
// the window is generous: ~(bodyFetchRetryAttempts-1) * bodyFetchRetryDelay ≈ 1s.
const (
	bodyFetchRetryAttempts = 3
	bodyFetchRetryDelay    = 500 * time.Millisecond
)

// safeExtractBodySection wraps imapserver.ExtractBodySection with panic recovery.
// For BODY[] requests on malformed messages, returns the full body data.
// This follows the email server principle: store and return what you have, let the client handle parsing.
//
// The second result is false when the returned slice is bodyData itself rather than a
// fresh buffer, so the caller neither charges nor retains it a second time.
func safeExtractBodySection(bodyData []byte, section *imap.FetchItemBodySection) (content []byte, copied bool) {
	// Capture panics from the MIME parser
	defer func() {
		if recover() != nil {
			// MIME parser panicked - this is rare but handled
		}
	}()

	// BODY[] is the message verbatim (RFC 3501 6.4.5), so answer it from the stored
	// bytes rather than from the MIME parser. Round-tripping a well-formed message
	// through the parser reproduces it exactly, but on a message the parser cannot
	// read the trip only loses data: it now tolerates a malformed header block and
	// returns just the "\r\n" header terminator, which no longer looks empty to a
	// len(result) == 0 fallback. Serving the raw bytes also keeps the literal length
	// in step with the size reported elsewhere.
	if len(bodyData) > 0 && len(section.Part) == 0 && section.Specifier == imap.PartSpecifierNone &&
		len(section.HeaderFields) == 0 && len(section.HeaderFieldsNot) == 0 {
		return bodyData, false
	}

	// Try to extract the requested section. For sections other than BODY[]
	// (BODY[TEXT], BODY[1], ...), empty is a valid answer: the part does not exist.
	return imapserver.ExtractBodySection(bytes.NewReader(bodyData), section), true
}

// sectionWithoutPartial returns the section with its <offset.size> slice removed, so the
// whole section is extracted once and the slice applied afterwards.
func sectionWithoutPartial(section *imap.FetchItemBodySection) *imap.FetchItemBodySection {
	if section.Partial == nil {
		return section
	}
	full := *section
	full.Partial = nil
	return &full
}

// applyPartial slices out the client's <offset.size> request, mirroring what
// imapserver.ExtractBodySection does with a Partial. Offset and Size come off the wire,
// so the end bound also has to survive an addition that wraps.
func applyPartial(b []byte, partial *imap.SectionPartial) []byte {
	if partial == nil {
		return b
	}
	if partial.Offset < 0 || partial.Offset > int64(len(b)) {
		return nil
	}
	end := partial.Offset + partial.Size
	if end < partial.Offset || end > int64(len(b)) {
		end = int64(len(b))
	}
	return b[partial.Offset:end]
}

// safeDecodeBinarySection wraps imapserver.DecodeBinarySection with panic recovery.
func safeDecodeBinarySection(bodyData []byte, section *imap.FetchItemBinarySection) (buf []byte, err error) {
	defer func() {
		if recover() != nil {
			// MIME parser panicked - return empty
			buf, err = nil, nil
		}
	}()

	return imapserver.DecodeBinarySection(bytes.NewReader(bodyData), section)
}

// safeDecodeBinarySectionSize wraps imapserver.DecodeBinarySectionSize with panic recovery.
func safeDecodeBinarySectionSize(bodyData []byte, section *imap.FetchItemBinarySectionSize) (n uint32, err error) {
	defer func() {
		if recover() != nil {
			// MIME parser panicked - return 0
			n, err = 0, nil
		}
	}()

	return imapserver.DecodeBinarySectionSize(bytes.NewReader(bodyData), section)
}

// requireFetchBinary refuses the BINARY, BINARY.PEEK and BINARY.SIZE items of
// a FETCH, or of NOTIFY's MessageNew fetch-atts, unless the session offers
// them; go-imap parses them whatever the session offers. They are BINARY's
// (RFC 3516 §4.2) and also IMAP4rev2's, which "includes additional FETCH items
// (BINARY, BINARY.PEEK, and BINARY.SIZE) but not extensions to the APPEND
// command" (RFC 9051 Appendix B): disabling BINARY alone keeps them, disabling
// both refuses them.
func (s *IMAPSession) requireFetchBinary(options *imap.FetchOptions) error {
	if len(options.BinarySection) == 0 && len(options.BinarySectionSize) == 0 {
		return nil
	}
	if s.GetCapabilities().Has(imap.CapIMAP4rev2) {
		return nil
	}
	return s.requireCapability(imap.CapBinary, "FETCH BINARY")
}

func (s *IMAPSession) Fetch(ctx context.Context, w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	return s.fetch(ctx, w, numSet, options, nil)
}

// fetchProgress is how far a fetch got through its messages, which it answers
// in ascending UID order.
type fetchProgress struct {
	answered imap.UID // the last message it wrote a response for
	failed   imap.UID // the message it failed at, 0 if it did not fail at one
}

// fetch is Fetch, recording in progress, when it is not nil, how far it got.
func (s *IMAPSession) fetch(ctx context.Context, w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions, progress *fetchProgress) error {
	ctx = s.pinnedContext(ctx)

	// FETCH is not wrapped by meteredSession (it self-instruments below), so the
	// per-command cap is applied here. It is zero by default — see CommandTimeouts.Fetch.
	ctx, cancelCommandTimeout := applyCommandTimeout(ctx, "FETCH", s.server.commandTimeouts)
	defer cancelCommandTimeout()

	start := time.Now()
	// recordMetrics records throughput + latency, classifying the status the same
	// way the meteredSession wrapper does (success / client_error / server_error)
	// so FETCH stays consistent with the rest of sora_commands_total. Pass nil on success.
	recordMetrics := func(err error) {
		metrics.CommandsTotal.WithLabelValues("imap", "FETCH", commandStatus(err)).Inc()
		metrics.CommandDuration.WithLabelValues("imap", "FETCH").Observe(time.Since(start).Seconds())
	}

	if err := s.requireFetchBinary(options); err != nil {
		recordMetrics(err)
		return err
	}

	// The client's numbering holds still until the last response (seqViewMu).
	s.seqViewMu.RLock()
	defer s.seqViewMu.RUnlock()
	endFetch := s.beginFetch()
	defer endFetch()
	// A Seen update may have pinned reads to the primary while beginFetch waited.
	ctx = s.pinnedContext(ctx)

	// First, safely read necessary session state and decode the sequence numbers all within a single read lock
	var selectedMailboxID int64
	var selectedMailboxOwnerID int64
	var selectedExamined bool
	var recentAbove imap.UID
	var view seqView
	var decodedNumSet imap.NumSet

	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		s.WarnLog("failed to acquire read lock within timeout")
		imapErr := &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
		recordMetrics(imapErr)
		return imapErr
	}

	if s.selectedMailbox == nil {
		release()
		s.DebugLog("no mailbox selected")
		imapErr := &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "No mailbox selected",
		}
		recordMetrics(imapErr)
		return imapErr
	}

	selectedMailboxID = s.selectedMailbox.ID
	selectedMailboxOwnerID = s.selectedMailbox.AccountID
	selectedExamined = s.selectedExamined.Load()
	recentAbove = s.recentFlagAboveLocked()
	view = s.seqViewLocked()
	decodedNumSet = s.decodeNumSetLocked(view, numSet)
	release()

	// QRESYNC: Handle VANISHED modifier (RFC 7162 §3.2.6)
	// VANISHED returns UIDs of expunged messages since ChangedSince modseq.
	// It needs CHANGEDSINCE and a client that issued ENABLE QRESYNC on this
	// connection; QRESYNC being advertised is not enough: "A server MUST
	// respond with a tagged BAD response if the VANISHED UID FETCH modifier is
	// specified and the client hasn't issued "ENABLE QRESYNC" in the current
	// connection" (RFC 7162 §3.2.6).
	if options.Vanished && options.ChangedSince > 0 && s.conn != nil && s.conn.EnabledCaps().Has(imap.CapQResync) {
		s.DebugLog("FETCH with VANISHED modifier", "changed_since", options.ChangedSince)

		vanishedUIDs, err := s.server.rdb.GetVanishedUIDsForFetchWithRetry(ctx, selectedMailboxID, options.ChangedSince)
		if err != nil {
			s.WarnLog("failed to retrieve vanished UIDs", "error", err)
			// Don't fail the FETCH - just continue without VANISHED response
		} else if len(vanishedUIDs) > 0 {
			// RFC 7162 §3.2.4.1: The VANISHED Fetch modifier only returns vanished responses
			// for messages IN the requested UID set. Filter to subset.
			var filteredUIDs []imap.UID
			if uidSet, ok := numSet.(imap.UIDSet); ok {
				for _, uid := range vanishedUIDs {
					if uidSet.Contains(uid) {
						filteredUIDs = append(filteredUIDs, uid)
					}
				}
			} else {
				// Fallback (for SeqSet fetch which shouldn't have VANISHED modifier by spec)
				filteredUIDs = vanishedUIDs
			}

			if len(filteredUIDs) > 0 {
				// Convert UIDs to ranges for efficient transmission
				uidSet := convertUIDsToRanges(filteredUIDs)
				// RFC 7162 §3.2.6: VANISHED (EARLIER) response must appear before FETCH responses
				// The 'true' parameter indicates this is sent before FETCH responses
				w.WriteVanished(uidSet, true)
				s.DebugLog("wrote VANISHED response", "count", len(filteredUIDs))
			}
		}
	} else if options.Vanished {
		// VANISHED modifier used without ENABLE QRESYNC or ChangedSince - protocol violation
		imapErr := &imap.Error{
			Type: imap.StatusResponseTypeBad,
			Code: imap.ResponseCodeClientBug,
			Text: "VANISHED requires ENABLE QRESYNC and CHANGEDSINCE",
		}
		recordMetrics(imapErr)
		return imapErr
	}

	needsBodyStructure := options.BodyStructure != nil

	// Determine if this FETCH implicitly marks messages as \Seen: any BODY[] or
	// BINARY[] that is not the .PEEK form (RFC 9051 §6.4.5). Not in a mailbox
	// opened with EXAMINE, where "No changes to the permanent state of the
	// mailbox, including per-user state, are permitted" (RFC 9051 §6.3.3). A
	// SELECT that the ACL made read-only is not EXAMINE (RFC 9051 §6.3.2); the
	// 's' right below decides there.
	markSeen := !selectedExamined &&
		(slices.ContainsFunc(options.BodySection, func(bs *imap.FetchItemBodySection) bool { return !bs.Peek }) ||
			slices.ContainsFunc(options.BinarySection, func(bs *imap.FetchItemBinarySection) bool { return !bs.Peek }))

	// RFC 4314 §4: a FETCH that would implicitly set \Seen MUST NOT do so when the
	// user lacks the 's' right on the mailbox. The owner always holds every right, so
	// only shared-mailbox grantees incur the permission check. Fail closed (suppress the
	// implicit \Seen) if the check itself errors.
	if markSeen && selectedMailboxOwnerID != s.AccountID() {
		hasSeen, err := s.server.rdb.CheckMailboxPermissionWithRetry(ctx, selectedMailboxID, s.AccountID(), db.ACLRightSeen)
		if err != nil {
			s.WarnLog("failed to check 's' right for implicit \\Seen; suppressing", "error", err)
			markSeen = false
		} else if !hasSeen {
			s.DebugLog("user lacks 's' right; not implicitly marking messages \\Seen on FETCH")
			markSeen = false
		}
	}

	if view.tracker == nil {
		s.DebugLog("session tracker is nil, cannot process messages")
		return nil
	}

	var totalBytesFetched int64
	var writeErr error

	var preview *previewRun
	if options.Preview != nil {
		preview = newPreviewRun()
		defer func() {
			// RFC 8970 §8: log who makes the server generate previews. Only
			// downloads are worth a line; the session log carries the user.
			if preview.downloads > 0 {
				s.InfoLog("FETCH PREVIEW downloaded message bodies", "count", preview.downloads)
			}
		}()
	}

	cb := func(messages []db.Message) error {
		if err := ctx.Err(); err != nil {
			writeErr = err
			return err
		}
		// Number the messages as the client does. A message it has not been told
		// about (a UID FETCH may name one) has no number it could be sent under,
		// and is neither returned nor marked \Seen.
		known := make([]db.Message, 0, len(messages))
		for _, msg := range messages {
			if msg.Seq = view.encode(msg.Seq); msg.Seq != 0 {
				known = append(known, msg)
			}
		}
		messages = known
		// The parser accepted CHANGEDSINCE only if the session offers
		// CONDSTORE, so the request alone gates it here.
		if options.ChangedSince > 0 {
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

		for _, msg := range messages {
			if err := ctx.Err(); err != nil {
				writeErr = err
				return err
			}
			totalBytesFetched += int64(msg.Size)
			metrics.MessageThroughput.WithLabelValues("imap", "fetched", "success").Inc()
			if s.IMAPUser != nil {
				metrics.TrackDomainMessage("imap", s.IMAPUser.Domain(), "fetched")
			}
			// Unsolicited NOTIFY MessageNew fetches (progress != nil) push one-off
			// event attributes, often while the client sits in IDLE. Skip new
			// retention or replacement of the session's chunk-fetch cache;
			// normal memory admission may still reclaim in-memory retention.
			retainSections := progress == nil
			if err := s.writeMessageFetchData(ctx, w, &msg, options, selectedMailboxID, recentAbove, markSeen, view.tracker, preview, retainSections); err != nil {
				if progress != nil {
					progress.failed = msg.UID
				}
				writeErr = err
				return err
			}
			if progress != nil {
				progress.answered = msg.UID
			}
		}
		return nil
	}

	err := s.server.rdb.StreamMessagesByNumSetWithRetry(view.context(ctx), selectedMailboxID, decodedNumSet, cb, needsBodyStructure)
	if writeErr != nil {
		// Bypass explicit metric tracking for socket disconnections, identically to pre-streaming behavior
		return writeErr
	}
	if err != nil {
		ierr := s.internalError("failed to retrieve messages: %v", err)
		recordMetrics(ierr)
		return ierr
	}

	if s.IMAPUser != nil {
		metrics.TrackDomainBytes("imap", s.IMAPUser.Domain(), "out", totalBytesFetched)
	}

	recordMetrics(nil)
	return nil
}

// writeMessageFetchData handles writing all FETCH data items for a single message.
// recentAbove is the session's \Recent threshold (recentFlagAboveLocked);
// markSeen is whether the FETCH implicitly sets \Seen; preview is the command's
// PREVIEW state, nil unless PREVIEW was requested.
func (s *IMAPSession) writeMessageFetchData(ctx context.Context, w *imapserver.FetchWriter, msg *db.Message, options *imap.FetchOptions, selectedMailboxID int64, recentAbove imap.UID, markSeen bool, tracker *imapserver.SessionTracker, preview *previewRun, retainSections bool) (retErr error) {
	s.DebugLog("fetching message", "uid", msg.UID, "seq", msg.Seq)

	// msg.Seq is the client's sequence number (Fetch translated it, see seqView).
	seqNum := msg.Seq

	if seqNum == 0 {
		// Sequence number should never be 0 for valid messages
		s.DebugLog("skipping message with invalid sequence number", "uid", msg.UID, "seq", msg.Seq)
		return nil
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

	// BINARY and BINARY.SIZE are decoded before the message's FETCH response
	// is opened: a section whose Content-Transfer-Encoding cannot be decoded
	// fails the command with NO [UNKNOWN-CTE] (RFC 9051 §7.5.2), which must not
	// leave a partial response, possibly an empty "* n FETCH ()", behind it.
	// Fetch has refused the items up front unless the session offers them,
	// through BINARY or IMAP4rev2.
	var binary *decodedBinary
	if len(options.BinarySection) > 0 || len(options.BinarySectionSize) > 0 {
		var err error
		if binary, err = s.decodeBinaryWithRetention(ctx, &bodyData, &bodyDataFetched, options, msg, retainSections); err != nil {
			return err
		}
		defer s.freeSectionCopies(binary.charged)
	}
	// BODY sections are extracted before the response too, for the same
	// reason: a body that cannot be read right now fails the command with
	// NO [UNAVAILABLE], and a body or section the session memory budget
	// cannot hold with NO [LIMIT] or NO [UNAVAILABLE] (sectionMemoryRefused).
	var sections *bodySections
	if len(options.BodySection) > 0 {
		var err error
		var priorCopies int64
		if binary != nil {
			priorCopies = binary.charged
		}
		if sections, err = s.extractBodySectionsWithRetention(ctx, &bodyData, &bodyDataFetched, options, msg, priorCopies, retainSections); err != nil {
			return err
		}
		defer s.freeSectionCopies(sections.charged)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Loading, decoding and extracting are what usually fails the command at
	// this message, so its implicit \Seen (RFC 9051 §6.4.5) is set only now, one
	// message at a time rather than for the whole stream chunk up front: a
	// FETCH that fails there leaves that message, and the ones after it whose
	// bodies it never sent, as they were. A failure once the response is open
	// (an ENVELOPE that cannot be built from the stored recipients, a write
	// error) still leaves this one message \Seen, and its update to Poll.
	var seenAnswer *implicitSeenAnswer
	if markSeen {
		options, seenAnswer = s.setImplicitSeen(ctx, msg, options, selectedMailboxID, tracker)
		if seenAnswer != nil {
			defer seenAnswer.release()
		}
	}

	m := w.CreateMessage(seqNum)
	if m == nil {
		// This indicates an issue with the imapserver library or FetchWriter.
		return fmt.Errorf("imapserver: FetchWriter.CreateMessage returned nil for seq %d (UID %d)", seqNum, msg.UID)
	}
	// Metadata and PREVIEW may remain buffered until Close. Propagate a failed
	// flush so the caller stops streaming bodies into a disconnected client.
	// An earlier handler error still takes precedence over the close error.
	defer func() {
		if closeErr := m.Close(); closeErr != nil {
			s.DebugLog("error closing FetchResponseWriter", "uid", msg.UID, "seq", seqNum, "error", closeErr)
			if retErr == nil {
				retErr = closeErr
			}
		}
		// Suppress only the update this successfully completed response carried.
		// A failed or partial response leaves it for Poll to announce.
		if retErr == nil && seenAnswer != nil {
			seenAnswer.answered(msg.UID, uint64(*msg.UpdatedModSeq))
		}
	}()

	if err := s.writeBasicMessageData(m, msg, options, recentAbove); err != nil {
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
			bs, err = s.server.rdb.GetMessageBodyStructureWithRetry(ctx, msg.UID, selectedMailboxID)
			if err != nil {
				s.WarnLog("failed to fetch body structure, using fallback", "uid", msg.UID, "error", err)
				fallback := &imap.BodyStructureSinglePart{
					Type:     "text",
					Subtype:  "plain",
					Size:     uint32(msg.Size),
					Extended: &imap.BodyStructureSinglePartExt{},
					Text:     &imap.BodyStructureText{}, // body-fld-lines is mandatory for a text part
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

	if sections != nil {
		if err := writeBodySections(m, options, sections, func(section *imap.FetchItemBodySection, nuls int) {
			metrics.IMAPBodyNULReplaced.WithLabelValues("imap").Inc()
			s.WarnLog("sent NUL octets of a BODY section as 0x80", "uid", msg.UID,
				"part", section.Part, "specifier", section.Specifier, "nuls", nuls)
		}); err != nil {
			return err
		}
	}

	if binary != nil {
		if err := writeDecodedBinary(m, options, binary); err != nil {
			return err
		}
	}

	// The parser accepted PREVIEW only if the session advertises it, so the
	// request alone gates it here.
	if options.Preview != nil && preview != nil {
		s.writePreview(ctx, m, msg, options.Preview.Lazy, preview, &bodyData, &bodyDataFetched)
	}

	// Likewise MODSEQ, and CHANGEDSINCE, which implies it: the parser accepted
	// them only if the session offers CONDSTORE. Requesting MODSEQ also makes
	// the client CONDSTORE-aware, so a later capability filter preserves it.
	if options.ModSeq {
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

func (s *IMAPSession) writeBasicMessageData(m *imapserver.FetchResponseWriter, msg *db.Message, options *imap.FetchOptions, recentAbove imap.UID) error {
	if options.Flags {
		allFlags := db.BitwiseToFlags(msg.BitwiseFlags) // System flags
		for _, customFlag := range msg.CustomFlags {
			allFlags = append(allFlags, imap.Flag(customFlag))
		}
		// Sanitize flags to remove invalid values (NIL, NULL, etc.) that may have been
		// stored in the database before validation was added
		allFlags = helpers.SanitizeFlags(allFlags)

		m.WriteFlags(withRecentFlag(allFlags, msg.UID, recentAbove))
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

func (s *IMAPSession) ensureBodyDataLoaded(ctx context.Context, msg *db.Message, bodyData *[]byte, bodyDataFetched *bool) error {
	if !*bodyDataFetched {
		var fetchErr error
		*bodyData, fetchErr = s.getMessageBody(ctx, msg)
		*bodyDataFetched = true // Mark as fetched even if error or nil data, to prevent re-fetching.
		if fetchErr != nil {
			s.DebugLog("failed to get message body", "uid", msg.UID, "error", fetchErr)
			return fetchErr // Propagate error to allow handlers to decide how to proceed (e.g., return NIL)
		}
	}
	return nil
}

// decodedBinary is a message's BINARY sections and BINARY.SIZE values, in the
// order of the FETCH options' BinarySection and BinarySectionSize.
type decodedBinary struct {
	sections [][]byte
	sizes    []uint32
	charged  int64 // session memory charged for sections
}

// binaryPart is a part a FETCH names in BINARY or BINARY.SIZE items, with the
// indexes of those items in the FETCH options.
type binaryPart struct {
	part     []int
	sections []int // into BinarySection
	sizes    []int // into BinarySectionSize
}

// binaryParts groups the BINARY and BINARY.SIZE items of a FETCH by the part
// they name, in the order the parts are first named.
func binaryParts(options *imap.FetchOptions) []*binaryPart {
	var parts []*binaryPart
	byPart := make(map[string]*binaryPart)
	named := func(part []int) *binaryPart {
		key := fmt.Sprint(part)
		p := byPart[key]
		if p == nil {
			p = &binaryPart{part: part}
			byPart[key] = p
			parts = append(parts, p)
		}
		return p
	}
	for i, section := range options.BinarySection {
		p := named(section.Part)
		p.sections = append(p.sections, i)
	}
	for i, section := range options.BinarySectionSize {
		p := named(section.Part)
		p.sizes = append(p.sizes, i)
	}
	return parts
}

// decodeBinary decodes the BINARY sections and BINARY.SIZE values a FETCH asks
// for. Each part is decoded once, however many items name it: one command line
// has room for thousands of items like BINARY.PEEK[2]<0.1>, and a decode is
// work in the size of the whole part. A section whose Content-Transfer-Encoding
// cannot be decoded fails with NO [UNKNOWN-CTE]: RFC 9051 §7.5.2, for both
// items, "If the server does not know how to decode the section's
// Content-Transfer-Encoding, it MUST fail the request and issue a "NO" response
// that contains the "UNKNOWN-CTE" response code."
func (s *IMAPSession) decodeBinary(ctx context.Context, bodyData *[]byte, bodyDataFetched *bool, options *imap.FetchOptions, msg *db.Message) (*decodedBinary, error) {
	return s.decodeBinaryWithRetention(ctx, bodyData, bodyDataFetched, options, msg, true)
}

func (s *IMAPSession) decodeBinaryWithRetention(ctx context.Context, bodyData *[]byte, bodyDataFetched *bool, options *imap.FetchOptions, msg *db.Message, retainSections bool) (*decodedBinary, error) {
	b := &decodedBinary{
		sections: make([][]byte, len(options.BinarySection)),
		sizes:    make([]uint32, len(options.BinarySectionSize)),
	}
	// The body is loaded only for a part the session has not retained. A body
	// loadSectionBody leaves nil gives empty sections and zero sizes.
	loadBody := func() ([]byte, error) {
		if err := s.loadSectionBody(ctx, msg, bodyData, bodyDataFetched, b.charged); err != nil {
			return nil, err
		}
		return *bodyData, nil
	}

	for _, p := range binaryParts(options) {
		if err := s.decodeBinaryPart(b, p, options, msg, bodyData, loadBody, retainSections); err != nil {
			s.freeSectionCopies(b.charged)
			return nil, err
		}
	}
	return b, nil
}

// decodeBinaryPart fills in b the items that name p, from the one decoded
// section of p. A part named only with a <partial> is being fetched in chunks:
// its decoded section is retained for the session's next chunk of it, as a BODY
// section is (body_section_cache.go), and answered from there while it is.
func (s *IMAPSession) decodeBinaryPart(b *decodedBinary, p *binaryPart, options *imap.FetchOptions, msg *db.Message, bodyData *[]byte, loadBody func() ([]byte, error), retainSections bool) error {
	key := binarySectionCacheKey(msg.ContentHash, p.part)
	section := s.cachedBodySection(key) // charged to the retention while it is retained
	retained := section != nil

	chunked := !slices.ContainsFunc(p.sections, func(i int) bool { return options.BinarySection[i].Partial == nil })
	if !retained {
		if spilledSize, ok := s.cachedSpilledSectionSize(key); ok {
			if ok, err := s.answerBinaryFromSpill(b, p, options, msg.UID, key, spilledSize, chunked, int64(len(*bodyData))); ok || err != nil {
				return err
			}
		}
	}

	var body []byte // the body the section is decoded from, held with its copies
	if !retained {
		var err error
		if body, err = loadBody(); err != nil || body == nil {
			return err // no body: empty sections and zero sizes
		}
		if len(p.sections) == 0 {
			// BINARY.SIZE alone: count the decoded octets without holding them.
			n, err := safeDecodeBinarySectionSize(body, &imap.FetchItemBinarySectionSize{Part: p.part})
			if err != nil {
				return s.unknownCTE(msg.UID)
			}
			for _, i := range p.sizes {
				b.sizes[i] = n
			}
			return nil
		}
		if section, err = safeDecodeBinarySection(body, &imap.FetchItemBinarySection{Part: p.part}); err != nil {
			return s.unknownCTE(msg.UID)
		}
	}
	for _, i := range p.sizes {
		b.sizes[i] = uint32(len(section))
	}

	if !chunked {
		// The whole section is sent, so the items are slices of it, held and
		// charged once until the response is written. A retained section needs
		// one independent copy: charging it may reclaim the cache's charge.
		if retained {
			section = bytes.Clone(section)
		}
		charged, ok := s.chargeSectionCopy(len(section))
		if !ok {
			return s.sectionMemoryRefused(msg.UID, int64(len(*bodyData))+b.charged+int64(len(section)))
		}
		for _, i := range p.sections {
			b.sections[i] = applyPartial(section, options.BinarySection[i].Partial)
		}
		b.charged += charged
		return nil
	}

	// The items keep copies of their slices, which is what they charge: they are
	// held until the response is written, while the section goes to the
	// optional retention, which may give it up before then. The transient decoded
	// section does not need a persistent charge when the session cannot retain it.
	for _, i := range p.sections {
		buf := bytes.Clone(applyPartial(section, options.BinarySection[i].Partial))
		n, ok := s.chargeSectionCopy(len(buf))
		if !ok {
			return s.sectionMemoryRefused(msg.UID, int64(len(*bodyData))+b.charged+int64(len(buf)))
		}
		b.charged += n
		b.sections[i] = buf
	}
	// Retention is optional. A partial that fits the remaining budget must
	// still work when keeping the full section does not, or is not eligible.
	if retainSections && !retained && key != "" && len(section) > 0 {
		if len(section) <= maxCachedBodySectionBytes {
			if charged, ok := s.chargeSectionCopy(len(section)); ok {
				if !s.retainBodySection(key, section) {
					s.freeSectionCopies(charged)
				}
			}
		} else {
			s.spillBodySection(key, section)
		}
	}
	return nil
}

// answerBinaryFromSpill serves p's BINARY and BINARY.SIZE items from a disk-spilled
// section, charging session memory before allocating buffers. If the spilled file can no
// longer be read, it releases any partial charges made for p and returns (false, nil) so
// the caller falls back to loading and decoding the raw message.
func (s *IMAPSession) answerBinaryFromSpill(b *decodedBinary, p *binaryPart, options *imap.FetchOptions, uid imap.UID, key string, spilledSize int, chunked bool, loadedBody int64) (bool, error) {
	if len(p.sections) == 0 {
		for _, i := range p.sizes {
			b.sizes[i] = uint32(spilledSize)
		}
		return true, nil
	}
	if !chunked {
		charged, ok := s.chargeSectionCopy(spilledSize)
		if !ok {
			return false, s.sectionMemoryRefused(uid, loadedBody+b.charged+int64(spilledSize))
		}
		full := make([]byte, spilledSize)
		if !s.readSpilledSectionInto(key, 0, full) {
			s.freeSectionCopies(charged)
			return false, nil
		}
		for _, i := range p.sections {
			b.sections[i] = applyPartial(full, options.BinarySection[i].Partial)
		}
		for _, i := range p.sizes {
			b.sizes[i] = uint32(spilledSize)
		}
		b.charged += charged
		return true, nil
	}

	var partCharged int64
	for done, i := range p.sections {
		off, length := partialBounds(spilledSize, options.BinarySection[i].Partial)
		n, ok := s.chargeSectionCopy(length)
		if !ok {
			for _, prev := range p.sections[:done] {
				b.sections[prev] = nil
			}
			s.freeSectionCopies(partCharged)
			return false, s.sectionMemoryRefused(uid, loadedBody+b.charged+partCharged+int64(length))
		}
		buf := make([]byte, length)
		if !s.readSpilledSectionInto(key, off, buf) {
			for _, prev := range p.sections[:done] {
				b.sections[prev] = nil
			}
			s.freeSectionCopies(partCharged + n)
			return false, nil
		}
		partCharged += n
		b.sections[i] = buf
	}
	for _, i := range p.sizes {
		b.sizes[i] = uint32(spilledSize)
	}
	b.charged += partCharged
	return true, nil
}

// writeDecodedBinary writes the BINARY sections and BINARY.SIZE values
// decodeBinary returned. A section goes as a literal8 only when it contains a
// NUL octet: RFC 9051 §7.5.2, "If the domain of the decoded data is "8bit"
// and the data does not contain the NUL octet, the server SHOULD return the
// data in a <string> instead of a <literal8>".
func writeDecodedBinary(w *imapserver.FetchResponseWriter, options *imap.FetchOptions, b *decodedBinary) error {
	for i, section := range options.BinarySection {
		if err := w.WriteBinarySectionBytes(section, b.sections[i]); err != nil {
			return err
		}
	}
	for i, section := range options.BinarySectionSize {
		w.WriteBinarySectionSize(section, b.sizes[i])
	}
	return nil
}

// bodySectionWriter is the part of *imapserver.FetchResponseWriter that
// writeBodySections uses.
type bodySectionWriter interface {
	WriteBodySection(section *imap.FetchItemBodySection, size int64) io.WriteCloser
}

// bodySections is a message's BODY sections, in the order of the FETCH
// options' BodySection.
type bodySections struct {
	contents [][]byte
	charged  int64 // session memory charged for contents
}

// extractBodySections extracts the BODY sections a FETCH asks for before the
// message's response is opened and its implicit \Seen set, as decodeBinary
// decodes BINARY sections: a body that cannot be read right now, or a body or
// a section copy the session memory budget cannot hold, then fails the
// command at this message with nothing written and nothing set. The body is
// loaded unless the section this session retained answers every chunk asked
// for. The sections are held, and charged, until the response is written.
// priorCopies counts BINARY buffers already prepared for this same response.
func (s *IMAPSession) extractBodySections(ctx context.Context, bodyData *[]byte, bodyDataFetched *bool, options *imap.FetchOptions, msg *db.Message, priorCopies int64) (*bodySections, error) {
	return s.extractBodySectionsWithRetention(ctx, bodyData, bodyDataFetched, options, msg, priorCopies, true)
}

func (s *IMAPSession) extractBodySectionsWithRetention(ctx context.Context, bodyData *[]byte, bodyDataFetched *bool, options *imap.FetchOptions, msg *db.Message, priorCopies int64, retainSections bool) (*bodySections, error) {
	b := &bodySections{contents: make([][]byte, len(options.BodySection))}
	for i, section := range options.BodySection {
		content, charged, err := s.extractBodySection(ctx, bodyData, bodyDataFetched, section, msg, priorCopies+b.charged, retainSections)
		if err != nil {
			s.freeSectionCopies(b.charged)
			return nil, err
		}
		b.contents[i] = content
		b.charged += charged
	}
	return b, nil
}

// extractBodySection returns one BODY section and what it charged to the
// session budget for it. For a chunk request the whole section is extracted
// and retained, so that the chunks which follow are answered from it instead
// of reloading and re-extracting the message for every chunk. A chunk of the
// retained section is held as a copy of its own, which is what it charges:
// the retention may give the section up before the response is written.
func (s *IMAPSession) extractBodySection(ctx context.Context, bodyData *[]byte, bodyDataFetched *bool, section *imap.FetchItemBodySection, msg *db.Message, priorCopies int64, retainSections bool) ([]byte, int64, error) {
	var cacheKey string
	if section.Partial != nil {
		cacheKey = bodySectionCacheKey(msg.ContentHash, section)
		if retained := s.cachedBodySection(cacheKey); retained != nil {
			return s.retainedSectionChunk(msg.UID, applyPartial(retained, section.Partial), int64(len(*bodyData))+priorCopies)
		}
		if spilledSize, ok := s.cachedSpilledSectionSize(cacheKey); ok {
			off, length := partialBounds(spilledSize, section.Partial)
			charged, ok := s.chargeSectionCopy(length)
			if !ok {
				return nil, 0, s.sectionMemoryRefused(msg.UID, int64(len(*bodyData))+priorCopies+int64(length))
			}
			buf := make([]byte, length)
			if s.readSpilledSectionInto(cacheKey, off, buf) {
				return buf, charged, nil
			}
			s.freeSectionCopies(charged)
		}
	}

	if err := s.loadSectionBody(ctx, msg, bodyData, bodyDataFetched, priorCopies); err != nil {
		return nil, 0, err
	}
	if *bodyData == nil {
		return nil, 0, nil // no body: an empty section
	}
	// If MIME parsing fails or panics, safeExtractBodySection returns what it
	// can: the server hands back what it stored and lets the client parse it.
	full, copied := safeExtractBodySection(*bodyData, sectionWithoutPartial(section))
	if !copied {
		return applyPartial(full, section.Partial), 0, nil // the body itself, charged as such
	}
	if section.Partial != nil && len(full) > maxCachedBodySectionBytes {
		chunk, charged, err := s.retainedSectionChunk(msg.UID, applyPartial(full, section.Partial), int64(len(*bodyData))+priorCopies)
		if err != nil {
			return nil, 0, err
		}
		if retainSections {
			s.spillBodySection(cacheKey, full)
		}
		return chunk, charged, nil
	}
	charged, ok := s.chargeSectionCopy(len(full))
	if !ok {
		return nil, 0, s.sectionMemoryRefused(msg.UID, int64(len(*bodyData))+priorCopies+int64(len(full)))
	}
	if !retainSections || section.Partial == nil || !s.retainBodySection(cacheKey, full) {
		return applyPartial(full, section.Partial), charged, nil
	}
	// The retained section carries the charge now.
	return s.retainedSectionChunk(msg.UID, applyPartial(full, section.Partial), int64(len(*bodyData))+priorCopies)
}

// retainedSectionChunk returns a copy of a chunk of the retained section,
// charged to the session budget. The copy needs no body beside it, and the
// budget gives the retained section up for it if need be. priorOwned counts only
// this response's held body and copies, not optional retention or other work.
func (s *IMAPSession) retainedSectionChunk(uid imap.UID, chunk []byte, priorOwned int64) ([]byte, int64, error) {
	chunk = bytes.Clone(chunk)
	charged, ok := s.chargeSectionCopy(len(chunk))
	if !ok {
		return nil, 0, s.sectionMemoryRefused(uid, priorOwned+int64(len(chunk)))
	}
	return chunk, charged, nil
}

// loadSectionBody loads the body BODY and BINARY sections are taken from. A
// body that cannot be read right now, or that the session memory budget
// cannot hold, fails the FETCH; any other failure leaves it nil, for empty
// sections.
func (s *IMAPSession) loadSectionBody(ctx context.Context, msg *db.Message, bodyData *[]byte, bodyDataFetched *bool, priorCopies int64) error {
	if loadErr := s.ensureBodyDataLoaded(ctx, msg, bodyData, bodyDataFetched); loadErr != nil {
		// Transient: the body is staged for upload but not yet retrievable from
		// this node (read-before-upload race, or cross-node staging). Fail the
		// FETCH with NO [UNAVAILABLE] so the client retries instead of receiving
		// (and possibly acting on) an empty body. See errBodyTransientlyUnavailable.
		if errors.Is(loadErr, errBodyTransientlyUnavailable) {
			return s.transientBodyUnavailable(msg.UID, loadErr)
		}
		// The body exists but the session budget cannot hold it: refused like a
		// section copy the budget cannot hold, as an empty section would pass
		// for the message.
		var overBudget *bodyOverBudgetError
		if errors.As(loadErr, &overBudget) {
			return s.sectionMemoryRefused(msg.UID, priorCopies+int64(overBudget.size))
		}
		// Graceful degradation: return empty sections instead of failing the
		// entire multi-message FETCH. This prevents one broken message (missing
		// S3 content, 0-byte message, etc.) from making the whole mailbox
		// listing fail for webmail clients like Roundcube/SOGo.
		s.WarnLog("failed to load message body, returning empty sections", "uid", msg.UID, "error", loadErr)
	}
	return nil
}

// writeBodySections writes the BODY sections extractBodySections returned.
// onNUL, if not nil, is told of each section sent with NUL octets replaced.
func writeBodySections(w bodySectionWriter, options *imap.FetchOptions, b *bodySections, onNUL func(section *imap.FetchItemBodySection, nuls int)) error {
	for i, section := range options.BodySection {
		nuls, err := writeBodySectionData(w, section, b.contents[i])
		if err != nil {
			return err
		}
		if nuls > 0 && onNUL != nil {
			onNUL(section, nuls)
		}
	}
	return nil
}

// nulReplacement is what a NUL octet in a BODY section is sent as.
const nulReplacement = 0x80

// writeBodySectionData writes one BODY[...] data item and returns how many NUL
// octets it sent as nulReplacement.
//
// BODY[] takes an nstring, never a literal8, and a literal is "*CHAR8" with
// CHAR8 = %x01-ff (RFC 9051 §9). A stored section can still hold NUL: a body
// stored before APPEND and delivery re-encoded such parts as base64, one
// registered by import s3, a multipart without a boundary. Each NUL is sent as
// 0x80, as Dovecot does (imap-msgpart.c, i_stream_create_nonuls), so the size
// and every partial offset stay as they are. BINARY[] sends the octets as they
// are, in a literal8. content is never modified: it can be the message body or
// a section retained for later chunks.
func writeBodySectionData(w bodySectionWriter, section *imap.FetchItemBodySection, content []byte) (nuls int, err error) {
	if content == nil { // Ensure not nil for WriteBodySection
		content = []byte{}
	}
	wc := w.WriteBodySection(section, int64(len(content))) // section is *FetchItemBodySection
	var writeErr error
	if bytes.IndexByte(content, 0) < 0 {
		_, writeErr = wc.Write(content)
	} else {
		buf := make([]byte, min(len(content), 32<<10))
		for rest := content; len(rest) > 0 && writeErr == nil; {
			n := copy(buf, rest)
			rest = rest[n:]
			for i, c := range buf[:n] {
				if c == 0 {
					buf[i] = nulReplacement
					nuls++
				}
			}
			_, writeErr = wc.Write(buf[:n])
		}
	}
	closeErr := wc.Close()
	if writeErr != nil {
		return nuls, writeErr
	}
	return nuls, closeErr
}

// chargeSectionCopy accounts the extractor's copy of a section against the session
// budget for as long as the copy is held: the copy is a second full-size buffer next to
// the message body it was extracted from, so a budget that ignores it under-reports the
// real peak by roughly half. It returns the bytes charged (0 when there is no tracker)
// and false when the budget cannot take the copy.
func (s *IMAPSession) chargeSectionCopy(n int) (int64, bool) {
	if s.memTracker == nil || n <= 0 {
		return 0, true
	}
	if !s.memoryAvailable(int64(n)) || s.memTracker.Allocate(int64(n)) != nil {
		return 0, false
	}
	return int64(n), true
}

// sectionMemoryRefused answers a body or section the session budget cannot hold with
// NO rather than an empty literal: an empty body section is indistinguishable from a
// genuinely empty message to the client, which may act on it destructively (see
// errBodyTransientlyUnavailable). need is what the message's FETCH holds at once for
// it: the held body and all response-owned copies, including the next allocation.
// Optional retention and unrelated/concurrent allocations are excluded. A need
// over the whole budget can never be met, however often the client retries: RFC 5530 LIMIT, "The
// operation ran up against an implementation limit of some kind". A need within it is
// refused only because other allocations of the session hold the budget now, and a
// retry can succeed: UNAVAILABLE, "Temporary failure because a subsystem is down",
// which clients such as iOS Mail retry on every sync.
func (s *IMAPSession) sectionMemoryRefused(uid imap.UID, need int64) *imap.Error {
	limit := s.memTracker.MaxAllowed()
	imapErr := &imap.Error{
		Type: imap.StatusResponseTypeNo,
		Code: imap.ResponseCodeUnavailable,
		Text: "Session memory limit reached, please try again later",
	}
	if limit > 0 && need > limit {
		imapErr.Code = imap.ResponseCodeLimit
		imapErr.Text = "Message too large for the session memory limit"
	}
	s.WarnLog("session memory limit exceeded serving a message", "uid", uid, "bytes", need,
		"limit", limit, "code", imapErr.Code)
	metrics.SessionMemoryLimitExceeded.WithLabelValues("imap", s.server.name, s.server.hostname).Inc()
	metrics.CommandsTotal.WithLabelValues("imap", "FETCH", commandStatus(imapErr)).Inc()
	return imapErr
}

// freeSectionCopies returns what chargeSectionCopy charged to the session budget.
func (s *IMAPSession) freeSectionCopies(charged int64) {
	if charged > 0 {
		s.memTracker.Free(charged)
	}
}

// unknownCTE answers a BINARY or BINARY.SIZE item whose section has a
// Content-Transfer-Encoding the server cannot decode with NO [UNKNOWN-CTE]
// (RFC 9051 §7.5.2).
func (s *IMAPSession) unknownCTE(uid imap.UID) *imap.Error {
	s.InfoLog("cannot decode the Content-Transfer-Encoding of a BINARY section", "uid", uid)
	imapErr := imapserver.ErrUnknownCTE
	metrics.CommandsTotal.WithLabelValues("imap", "FETCH", commandStatus(imapErr)).Inc()
	return imapErr
}

// transientBodyUnavailable records the event and returns the IMAP error used when a
// message body is staged for upload but not yet retrievable from this node. Returning
// NO [UNAVAILABLE] (instead of degrading to an empty body) tells the client to retry
// once the upload lands, and — critically — prevents an automated consumer from treating
// an empty read as success and deleting the message.
func (s *IMAPSession) transientBodyUnavailable(uid imap.UID, cause error) *imap.Error {
	s.WarnLog("message body not yet available, asking client to retry", "uid", uid, "error", cause)
	imapErr := &imap.Error{
		Type: imap.StatusResponseTypeNo,
		Code: imap.ResponseCodeUnavailable,
		Text: "Message body temporarily unavailable, please retry",
	}
	// NO [UNAVAILABLE] is a server-side transient condition (body upload lag);
	// commandStatus folds it into "server_error" to match the wrapper taxonomy.
	metrics.CommandsTotal.WithLabelValues("imap", "FETCH", commandStatus(imapErr)).Inc()
	return imapErr
}

func (s *IMAPSession) getMessageBody(ctx context.Context, msg *db.Message) ([]byte, error) {
	// Pre-read guard: refuse a body that can't fit the session budget BEFORE pulling it
	// into memory. The post-read Allocate() below can only detect the overrun once the
	// body is already resident — too late to prevent the OOM. msg.Size is the stored
	// metadata size, so this bounds the single allocation. (security-audit M13)
	// Both refusals are a bodyOverBudgetError.
	if msg.Size > 0 && !s.memoryAvailable(int64(msg.Size)) {
		return nil, &bodyOverBudgetError{size: msg.Size}
	}

	data, err := s.loadMessageBody(ctx, msg)
	if err != nil {
		return nil, err
	}

	// Single accounting point for every source in loadMessageBody (cache, S3, disk).
	// A body without a recorded size is checked only here, so memoryAvailable gives
	// the retained section back first, as it does before the read for a sized body.
	if s.memTracker != nil {
		if !s.memoryAvailable(int64(len(data))) || s.memTracker.Allocate(int64(len(data))) != nil {
			return nil, &bodyOverBudgetError{size: len(data)}
		}
	}
	return data, nil
}

// loadMessageBody returns the raw message body from the fastest available source.
// Preference order:
//   - uploaded messages:     local cache → S3 → local staging disk (S3 outage)
//   - not-yet-uploaded msgs: local staging disk → S3 (cross-node / late-upload race)
//
// The S3 fallback on the not-uploaded path (with a short bounded retry) is what
// self-heals the common multi-backend situation where a body was delivered/staged on
// another node and has since been uploaded, while this node's in-memory message still
// reads uploaded=false.
//
// When the not-uploaded body cannot be served from disk or S3, the error distinguishes
// transient from permanent: if the upload is still pending (or the message has since
// been marked uploaded) it returns errBodyTransientlyUnavailable so the FETCH handler answers
// NO [UNAVAILABLE] and the client retries; otherwise the content is genuinely gone and
// a generic retrieve error is returned so the handler degrades to an empty body.
func (s *IMAPSession) loadMessageBody(ctx context.Context, msg *db.Message) ([]byte, error) {
	if msg.IsUploaded {
		// Try cache first (nil-safe: cache is optional and not configured in tests).
		if s.server.cache != nil {
			if cacheData, cacheErr := s.server.cache.Get(msg.ContentHash); cacheErr == nil && cacheData != nil {
				// Validate cached data is not empty — a 0-byte cache file would
				// otherwise be served as a "hit", returning an empty body to the
				// client.  Fall through to S3 so the real content can be fetched.
				if !bodySizeMatches(cacheData, msg.Size) {
					// A 0-byte or truncated cache file (a crash mid-write, a disk that
					// filled up) must not be served as the message: S3 is the authority.
					s.WarnLog("cache body size disagrees with the message, falling through to S3",
						"uid", msg.UID, "content_hash", msg.ContentHash, "cached", len(cacheData), "expected", msg.Size)
					s.server.cache.Delete(msg.ContentHash)
				} else {
					s.DebugLog("cache hit", "uid", msg.UID)
					return cacheData, nil
				}
			}
		}

		// Fallback to S3.
		s.DebugLog("cache miss, fetching from S3", "uid", msg.UID, "content_hash", msg.ContentHash)
		data, err := s.fetchBodyFromS3(ctx, msg)
		if err != nil {
			// S3 is unavailable — fall back to the local staging file if the uploader
			// still has it.  This covers test environments (where S3 is a no-op stub)
			// and transient S3 outages where the upload worker has not yet run.
			if s.server.uploader != nil {
				filePath := s.server.uploader.FilePath(msg.ContentHash, msg.AccountID)
				if diskData, diskErr := os.ReadFile(filePath); diskErr == nil && bodySizeMatches(diskData, msg.Size) {
					s.DebugLog("S3 unavailable, served from local disk", "uid", msg.UID)
					return diskData, nil
				}
			}
			// The message is marked uploaded but S3 could not serve it and the local
			// staging copy is gone. Distinguish a transient S3 outage (network/timeout/
			// 5xx/circuit-open) from a genuinely missing object (404/NoSuchKey): on a
			// transient failure ask the client to retry instead of handing back an empty
			// body for what is really a still-present message. A NoSuchKey falls through
			// to graceful empty-body degradation (the object is permanently gone).
			// Only a genuine S3-reachability failure is transient. fetchBodyFromS3 wraps
			// such failures (network/timeout/5xx/circuit-open) in ErrRetrieveFailed; it
			// also wraps NoSuchKey there, which IsNotFoundError excludes. Permanent
			// conditions (empty/0-byte object, missing S3 key, read error) are NOT
			// ErrRetrieveFailed and must NOT be reported transient, or the client would
			// retry forever instead of degrading to an empty body.
			if errors.Is(err, storage.ErrRetrieveFailed) && !resilient.IsNotFoundError(err) && !errors.Is(err, storage.ErrCorruptObject) {
				return nil, fmt.Errorf("message UID %d: %w (S3 unavailable): %v", msg.UID, errBodyTransientlyUnavailable, err)
			}
			// Permanent. A NoSuchKey on an uploaded message is genuine content loss worth
			// alerting on — logged only here, where the message is marked uploaded (a 404
			// during the not-yet-uploaded race is expected and not logged). Either way it
			// degrades to an empty body for the caller (see loadSectionBody).
			if resilient.IsNotFoundError(err) {
				s.WarnLog("message marked uploaded but missing from S3 (NoSuchKey)", "uid", msg.UID, "content_hash", msg.ContentHash, "s3_domain", msg.S3Domain, "s3_localpart", msg.S3Localpart)
			}
			return nil, err
		}
		return data, nil
	}

	// Not yet uploaded to S3: the body should be in this node's local staging dir.
	if s.server.uploader == nil {
		return nil, fmt.Errorf("message UID %d not yet uploaded and no uploader configured", msg.UID)
	}
	s.DebugLog("fetching not yet uploaded message from disk", "uid", msg.UID)
	filePath := s.server.uploader.FilePath(msg.ContentHash, msg.AccountID)
	if data, diskErr := os.ReadFile(filePath); diskErr == nil && bodySizeMatches(data, msg.Size) {
		return data, nil
	}

	// Local staging file is missing or empty. In a multi-backend cluster the body may
	// have been delivered/staged on another node and already uploaded to S3, while this
	// node's in-memory message still reads uploaded=false.
	//
	// Decide up front whether the body is still expected to arrive — a pending upload
	// exists, or it was already uploaded elsewhere. We only wait-and-retry S3 when it is:
	// there is no point sleeping for a body that is never coming, and gating the wait this
	// way keeps a bulk FETCH over abandoned uploads from paying the delay on every message.
	pending := s.bodyUploadStillPending(ctx, msg)

	if msg.S3Domain != "" && msg.S3Localpart != "" {
		attempts := 1
		if pending {
			attempts = bodyFetchRetryAttempts
		}
		for attempt := 0; attempt < attempts; attempt++ {
			s3Data, s3Err := s.fetchBodyFromS3(ctx, msg)
			if s3Err == nil {
				s.DebugLog("local staging file missing, served from S3", "uid", msg.UID, "attempt", attempt)
				return s3Data, nil
			}
			// Only NoSuchKey ("object hasn't landed yet") benefits from waiting and
			// retrying. Any other error is either a transient outage that GetWithRetry
			// already exhausted its own backoff on (looping would just multiply that
			// latency) or a permanent condition — stop and let classification decide.
			if !resilient.IsNotFoundError(s3Err) {
				break
			}
			if attempt < attempts-1 {
				select {
				case <-time.After(bodyFetchRetryDelay):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
		}
	}

	// Still unavailable. If an upload is in flight the FETCH handler should answer
	// NO [UNAVAILABLE] (client retries); otherwise the content is genuinely gone and we
	// degrade gracefully to an empty body.
	if pending {
		return nil, fmt.Errorf("message UID %d: %w", msg.UID, errBodyTransientlyUnavailable)
	}
	return nil, fmt.Errorf("message UID %d: %w: body not on disk and not in S3", msg.UID, storage.ErrRetrieveFailed)
}

// bodyUploadStillPending reports whether the system still intends to make this body
// available — i.e. a pending_upload record exists that the upload worker will still
// lease (attempts below max_attempts), or the message has since been marked uploaded (so
// a retry should find it in S3). It distinguishes the transient read-before-upload race
// from genuine, permanent content loss. On a DB error it returns true (conservative: a
// client retry is safer than handing back an empty body that the client may treat as
// the real, empty message).
//
// A row the worker has given up on does NOT count as pending: it is never leased again
// and will be reaped, so "please retry" would be a promise nobody keeps. iOS Mail
// batches body fetches, and one such NO aborts the whole batch, every sync, forever —
// "Cannot Get Mail" for the mailbox because of one lost body.
func (s *IMAPSession) bodyUploadStillPending(ctx context.Context, msg *db.Message) bool {
	// Read the master: the pending row and the message row committed together, and a
	// replica that has not caught up would answer "no pending upload" for a body that is
	// on its way — turning "retry later" into "the body is gone" (an empty body).
	ctx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	pending, err := s.server.rdb.PendingUploadRetryableWithRetry(ctx, msg.ContentHash, msg.AccountID, s.server.uploader.MaxAttempts())
	if err != nil {
		s.WarnLog("could not check pending-upload status; treating body as transiently unavailable", "uid", msg.UID, "error", err)
		return true
	}
	if pending {
		return true
	}
	// No pending upload: the body may have just been uploaded (uploaded flipped to true
	// between our in-memory snapshot and now). If so it's transient — a retry should
	// serve it from S3 via the uploaded path.
	uploaded, err := s.server.rdb.IsContentHashUploadedWithRetry(ctx, msg.ContentHash, msg.AccountID, msg.S3Domain, msg.S3Localpart)
	if err != nil {
		s.WarnLog("could not check uploaded status; treating body as transiently unavailable", "uid", msg.UID, "error", err)
		return true
	}
	return uploaded
}

// fetchBodyFromS3 retrieves a message body from S3 using the key components
// stored on the message record (which guard against the user's primary address
// changing after the message was stored). It validates the payload is non-empty
// and warms the local cache on success.
func (s *IMAPSession) fetchBodyFromS3(ctx context.Context, msg *db.Message) ([]byte, error) {
	if msg.S3Domain == "" || msg.S3Localpart == "" {
		return nil, fmt.Errorf("message UID %d is missing S3 key information", msg.UID)
	}
	s3Key := helpers.NewS3Key(msg.S3Domain, msg.S3Localpart, msg.ContentHash)

	// One body fetch gets one operation timeout, retries and body read included. The
	// resilient layer retries a GET up to four times with backoff and each attempt may
	// run to the S3 timeout, so an unbounded read against a hanging provider held a
	// FETCH for minutes — long past the point where Apple Mail reports the server as
	// not responding. The bound turns that into a prompt NO [UNAVAILABLE] the client
	// can act on, and honoring ctx means a client that hangs up ends the read at once.
	ctx, cancel := context.WithTimeout(ctx, s.server.s3.OperationTimeout())
	defer cancel()

	// Guard against a nil-client panic (e.g. test stubs using &storage.S3Storage{})
	// so it becomes an error rather than killing the connection goroutine.
	var reader io.ReadCloser
	var s3GetErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				s3GetErr = fmt.Errorf("S3 get panicked: %v", r)
			}
		}()
		reader, s3GetErr = s.server.s3.GetWithRetry(ctx, s3Key)
	}()
	if s3GetErr != nil {
		s.DebugLog("S3 GetWithRetry failed", "uid", msg.UID, "s3_key", s3Key, "error", s3GetErr)
		return nil, fmt.Errorf("message UID %d: %w: %w", msg.UID, storage.ErrRetrieveFailed, s3GetErr)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		s.DebugLog("failed to read S3 response", "uid", msg.UID, "error", err)
		return nil, err
	}
	if len(data) == 0 {
		s.WarnLog("S3 returned empty data", "uid", msg.UID, "s3_key", s3Key, "expected_size", msg.Size,
			"get_breaker_state", s.server.s3.GetGetBreakerState())
		return nil, fmt.Errorf("message UID %d (expected %d bytes): %w", msg.UID, msg.Size, storage.ErrEmptyData)
	}

	s.DebugLog("successfully fetched from S3", "uid", msg.UID, "size", len(data))
	if s.server.cache != nil {
		_ = s.server.cache.Put(msg.ContentHash, data)
	}
	return data, nil
}

// convertUIDsToRanges converts a sorted slice of UIDs into UIDSet ranges.
// This optimizes network transmission by grouping consecutive UIDs.
// Example: [1,2,3,5,6,10] -> [{Start:1, Stop:3}, {Start:5, Stop:6}, {Start:10, Stop:10}]
func convertUIDsToRanges(uids []imap.UID) imap.UIDSet {
	if len(uids) == 0 {
		return imap.UIDSet{}
	}

	// Count the ranges first: a long run of consecutive UIDs is one range.
	n := 1
	for i := 1; i < len(uids); i++ {
		if uids[i] != uids[i-1]+1 {
			n++
		}
	}
	uidSet := make(imap.UIDSet, 0, n)
	start := uids[0]
	prev := uids[0]

	for i := 1; i < len(uids); i++ {
		if uids[i] != prev+1 {
			// End of range
			uidSet = append(uidSet, imap.UIDRange{Start: start, Stop: prev})
			start = uids[i]
		}
		prev = uids[i]
	}

	// Add final range
	uidSet = append(uidSet, imap.UIDRange{Start: start, Stop: prev})
	return uidSet
}
