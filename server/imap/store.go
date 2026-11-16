package imap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
)

// keywordLimitExceededError is returned when a STORE would push a message past
// the per-message keyword cap. RFC 5530's [LIMIT] is the response code for
// exactly this ("the number of flags on a message"), so the client gets a
// clear, standard signal rather than a silently-dropped keyword.
func keywordLimitExceededError() *imap.Error {
	return &imap.Error{
		Type: imap.StatusResponseTypeNo,
		Code: imap.ResponseCodeLimit,
		Text: fmt.Sprintf("Too many keywords on a message (maximum %d)", db.MaxCustomKeywordsPerMessage),
	}
}

func (s *IMAPSession) Store(ctx context.Context, w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	// The client's numbering holds still until the last response (seqViewMu).
	s.seqViewMu.RLock()
	defer s.seqViewMu.RUnlock()

	// First, safely read session state with a single mutex acquisition
	var selectedMailboxID int64
	var selectedMailboxOwnerID int64
	var decodedNumSet imap.NumSet

	// Acquire read mutex to safely read session state
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		s.DebugLog("failed to acquire read lock within timeout")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}

	if s.selectedMailbox == nil {
		release()
		s.DebugLog("store failed: no mailbox selected")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "no mailbox selected",
		}
	}

	// RFC 3501 §6.3.2: no changes to the selected mailbox are permitted when it
	// was opened with EXAMINE (read-only).
	if s.selectedReadOnly.Load() {
		release()
		s.DebugLog("store rejected: mailbox opened read-only (EXAMINE)")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCode("READ-ONLY"),
			Text: "Mailbox is read-only (opened with EXAMINE)",
		}
	}

	selectedMailboxID = s.selectedMailbox.ID
	selectedMailboxOwnerID = s.selectedMailbox.AccountID
	// RFC 3501 §6.4.6: the new flags are returned "as if a FETCH of those
	// flags was done", \Recent included.
	recentAbove := s.recentFlagAboveLocked()
	view := s.seqViewLocked()
	decodedNumSet = s.decodeNumSetLocked(view, numSet)
	release()

	// Sanitize flags to remove invalid values (e.g., NIL, NULL, empty strings)
	// This prevents protocol errors like "Keyword used without being in FLAGS: NIL"
	sanitizedFlags := helpers.SanitizeFlags(flags.Flags)

	// Create a sanitized StoreFlags structure
	sanitizedStoreFlags := &imap.StoreFlags{
		Op:     flags.Op,
		Silent: flags.Silent,
		Flags:  sanitizedFlags,
	}

	if s.useMasterDB.Load() {
		ctx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	}
	// Neither the capabilities nor the client's CONDSTORE awareness change
	// during the command: read them once, not for every message (#1206).
	checkUnchangedSince := options != nil && options.UnchangedSinceSet && s.GetCapabilities().Has(imap.CapCondStore)
	writeModSeq := s.condStoreEnabled()
	var unchangedSince []uint64
	if checkUnchangedSince {
		unchangedSince = []uint64{options.UnchangedSince}
	}

	// RFC 4314 §4: STORE requires 's' to modify \Seen, 't' for \Deleted, and 'w'
	// for all other flags. Fetch the user's rights once (owner fast-path).
	storeRights, err := s.userRightsForMailbox(ctx, selectedMailboxID, selectedMailboxOwnerID)
	if err != nil {
		return s.internalError("failed to get user rights for mailbox: %v", err)
	}

	if sanitizedStoreFlags.Op != imap.StoreFlagsSet {
		// Add (+FLAGS) / Del (-FLAGS) only touch the listed flags. RFC 4314 §4:
		// STORE SHOULD NOT fail if the user can modify at least one specified flag,
		// so apply the permitted subset and silently drop the rest; fail only when
		// the user can modify none of them.
		permitted := filterFlagsByRights(sanitizedFlags, storeRights)
		if len(permitted) == 0 && len(sanitizedFlags) > 0 {
			s.DebugLog("user lacks permission to modify any of the specified flags")
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNoPerm,
				Text: "You do not have permission to modify the specified flags",
			}
		}
		sanitizedFlags = permitted
		sanitizedStoreFlags.Flags = permitted
	} else if !strings.ContainsAny(storeRights, "stw") {
		// A replace addresses every flag, listed or not, so it fails only when the
		// user can modify no flag at all.
		s.DebugLog("user lacks permission to modify any flag")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to modify the specified flags",
		}
	}
	// Note: STORE FLAGS (replace) does not reject a user holding only some of the
	// flag rights. RFC 4314 §4 forbids modifying flags the user lacks rights for; a
	// naive replace would also clear UNLISTED flags. The apply step below preserves
	// the current value of each non-modifiable flag.

	// RFC 9979 §3.2: unflagging also clears the flag color keywords (see
	// flag_color.go).
	if sanitizedStoreFlags.Op == imap.StoreFlagsDel {
		sanitizedStoreFlags.Flags = withColorsOnUnflag(sanitizedStoreFlags.Flags)
	}

	// Perform database operations outside of lock
	messages, err := s.server.rdb.GetMessagesByNumSetWithRetry(view.context(ctx), selectedMailboxID, decodedNumSet)
	if err != nil {
		return s.internalError("failed to retrieve messages: %v", err)
	}

	type storeResponseMessage struct {
		seq        uint32
		uid        imap.UID
		flags      []imap.Flag
		modSeq     int64
		prevModSeq int64 // before this STORE's write; unset when unchanged
		unchanged  bool
	}
	var responseMessages []storeResponseMessage

	// RFC 9051 §6.4.6: a non-silent STORE returns the updated flags in an
	// untagged FETCH, and RFC 7162 §3.1.3 gives a CONDSTORE-aware client FETCH
	// (MODSEQ) for every message a .SILENT STORE updated. That is command
	// response data, so STORE writes it itself rather than leaving it to the
	// command-boundary Poll, which would add FLAGS to a .SILENT answer, is
	// skipped under NOTIFY, and stops at a pending expunge. Poll is held off
	// until the answered rows are recorded in ownStoreEcho, so it does not
	// report them a second time.
	silentModSeq := sanitizedStoreFlags.Silent && writeModSeq
	answers := !sanitizedStoreFlags.Silent || silentModSeq
	if answers {
		s.ownStoreMu.Lock()
		defer s.ownStoreMu.Unlock()
	}
	writeResponses := func() {
		if !answers {
			return
		}
		for _, modified := range responseMessages {
			// A message the client has not been told about has no number to be
			// answered under; Poll reports it once the client knows it.
			if modified.seq == 0 {
				continue
			}
			m := w.CreateMessage(modified.seq)

			if !sanitizedStoreFlags.Silent {
				m.WriteFlags(withRecentFlag(modified.flags, modified.uid, recentAbove))
			}
			m.WriteUID(modified.uid)
			// RFC 7162 §3.2: include MODSEQ in the STORE-triggered FETCH reply only
			// when the client is CONDSTORE-aware (issued an enabling command) and the
			// session still advertises CONDSTORE.
			if writeModSeq {
				m.WriteModSeq(uint64(modified.modSeq))
			}

			if err := m.Close(); err != nil {
				s.DebugLog("failed to close fetch response", "uid", modified.uid, "error", err)
				continue
			}
			// Record the rows this answer told the client all Poll would: every
			// row when it carried FLAGS. A .SILENT (MODSEQ only) answer says
			// nothing about what another session changed, so it covers only a
			// row this STORE changed from a state the client already had: at or
			// below the poll cursor, or this session's own previous answer.
			// Otherwise Poll reports the flags (RFC 9051 §6.4.6 Note).
			if !sanitizedStoreFlags.Silent || (!modified.unchanged && s.clientHasModSeqLocked(view.tracker, selectedMailboxID, modified.uid, modified.prevModSeq)) {
				s.recordOwnStoreEchoLocked(view.tracker, selectedMailboxID, modified.uid, uint64(modified.modSeq))
			}
		}
	}

	// Check if the context is still valid before proceeding with flag updates
	if ctx.Err() != nil {
		s.DebugLog("request aborted before flag updates")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "Session closed during store operation",
		}
	}

	// Track messages that fail the UNCHANGEDSINCE precondition (RFC 7162 §3.1.3).
	// Both number spaces are collected so the MODIFIED response can use the same
	// space as the command: sequence numbers for a sequence STORE, UIDs for UID STORE.
	var failedUIDs imap.UIDSet
	var failedSeqs imap.SeqSet

	var validUIDs []imap.UID
	seqMap := make(map[imap.UID]uint32)

	for _, msg := range messages {
		// CONDSTORE functionality - only process if capability is enabled
		// UnchangedSinceSet, not a non-zero value, is what marks the modifier as
		// present: RFC 7162 §3.1.3 gives "UNCHANGEDSINCE 0" the opposite meaning
		// to an absent modifier -- it is the probe that must fail for every message
		// -- so reading it as absent would modify exactly the messages the client
		// asked never to touch.
		if checkUnchangedSince {
			var currentModSeq int64
			currentModSeq = msg.CreatedModSeq

			if msg.UpdatedModSeq != nil && *msg.UpdatedModSeq > currentModSeq {
				currentModSeq = *msg.UpdatedModSeq
			}

			if msg.ExpungedModSeq != nil && *msg.ExpungedModSeq > currentModSeq {
				currentModSeq = *msg.ExpungedModSeq
			}

			if uint64(currentModSeq) > options.UnchangedSince {
				s.DebugLog("CONDSTORE skipping message", "uid", msg.UID, "modseq", currentModSeq, "unchanged_since", options.UnchangedSince)
				failedUIDs.AddNum(msg.UID)
				if seq := view.encode(msg.Seq); seq != 0 {
					failedSeqs.AddNum(seq) // 0 would read as "*"
				}
				continue
			}
		}

		validUIDs = append(validUIDs, msg.UID)
		// The client's number for the message, 0 if it has none (seqView.encode).
		seqMap[msg.UID] = view.encode(msg.Seq)

		// RFC 5530 [LIMIT]: reject a STORE that would push this message past the
		// per-message keyword cap, rather than silently dropping keywords (which
		// would falsely report success). -FLAGS only removes keywords, so skip it.
		// This runs before any write, so an over-limit STORE applies nothing.
		var resulting []imap.Flag
		switch sanitizedStoreFlags.Op {
		case imap.StoreFlagsAdd:
			resulting = make([]imap.Flag, 0, len(msg.CustomFlags)+len(sanitizedStoreFlags.Flags))
			for _, cf := range msg.CustomFlags {
				resulting = append(resulting, imap.Flag(cf))
			}
			resulting = append(resulting, sanitizedStoreFlags.Flags...)
		case imap.StoreFlagsSet:
			cur := db.BitwiseToFlags(msg.BitwiseFlags)
			for _, cf := range msg.CustomFlags {
				cur = append(cur, imap.Flag(cf))
			}
			resulting = storeReplaceTarget(cur, sanitizedStoreFlags.Flags, storeRights)
		}
		resulting = db.NormalizeAttachmentKeywordUpdate(resulting, sanitizedStoreFlags.Flags)
		if db.DistinctKeywordCount(resulting) > db.MaxCustomKeywordsPerMessage {
			return keywordLimitExceededError()
		}
	}

	if len(validUIDs) > 0 {
		var batchResults []db.BatchFlagUpdateResult
		switch sanitizedStoreFlags.Op {
		case imap.StoreFlagsAdd:
			batchResults, err = s.server.rdb.AddMessageFlagsBatchWithRetry(ctx, validUIDs, selectedMailboxID, sanitizedStoreFlags.Flags, unchangedSince...)
		case imap.StoreFlagsDel:
			batchResults, err = s.server.rdb.RemoveMessageFlagsBatchWithRetry(ctx, validUIDs, selectedMailboxID, sanitizedStoreFlags.Flags, unchangedSince...)
		case imap.StoreFlagsSet:
			// RFC 4314 §4: a replace must not modify flags the user lacks rights for.
			// Merge protected values from current rows inside the write transaction,
			// rather than overwriting concurrent changes with this read snapshot.
			batchResults, err = s.server.rdb.SetMessageFlagsBatchWithRightsWithRetry(ctx, validUIDs, selectedMailboxID, sanitizedStoreFlags.Flags, storeRights, unchangedSince...)
		}

		if err != nil {
			if errors.Is(err, consts.ErrTooManyKeywords) {
				return keywordLimitExceededError()
			}
			return s.internalError("failed to update flags for batch: %v", err)
		}

		for _, res := range batchResults {
			if res.PreconditionFailed {
				failedUIDs.AddNum(res.UID)
				if seq := seqMap[res.UID]; seq != 0 {
					failedSeqs.AddNum(seq) // 0 would read as "*"
				}
				continue
			}
			responseMessages = append(responseMessages, storeResponseMessage{
				seq:        seqMap[res.UID],
				uid:        res.UID,
				flags:      res.Flags,
				modSeq:     res.ModSeq,
				prevModSeq: res.PrevModSeq,
			})
			s.DebugLog("operation updated message", "uid", res.UID, "new_modseq", res.ModSeq)
		}

		// Pin this session to the master DB to ensure read-your-writes consistency
		// so a subsequent FETCH or SEARCH in this session reads the new flags from
		// the master rather than a lagging read replica.
		s.useMasterDB.Store(true)

		// RFC 9051 §6.4.6: non-silent STORE returns the resulting flags as a
		// FETCH, including when normalization rejected a requested keyword but
		// left the stored state unchanged. Batch updates omit such no-op rows.
		// Read them from the master so a concurrent writer's flags are current;
		// only validUIDs are eligible, preserving UNCHANGEDSINCE failures.
		if answers && len(batchResults) < len(validUIDs) {
			changed := make(map[imap.UID]bool, len(batchResults))
			for _, res := range batchResults {
				changed[res.UID] = true
			}
			var unchanged imap.UIDSet
			for _, uid := range validUIDs {
				if !changed[uid] {
					unchanged.AddNum(uid)
				}
			}
			readCtx := context.WithValue(ctx, consts.UseMasterDBKey, true)
			current, err := s.server.rdb.GetMessagesByNumSetWithRetry(readCtx, selectedMailboxID, unchanged)
			if err != nil {
				return s.internalError("failed to read unchanged STORE flags: %v", err)
			}
			for _, msg := range current {
				flags := db.BitwiseToFlags(msg.BitwiseFlags)
				for _, flag := range msg.CustomFlags {
					flags = append(flags, imap.Flag(flag))
				}
				modSeq := msg.CreatedModSeq
				if msg.UpdatedModSeq != nil {
					modSeq = max(modSeq, *msg.UpdatedModSeq)
				}
				responseMessages = append(responseMessages, storeResponseMessage{seq: seqMap[msg.UID], uid: msg.UID, flags: flags, modSeq: modSeq, unchanged: true})
			}
		}
	}

	// RFC 7162 §3.1.3: report messages that failed the UNCHANGEDSINCE precondition
	// in a MODIFIED response code, after the FETCH responses for the messages that
	// DID update. The tagged response is OK, not NO: the STORE succeeded for the
	// passing messages and merely skipped the ones whose mod-sequence changed (see
	// the "d105 ... OK [MODIFIED 7,9]" example). NO [MODIFIED] is reserved for the
	// distinct case where targeted messages no longer exist — which cannot happen
	// here, since expunged messages are absent from GetMessagesByNumSet and never
	// enter the failed set.
	if len(failedUIDs) > 0 {
		s.DebugLog("CONDSTORE: returning MODIFIED for failed UIDs", "uids", failedUIDs.String())

		// Still send FETCH responses for successfully modified messages (before the OK).
		writeResponses()

		// RFC 7162 §3.1.3: the MODIFIED set uses the command's number space —
		// sequence numbers for a sequence-number STORE, UIDs for a UID STORE.
		modifiedSet := failedUIDs.String()
		if _, isSeqStore := numSet.(imap.SeqSet); isSeqStore {
			modifiedSet = failedSeqs.String()
		}
		return &imap.Error{
			Type: imap.StatusResponseTypeOK,
			Code: imap.ResponseCode(fmt.Sprintf("MODIFIED %s", modifiedSet)),
			Text: "UNCHANGEDSINCE precondition failed for some messages",
		}
	}

	// Before responding with fetches, check if context is still valid
	if ctx.Err() != nil {
		s.DebugLog("request aborted after flag updates, response will be incomplete")
		return nil
	}

	writeResponses()

	return nil
}

// clientHasModSeqLocked reports whether the client already has message uid's
// state as of modSeq: Poll has delivered every change up to its cursor when the
// session tracker holds no queued updates, and ownStoreEcho holds the states
// this session's own STORE or FETCH answers gave the client. The caller holds
// ownStoreMu, which Poll holds while it advances the cursor and queues the
// changes.
func (s *IMAPSession) clientHasModSeqLocked(tracker *imapserver.SessionTracker, mailboxID int64, uid imap.UID, modSeq int64) bool {
	if tracker == nil || tracker.QueuedUpdates() > 0 {
		return false
	}
	if uint64(modSeq) <= s.currentHighestModSeq.Load() {
		return true
	}
	echoed, ok := s.ownStoreEcho[uid]
	return ok && s.ownStoreEchoMailboxID == mailboxID && echoed == uint64(modSeq)
}

// recordOwnStoreEchoLocked records that this session's STORE already answered
// message uid as of modSeq, so Poll skips repeating that exact state. Nothing
// is recorded while the session tracker holds queued updates from an earlier
// Poll or while a concurrent FETCH (e.g. NOTIFY MessageNew fetch-atts) is in
// flight, because an older state of uid may still be flushed after STORE's
// response and Poll must queue the current state behind it.
func (s *IMAPSession) recordOwnStoreEchoLocked(tracker *imapserver.SessionTracker, mailboxID int64, uid imap.UID, modSeq uint64) {
	if tracker == nil || tracker.QueuedUpdates() > 0 || s.fetchInFlight > 0 {
		return
	}
	entries := 1
	if s.ownStoreEchoMailboxID == mailboxID {
		entries = len(s.ownStoreEcho)
		if _, exists := s.ownStoreEcho[uid]; !exists {
			entries++
		}
	}
	// This metadata is optional: use the same conservative map-space estimate
	// as implicitSeenAnswer.expect without reclaiming body cache or changing
	// response budgets.
	if entries > maxFetchSeenEchoEntries || (s.memTracker != nil && !s.memTracker.CanAllocate(256+64*int64(entries))) {
		return
	}
	if s.ownStoreEcho == nil || s.ownStoreEchoMailboxID != mailboxID {
		s.ownStoreEcho = make(map[imap.UID]uint64)
		s.ownStoreEchoMailboxID = mailboxID
	}
	s.ownStoreEcho[uid] = modSeq
}
