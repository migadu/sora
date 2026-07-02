package imap

import (
	"fmt"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
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

func (s *IMAPSession) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	// First, safely read session state with a single mutex acquisition
	var selectedMailboxID int64
	var selectedMailboxOwnerID int64
	var decodedNumSet imap.NumSet

	// Acquire read mutex to safely read session state
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
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

	// Capture modseq before unlocking
	modSeqSnapshot := s.currentHighestModSeq.Load()

	// Use our helper method that assumes the mutex is held (read lock is sufficient)
	decodedNumSet = s.decodeNumSetLocked(numSet)
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

	// RFC 4314 §4: STORE requires 's' to modify \Seen, 't' for \Deleted, and 'w'
	// for all other flags. Fetch the user's rights once (owner fast-path).
	storeRights, err := s.userRightsForMailbox(s.ctx, selectedMailboxID, selectedMailboxOwnerID)
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
	}
	// Note: STORE FLAGS (replace) does not reject here. RFC 4314 §4 forbids modifying
	// flags the user lacks rights for; a naive replace would also clear UNLISTED flags.
	// The apply step below preserves the current value of each non-modifiable flag.

	// Perform database operations outside of lock
	messages, err := s.server.rdb.GetMessagesByNumSetWithRetry(s.ctx, selectedMailboxID, decodedNumSet)
	if err != nil {
		return s.internalError("failed to retrieve messages: %v", err)
	}

	// Check if mailbox changed during our operation
	if modSeqSnapshot > 0 && s.currentHighestModSeq.Load() > modSeqSnapshot {
		s.DebugLog("mailbox changed during STORE operation", "old_modseq", modSeqSnapshot, "new_modseq", s.currentHighestModSeq.Load())
		// For sequence sets, this could mean we're updating wrong messages
		if _, isSeqSet := numSet.(imap.SeqSet); isSeqSet {
			// Re-decode and re-fetch to ensure consistency
			decodedNumSet = s.decodeNumSet(numSet) // This will re-lock, but it's a rare case
			messages, err = s.server.rdb.GetMessagesByNumSetWithRetry(s.ctx, selectedMailboxID, decodedNumSet)
			if err != nil {
				return s.internalError("failed to retrieve messages: %v", err)
			}
		}
	}

	var modifiedMessages []struct {
		seq    uint32
		uid    imap.UID
		flags  []imap.Flag
		modSeq int64
	}

	// Check if the context is still valid before proceeding with flag updates
	if s.ctx.Err() != nil {
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
		if s.GetCapabilities().Has(imap.CapCondStore) && options != nil && options.UnchangedSince > 0 {
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
				failedSeqs.AddNum(msg.Seq)
				continue
			}
		}

		validUIDs = append(validUIDs, msg.UID)
		seqMap[msg.UID] = msg.Seq

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
			resulting = replaceTargetFlags(cur, sanitizedStoreFlags.Flags, storeRights)
		}
		if db.DistinctKeywordCount(resulting) > db.MaxCustomKeywordsPerMessage {
			return keywordLimitExceededError()
		}
	}

	if len(validUIDs) > 0 {
		var batchResults []db.BatchFlagUpdateResult
		switch sanitizedStoreFlags.Op {
		case imap.StoreFlagsAdd:
			batchResults, err = s.server.rdb.AddMessageFlagsBatchWithRetry(s.ctx, validUIDs, selectedMailboxID, sanitizedStoreFlags.Flags)
		case imap.StoreFlagsDel:
			batchResults, err = s.server.rdb.RemoveMessageFlagsBatchWithRetry(s.ctx, validUIDs, selectedMailboxID, sanitizedStoreFlags.Flags)
		case imap.StoreFlagsSet:
			// RFC 4314 §4: a replace must not modify flags the user lacks rights for.
			// Per message, compute the target = requested values for modifiable flags
			// + preserved current values for the rest, then SET each distinct target
			// as one batch. For the owner (full rights) every message's target equals
			// the requested set, collapsing to a single batch (no behaviour change).
			currentByUID := make(map[imap.UID][]imap.Flag, len(messages))
			for _, msg := range messages {
				cur := db.BitwiseToFlags(msg.BitwiseFlags)
				for _, cf := range msg.CustomFlags {
					cur = append(cur, imap.Flag(cf))
				}
				currentByUID[msg.UID] = cur
			}
			groupUIDs := make(map[string][]imap.UID)
			groupFlags := make(map[string][]imap.Flag)
			for _, uid := range validUIDs {
				target := replaceTargetFlags(currentByUID[uid], sanitizedStoreFlags.Flags, storeRights)
				key := flagSetKey(target)
				groupUIDs[key] = append(groupUIDs[key], uid)
				groupFlags[key] = target
			}
			for key, uids := range groupUIDs {
				var res []db.BatchFlagUpdateResult
				res, err = s.server.rdb.SetMessageFlagsBatchWithRetry(s.ctx, uids, selectedMailboxID, groupFlags[key])
				if err != nil {
					break
				}
				batchResults = append(batchResults, res...)
			}
		}

		if err != nil {
			return s.internalError("failed to update flags for batch: %v", err)
		}

		for _, res := range batchResults {
			modifiedMessages = append(modifiedMessages, struct {
				seq    uint32
				uid    imap.UID
				flags  []imap.Flag
				modSeq int64
			}{
				seq:    seqMap[res.UID],
				uid:    res.UID,
				flags:  res.Flags,
				modSeq: res.ModSeq,
			})
			s.DebugLog("operation updated message", "uid", res.UID, "new_modseq", res.ModSeq)
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
		if !sanitizedStoreFlags.Silent {
			for _, modified := range modifiedMessages {
				m := w.CreateMessage(modified.seq)
				m.WriteFlags(modified.flags)
				m.WriteUID(modified.uid)
				if s.condStoreEnabled() {
					m.WriteModSeq(uint64(modified.modSeq))
				}
				if err := m.Close(); err != nil {
					s.DebugLog("failed to close fetch response", "uid", modified.uid, "error", err)
				}
			}
		}

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
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted after flag updates, response will be incomplete")
		return nil
	}

	// Re-acquire read mutex to access session tracker for encoding sequence numbers in the response
	acquired, release = s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.DebugLog("failed to acquire second read lock within timeout")
		return nil // Continue without sending responses since we already updated the flags
	}
	release()

	if !sanitizedStoreFlags.Silent {
		for _, modified := range modifiedMessages {
			// Use database sequence number directly (no encoding needed)
			m := w.CreateMessage(modified.seq)

			m.WriteFlags(modified.flags)
			m.WriteUID(modified.uid)
			// RFC 7162 §3.2: include MODSEQ in the STORE-triggered FETCH reply only
			// when the client is CONDSTORE-aware (issued an enabling command) and the
			// session still advertises CONDSTORE.
			if s.condStoreEnabled() {
				m.WriteModSeq(uint64(modified.modSeq))
			}

			if err := m.Close(); err != nil {
				s.DebugLog("failed to close fetch response", "uid", modified.uid, "error", err)
			}
		}
	}

	return nil
}
