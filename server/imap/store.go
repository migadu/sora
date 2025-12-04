package imap

import (
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/helpers"
)

func (s *IMAPSession) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	// First, safely read session state with a single mutex acquisition
	var selectedMailboxID int64
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

	selectedMailboxID = s.selectedMailbox.ID

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

	// Check ACL permissions based on which flags are being modified
	// Need 'w' (write) for general flags, 's' (seen) for \Seen, 't' (delete-msg) for \Deleted
	var needsWrite, needsSeen, needsDelete bool
	for _, flag := range sanitizedFlags {
		switch flag {
		case imap.FlagSeen:
			needsSeen = true
		case imap.FlagDeleted:
			needsDelete = true
		default:
			needsWrite = true
		}
	}

	// Check required permissions
	if needsWrite {
		hasWriteRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, selectedMailboxID, s.AccountID(), 'w')
		if err != nil {
			return s.internalError("failed to check write permission: %v", err)
		}
		if !hasWriteRight {
			s.DebugLog("user does not have write permission")
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNoPerm,
				Text: "You do not have permission to modify flags on this mailbox",
			}
		}
	}
	if needsSeen {
		hasSeenRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, selectedMailboxID, s.AccountID(), 's')
		if err != nil {
			return s.internalError("failed to check seen permission: %v", err)
		}
		if !hasSeenRight {
			s.DebugLog("user does not have seen permission")
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNoPerm,
				Text: "You do not have permission to modify \\Seen flag on this mailbox",
			}
		}
	}
	if needsDelete {
		hasDeleteRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, selectedMailboxID, s.AccountID(), 't')
		if err != nil {
			return s.internalError("failed to check delete permission: %v", err)
		}
		if !hasDeleteRight {
			s.DebugLog("user does not have delete permission")
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNoPerm,
				Text: "You do not have permission to modify \\Deleted flag on this mailbox",
			}
		}
	}

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
				continue
			}
		}

		var newFlags []imap.Flag
		var newModSeq int64
		switch sanitizedStoreFlags.Op {
		case imap.StoreFlagsAdd:
			newFlags, newModSeq, err = s.server.rdb.AddMessageFlagsWithRetry(s.ctx, msg.UID, msg.MailboxID, sanitizedStoreFlags.Flags)
		case imap.StoreFlagsDel:
			newFlags, newModSeq, err = s.server.rdb.RemoveMessageFlagsWithRetry(s.ctx, msg.UID, msg.MailboxID, sanitizedStoreFlags.Flags)
		case imap.StoreFlagsSet:
			newFlags, newModSeq, err = s.server.rdb.SetMessageFlagsWithRetry(s.ctx, msg.UID, msg.MailboxID, sanitizedStoreFlags.Flags)
		}

		if err != nil {
			return s.internalError("failed to update flags for message: %v", err)
		}

		if newModSeq == 0 { // Should not happen if DB functions are correct
			s.DebugLog("message received zero MODSEQ after flag update", "uid", msg.UID)
		}

		s.DebugLog("operation updated message", "uid", msg.UID, "new_modseq", newModSeq)

		modifiedMessages = append(modifiedMessages, struct {
			seq    uint32
			uid    imap.UID
			flags  []imap.Flag
			modSeq int64
		}{
			seq:    msg.Seq,
			uid:    msg.UID,
			flags:  newFlags,
			modSeq: newModSeq,
		})
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
	currentSessionTracker := s.sessionTracker // Get the current session tracker
	release()

	if !sanitizedStoreFlags.Silent && currentSessionTracker != nil {
		for _, modified := range modifiedMessages {
			m := w.CreateMessage(currentSessionTracker.EncodeSeqNum(modified.seq))

			m.WriteFlags(modified.flags)
			m.WriteUID(modified.uid)
			// CONDSTORE: Include MODSEQ in response if capability is enabled
			if s.GetCapabilities().Has(imap.CapCondStore) {
				m.WriteModSeq(uint64(modified.modSeq))
			}

			if err := m.Close(); err != nil {
				s.DebugLog("failed to close fetch response", "uid", modified.uid, "error", err)
			}
		}
	}

	return nil
}
