package imap

import (
	"context"
	"errors"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

func (s *IMAPSession) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	// If the session is closing, don't try to poll.
	if s.ctx.Err() != nil {
		s.DebugLog("session context is cancelled, skipping poll")
		return nil
	}

	// First phase: Read state with read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.DebugLog("failed to acquire read lock within timeout")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}

	if s.selectedMailbox == nil || s.mailboxTracker == nil || s.sessionTracker == nil {
		release()
		return nil
	}
	mailboxID := s.selectedMailbox.ID
	highestModSeqToPollFrom := s.currentHighestModSeq.Load()
	release()

	// Create a context that signals to use the master DB if the session is pinned.
	readCtx := s.ctx
	if s.useMasterDB {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	poll, err := s.server.rdb.PollMailboxWithRetry(readCtx, mailboxID, highestModSeqToPollFrom)
	if err != nil {
		// If mailbox was deleted, clear the selected mailbox state and return nil
		// The next command that requires a selected mailbox will fail with "No mailbox selected"
		if errors.Is(err, db.ErrMailboxNotFound) {
			s.WarnLog("selected mailbox was deleted, clearing selection", "mailbox_id", mailboxID)
			// Acquire write lock to safely clear state
			acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
			if acquired {
				s.clearSelectedMailboxStateLocked()
				release()
			}
			return nil // Return success - no updates to send
		}
		return s.internalError("failed to poll mailbox: %v", err)
	}

	acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.DebugLog("failed to acquire write lock within timeout")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}

	if s.selectedMailbox == nil || s.selectedMailbox.ID != mailboxID || s.mailboxTracker == nil || s.sessionTracker == nil {
		release()
		return nil
	}

	// Determine the highest MODSEQ from the updates processed in this poll.
	// Start with the MODSEQ we polled from, in case no updates are found.
	maxModSeqInThisPoll := highestModSeqToPollFrom
	if len(poll.Updates) > 0 {
		for _, update := range poll.Updates {
			if update.EffectiveModSeq > maxModSeqInThisPoll {
				maxModSeqInThisPoll = update.EffectiveModSeq
			}
		}
		s.currentHighestModSeq.Store(maxModSeqInThisPoll)
	} else {
		// If there were no specific message updates, update to the global current_modseq
		// to ensure the session eventually catches up if the mailbox is truly idle.
		s.currentHighestModSeq.Store(poll.ModSeq)
	}

	// First, check for state desync and update message count if needed
	currentCount := s.currentNumMessages.Load()
	if poll.NumMessages > currentCount {
		// New messages arrived
		s.DebugLog("updating message count", "old_count", currentCount, "new_count", poll.NumMessages)
		s.mailboxTracker.QueueNumMessages(poll.NumMessages)
		s.currentNumMessages.Store(poll.NumMessages)
	} else if poll.NumMessages < currentCount {
		// Database has fewer messages - check if there are expunge updates to explain it
		hasExpungeUpdates := false
		for _, update := range poll.Updates {
			if update.IsExpunge {
				hasExpungeUpdates = true
				break
			}
		}

		if !hasExpungeUpdates {
			// No expunge updates but database has fewer messages.
			// This can happen when:
			// 1. Messages were expunged between SELECT and first poll (missed in this poll)
			// 2. External deletion (direct DB manipulation)
			// 3. Replica lag
			// We'll handle this in the final reconciliation after processing updates
			s.DebugLog("database has fewer messages with no expunge updates in this poll",
				"session_count", currentCount, "db_count", poll.NumMessages,
				"will_reconcile_after_processing", true)
		}
	}

	// Group updates by sequence number to detect duplicate expunges
	expungedSeqNums := make(map[uint32]bool)
	skippedExpunges := 0

	// Process expunge updates
	for _, update := range poll.Updates {
		if !update.IsExpunge {
			continue
		}

		// Check if we've already processed an expunge for this sequence number
		if expungedSeqNums[update.SeqNum] {
			s.DebugLog("skipping duplicate expunge update", "seq", update.SeqNum, "uid", update.UID)
			skippedExpunges++
			continue
		}

		// Validate sequence number is within range
		currentMessages := s.currentNumMessages.Load()
		if update.SeqNum == 0 || update.SeqNum > currentMessages {
			s.DebugLog("expunge sequence number out of range, skipping", "seq", update.SeqNum, "uid", update.UID, "mailbox_messages", currentMessages)
			skippedExpunges++
			continue
		}

		s.DebugLog("processing expunge update", "seq", update.SeqNum, "uid", update.UID)
		s.mailboxTracker.QueueExpunge(update.SeqNum)
		// Atomically decrement the current number of messages
		s.currentNumMessages.Add(^uint32(0)) // Equivalent to -1 for unsigned

		// Mark this sequence number as already expunged to prevent duplicates
		expungedSeqNums[update.SeqNum] = true
	}

	// Final reconciliation: ensure session count matches database count
	// After processing all expunge updates, the session count should match the database.
	finalCount := s.currentNumMessages.Load()
	if poll.NumMessages < finalCount {
		// Database has fewer messages than session after processing expunges.
		diff := finalCount - poll.NumMessages

		// Count actual expunge updates processed (not skipped)
		processedExpunges := 0
		for _, update := range poll.Updates {
			if update.IsExpunge && expungedSeqNums[update.SeqNum] {
				// This expunge was processed (marked in expungedSeqNums map)
				processedExpunges++
			}
			// Note: Skipped expunges (!expungedSeqNums[update.SeqNum]) are already counted in skippedExpunges
		}

		// Determine if the mismatch can be safely reconciled
		canReconcile := false
		reconcileReason := ""

		if skippedExpunges > 0 && diff <= uint32(skippedExpunges) {
			// Explained by skipped duplicate/out-of-range expunges
			canReconcile = true
			reconcileReason = "skipped_expunges"
		} else if processedExpunges == 0 && diff <= 10 {
			// Small diff with no expunges processed in this poll
			// Likely expunged between SELECT and first poll, or very old expunges
			// Safe to sync as long as difference is small (< 10 messages)
			canReconcile = true
			reconcileReason = "missed_old_expunges"
		} else if processedExpunges == 0 && finalCount > poll.NumMessages {
			// Large diff with no expunges in this poll's modseq window.
			// This can happen when:
			// 1. Background cleaner hard-deleted old expunged messages (outside modseq window)
			// 2. Bulk APPEND operations happened, then bulk hard-deletes occurred
			// 3. Multiple sessions expunging with session missing the notifications
			// Since the database is authoritative and we processed no expunges in this poll,
			// it's safe to sync down to the database count.
			s.WarnLog("large message count mismatch with no recent expunges, syncing to database",
				"session_count", finalCount, "db_count", poll.NumMessages, "diff", diff)
			canReconcile = true
			reconcileReason = "hard_deletes_outside_window"
		}

		if canReconcile {
			s.DebugLog("syncing message count to database",
				"session_count", finalCount, "db_count", poll.NumMessages,
				"diff", diff, "reason", reconcileReason,
				"skipped_expunges", skippedExpunges, "processed_expunges", processedExpunges)
			s.currentNumMessages.Store(poll.NumMessages)
		} else {
			// Large unexplained mismatch - unsafe to continue
			s.WarnLog("state desync: unexplained message count mismatch",
				"session_count", finalCount, "db_count", poll.NumMessages,
				"diff", diff, "skipped_expunges", skippedExpunges,
				"processed_expunges", processedExpunges)
			return &imap.Error{
				Type: imap.StatusResponseTypeBye,
				Code: imap.ResponseCodeUnavailable,
				Text: "Mailbox state changed externally, please reconnect",
			}
		}
	} else if poll.NumMessages > finalCount {
		// Database has more messages than expected - sync up
		// This is safe because new messages just get higher sequence numbers
		s.DebugLog("syncing message count up to database", "session_count", finalCount, "db_count", poll.NumMessages)
		s.currentNumMessages.Store(poll.NumMessages)
	}

	// Process message flag updates
	for _, update := range poll.Updates {
		if update.IsExpunge {
			continue
		}

		allFlags := db.BitwiseToFlags(update.BitwiseFlags)
		if allFlags == nil {
			allFlags = []imap.Flag{}
		}
		for _, customFlag := range update.CustomFlags {
			allFlags = append(allFlags, imap.Flag(customFlag))
		}
		s.mailboxTracker.QueueMessageFlags(update.SeqNum, update.UID, allFlags, nil)
	}

	// Store sessionTracker reference before releasing lock to avoid race condition
	sessionTracker := s.sessionTracker

	release() // Release lock before writing to the network

	// Check if sessionTracker is still valid after releasing lock
	if sessionTracker == nil {
		return nil
	}

	return sessionTracker.Poll(w, allowExpunge)
}
