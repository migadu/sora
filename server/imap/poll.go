package imap

import (
	"context"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

func (s *IMAPSession) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	// If the session is closing, don't try to poll.
	if s.ctx.Err() != nil {
		s.Log("[POLL] Session context is cancelled, skipping poll.")
		return nil
	}

	// First phase: Read state with read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.Log("[POLL] Failed to acquire read lock within timeout")
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
		return s.internalError("failed to poll mailbox: %v", err)
	}

	acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.Log("[POLL] Failed to acquire write lock within timeout")
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

	// First, update message count if it has increased (new messages)
	// This must be done before processing expunges to ensure sequence numbers are valid
	currentCount := s.currentNumMessages.Load()
	messageCountChanged := false
	if poll.NumMessages > currentCount {
		s.Log("[POLL] Updating message count from %d to %d", currentCount, poll.NumMessages)
		s.mailboxTracker.QueueNumMessages(poll.NumMessages)
		s.currentNumMessages.Store(poll.NumMessages)
		messageCountChanged = true
	}

	// Group updates by sequence number to detect duplicate expunges
	expungedSeqNums := make(map[uint32]bool)

	// Process expunge updates
	for _, update := range poll.Updates {
		if !update.IsExpunge {
			continue
		}

		// Check if we've already processed an expunge for this sequence number
		if expungedSeqNums[update.SeqNum] {
			s.Log("[POLL] Skipping duplicate expunge update for seq %d (UID %d)", update.SeqNum, update.UID)
			continue
		}

		// Validate sequence number is within range
		currentMessages := s.currentNumMessages.Load()
		if update.SeqNum > currentMessages {
			s.Log("[POLL] WARNING: Expunge sequence number %d out of range (mailbox has %d messages), skipping", update.SeqNum, currentMessages)
			continue
		}

		s.Log("[POLL] Processing expunge update for seq %d (UID %d)", update.SeqNum, update.UID)
		s.mailboxTracker.QueueExpunge(update.SeqNum)
		// Atomically decrement the current number of messages
		s.currentNumMessages.Add(^uint32(0)) // Equivalent to -1 for unsigned

		// Mark this sequence number as already expunged to prevent duplicates
		expungedSeqNums[update.SeqNum] = true
	}

	// Update message count again if it has decreased (after expunges)
	finalCount := s.currentNumMessages.Load()
	if poll.NumMessages < finalCount {
		s.Log("[POLL] Adjusting message count from %d to %d after expunges", finalCount, poll.NumMessages)
		s.mailboxTracker.QueueNumMessages(poll.NumMessages)
		s.currentNumMessages.Store(poll.NumMessages)
	}

	// Process message flag updates
	for _, update := range poll.Updates {
		if update.IsExpunge {
			continue
		}

		allFlags := db.BitwiseToFlags(update.BitwiseFlags)
		for _, customFlag := range update.CustomFlags {
			allFlags = append(allFlags, imap.Flag(customFlag))
		}
		s.mailboxTracker.QueueMessageFlags(update.SeqNum, update.UID, allFlags, nil)
	}

	// Store sessionTracker reference before releasing lock to avoid race condition
	sessionTracker := s.sessionTracker
	
	// Check if we have any updates to process before calling sessionTracker.Poll
	// We have updates if there are database updates OR if the message count changed
	hasUpdates := len(poll.Updates) > 0 || messageCountChanged
	
	release() // Release lock before writing to the network

	// Check if sessionTracker is still valid after releasing lock
	if sessionTracker == nil {
		return nil
	}

	// Only call sessionTracker.Poll if we have meaningful updates to send
	// This prevents sending empty updates that cause panics in the go-imap library
	if !hasUpdates {
		s.Log("[POLL] No updates to send, skipping sessionTracker.Poll")
		return nil
	}

	return sessionTracker.Poll(w, allowExpunge)
}
