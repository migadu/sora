package imap

import (
	"context"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

func (s *IMAPSession) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	// First phase: Read state with read lock
	acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.Log("[POLL] Failed to acquire read lock within timeout")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}

	if s.selectedMailbox == nil || s.mailboxTracker == nil || s.sessionTracker == nil {
		s.mutex.RUnlock()
		cancel()
		return nil
	}
	mailboxID := s.selectedMailbox.ID
	highestModSeqToPollFrom := s.currentHighestModSeq.Load()
	s.mutex.RUnlock()
	cancel()

	// Create a context that signals to use the master DB if the session is pinned.
	readCtx := s.ctx
	if s.useMasterDB {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	poll, err := s.server.db.PollMailbox(readCtx, mailboxID, highestModSeqToPollFrom)
	if err != nil {
		return s.internalError("failed to poll mailbox: %v", err)
	}

	acquired, cancel = s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.Log("[POLL] Failed to acquire write lock within timeout")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}
	defer func() {
		s.mutex.Unlock()
		cancel()
	}()

	if s.selectedMailbox == nil || s.selectedMailbox.ID != mailboxID || s.mailboxTracker == nil || s.sessionTracker == nil {
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
	if poll.NumMessages > currentCount {
		s.Log("[POLL] Updating message count from %d to %d", currentCount, poll.NumMessages)
		s.mailboxTracker.QueueNumMessages(poll.NumMessages)
		s.currentNumMessages.Store(poll.NumMessages)
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

	return s.sessionTracker.Poll(w, allowExpunge)
}
