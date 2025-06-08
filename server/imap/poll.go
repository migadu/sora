package imap

import (
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/db"
)

func (s *IMAPSession) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	// First phase: Read state with read lock
	acquired, cancel := s.acquireReadLockWithTimeout()
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

	poll, err := s.server.db.PollMailbox(s.ctx, mailboxID, highestModSeqToPollFrom)
	if err != nil {
		return s.internalError("failed to poll mailbox: %v", err)
	}

	acquired, cancel = s.acquireWriteLockWithTimeout()
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

	for _, update := range poll.Updates {
		if update.IsExpunge {
			s.mailboxTracker.QueueExpunge(update.SeqNum)
			// Atomically decrement the current number of messages
			s.currentNumMessages.Add(^uint32(0)) // Equivalent to -1 for unsigned
		} else {
			allFlags := db.BitwiseToFlags(update.BitwiseFlags)
			for _, customFlag := range update.CustomFlags {
				allFlags = append(allFlags, imap.Flag(customFlag))
			}
			s.mailboxTracker.QueueMessageFlags(update.SeqNum, update.UID, allFlags, nil)
		}
	}

	// Lock-free comparison and update of message count
	currentCount := s.currentNumMessages.Load()
	if poll.NumMessages > currentCount {
		s.mailboxTracker.QueueNumMessages(poll.NumMessages)
		s.currentNumMessages.Store(poll.NumMessages)
	}

	return s.sessionTracker.Poll(w, allowExpunge)
}
