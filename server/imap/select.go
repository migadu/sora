package imap

import (
	"fmt"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Select(mboxName string, options *imap.SelectOptions) (*imap.SelectData, error) {
	s.Log("[SELECT] attempting to select mailbox: %s", mboxName)

	// Phase 1: Read session state with read lock
	acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.Log("[SELECT] Failed to acquire read lock within timeout")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}
	userID := s.UserID()
	s.mutex.RUnlock()
	cancel()

	// Phase 2: Database operations outside lock
	mailbox, err := s.server.db.GetMailboxByName(s.ctx, userID, mboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.Log("[SELECT] mailbox '%s' does not exist for user %d", mboxName, s.UserID())
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mboxName),
			}
		}

		return nil, s.internalError("failed to fetch mailbox '%s' for user %d: %v", mboxName, s.UserID(), err)
	}

	currentSummary, err := s.server.db.GetMailboxSummary(s.ctx, mailbox.ID)
	if err != nil {
		return nil, s.internalError("failed to get current summary for selected mailbox '%s': %v", mboxName, err)
	}

	// First, acquire the read lock once to read necessary session state
	acquired, cancel = s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.Log("[SELECT] Failed to acquire second read lock within timeout")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}

	// Check if this is a reselection of the previously selected mailbox
	isReselectOfPrevious := (s.lastSelectedMailboxID == mailbox.ID)
	// Store the highest UID from previous selection to calculate recent messages
	uidToCompareAgainst := s.lastHighestUID
	// Check if the context is already cancelled before proceeding with DB operations
	if s.ctx.Err() != nil {
		s.mutex.RUnlock()
		cancel()
		s.Log("[SELECT] context already cancelled before selecting mailbox '%s'", mboxName)
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Session closed during select operation"}
	}
	s.mutex.RUnlock()
	cancel()

	// Now perform all database operations outside the lock
	var numRecent uint32

	if isReselectOfPrevious {
		s.Log("[SELECT] mailbox %s reselected", mboxName)
		// This mailbox was the one most recently selected (and then unselected by the imapserver library).
		// Count messages with UID > uidToCompareAgainst.
		count, dbErr := s.server.db.CountMessagesGreaterThanUID(s.ctx, mailbox.ID, uidToCompareAgainst)
		if dbErr != nil {
			s.Log("[SELECT] Error counting messages greater than UID %d for mailbox %d: %v. Defaulting RECENT to total.", uidToCompareAgainst, mailbox.ID, dbErr)
			numRecent = uint32(currentSummary.NumMessages) // Fallback
		} else {
			numRecent = count
		}
	} else {
		// Different mailbox than the last one selected, or this is the first select in the session.
		// All messages are considered recent.
		numRecent = uint32(currentSummary.NumMessages)
	}

	// Acquire the lock once after all DB operations to update session state
	acquired, cancel = s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.Log("[SELECT] Failed to acquire write lock within timeout")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}
	defer func() {
		s.mutex.Unlock()
		cancel()
	}()

	// Check again if the context was cancelled during DB operations
	if s.ctx.Err() != nil {
		s.Log("[SELECT] context cancelled during mailbox '%s' selection, aborting state update", mboxName)
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Session closed during select operation"}
	}

	// Update session state for the *next* Unselect/Select cycle
	s.lastSelectedMailboxID = mailbox.ID
	if currentSummary.UIDNext > 0 {
		// UIDNext is the *next* UID to be assigned. So the current highest is UIDNext - 1.
		s.lastHighestUID = imap.UID(currentSummary.UIDNext - 1)
	} else {
		// This case implies the mailbox is empty or UIDs start at 1 and UIDNext is 1.
		s.lastHighestUID = 0
	}

	s.currentNumMessages.Store(uint32(currentSummary.NumMessages))
	s.currentHighestModSeq.Store(currentSummary.HighestModSeq)

	// Store the first unseen message sequence number from the mailbox summary
	s.firstUnseenSeqNum.Store(currentSummary.FirstUnseenSeqNum)
	if currentSummary.FirstUnseenSeqNum > 0 {
		s.Log("[SELECT] First unseen message is at sequence number %d", currentSummary.FirstUnseenSeqNum)
	}

	s.selectedMailbox = mailbox
	s.mailboxTracker = imapserver.NewMailboxTracker(s.currentNumMessages.Load())
	s.sessionTracker = s.mailboxTracker.NewSession()

	s.Log("[SELECT] mailbox '%s' (ID: %d) NumMessages=%d HighestModSeqForPolling=%d UIDNext=%d UIDValidity=%d ReportedHighestModSeq=%d NumRecentCalculated=%d FirstUnseenSeq=%d",
		mboxName, mailbox.ID, s.currentNumMessages.Load(), s.currentHighestModSeq.Load(), currentSummary.UIDNext, s.selectedMailbox.UIDValidity, currentSummary.HighestModSeq, numRecent, s.firstUnseenSeqNum.Load())

	selectData := &imap.SelectData{
		// Flags defined for this mailbox (system flags, common keywords, and in-use custom flags)
		Flags: getDisplayFlags(s.ctx, s.server.db, mailbox),
		// Flags that can be changed, including \* for custom
		PermanentFlags:    getPermanentFlags(),
		NumMessages:       s.currentNumMessages.Load(),
		UIDNext:           imap.UID(currentSummary.UIDNext),
		UIDValidity:       s.selectedMailbox.UIDValidity,
		NumRecent:         numRecent,
		HighestModSeq:     s.currentHighestModSeq.Load(),
		FirstUnseenSeqNum: s.firstUnseenSeqNum.Load(),
	}

	return selectData, nil
}

func (s *IMAPSession) Unselect() error {
	acquired, cancel := s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.Log("[UNSELECT] Failed to acquire write lock within timeout")
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

	if s.selectedMailbox != nil {
		s.Log("[UNSELECT] mailbox %s (ID: %d) cleared from session state.", s.selectedMailbox.Name, s.selectedMailbox.ID)
		// The s.lastSelectedMailboxID and s.lastHighestUID fields are intentionally *not* cleared here.
		// They hold the state of the mailbox that was just active, so the next Select
		// can use them to determine "new" messages for that specific mailbox.
	}
	s.clearSelectedMailboxStateLocked()
	return nil
}
