package imap

import (
	"fmt"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Select(mboxName string, options *imap.SelectOptions) (*imap.SelectData, error) {
	s.Log("[SELECT] attempting to select mailbox: %s", mboxName)

	mailbox, err := s.server.db.GetMailboxByName(s.ctx, s.UserID(), mboxName)
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

	// Determine NumRecent based on whether this mailbox was the last one selected.
	// This logic is outside the main session lock for the DB call, then re-locks for state update.
	var numRecent uint32
	var isReselectOfPrevious bool
	var uidToCompareAgainst imap.UID

	s.mutex.Lock()
	isReselectOfPrevious = (s.lastSelectedMailboxID == mailbox.ID)
	uidToCompareAgainst = s.lastHighestUID // This is the highest UID from the *previous* selection of this mailbox.
	s.mutex.Unlock()

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

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// After re-acquiring the lock, check if the session context was cancelled
	// (e.g., by s.Close() being called concurrently while DB operations were in progress).
	if s.ctx.Err() != nil {
		s.Log("[SELECT] context cancelled while selecting mailbox '%s', aborting state update.", mboxName)
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

	s.currentNumMessages = uint32(currentSummary.NumMessages)
	s.currentHighestModSeq = currentSummary.HighestModSeq

	s.selectedMailbox = mailbox
	s.mailboxTracker = imapserver.NewMailboxTracker(s.currentNumMessages)
	s.sessionTracker = s.mailboxTracker.NewSession()

	s.Log("[SELECT] mailbox '%s' (ID: %d)  NumMessages=%d HighestModSeqForPolling=%d UIDNext=%d UIDValidity=%d ReportedHighestModSeq=%d NumRecentCalculated=%d",
		mboxName, mailbox.ID, s.currentNumMessages, s.currentHighestModSeq, currentSummary.UIDNext, s.selectedMailbox.UIDValidity, currentSummary.HighestModSeq, numRecent)

	selectData := &imap.SelectData{
		// Flags defined for this mailbox (system flags, common keywords, and in-use custom flags)
		Flags: getDisplayFlags(s.ctx, s.server.db, mailbox),
		// Flags that can be changed, including \* for custom
		PermanentFlags: getPermanentFlags(),
		NumMessages:    s.currentNumMessages,
		UIDNext:        imap.UID(currentSummary.UIDNext),
		UIDValidity:    s.selectedMailbox.UIDValidity,
		NumRecent:      numRecent, // Use the calculated numRecent
		HighestModSeq:  s.currentHighestModSeq,
	}

	return selectData, nil
}

func (s *IMAPSession) Unselect() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.selectedMailbox != nil {
		s.Log("[UNSELECT] mailbox %s (ID: %d) cleared from session state.", s.selectedMailbox.Name, s.selectedMailbox.ID)
		// The s.lastSelectedMailboxID and s.lastHighestUID fields are intentionally *not* cleared here.
		// They hold the state of the mailbox that was just active, so the next Select
		// can use them to determine "new" messages for that specific mailbox.
	}
	s.clearSelectedMailboxStateLocked()
	return nil
}
