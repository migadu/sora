package imap

import (
	"context"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/pkg/metrics"
)

func (s *IMAPSession) Select(mboxName string, options *imap.SelectOptions) (*imap.SelectData, error) {
	s.DebugLog("attempting to select mailbox", "mailbox", mboxName)

	if s.ctx.Err() != nil {
		s.DebugLog("request aborted before selecting mailbox", "mailbox", mboxName)
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Session closed"}
	}

	// Prevent selecting the shared namespace root
	// The namespace root (e.g., "Shared") should only be a container, not a selectable mailbox
	if s.server.config != nil && s.server.config.SharedMailboxes.Enabled {
		sharedPrefix := strings.TrimSuffix(s.server.config.SharedMailboxes.NamespacePrefix, "/")
		if mboxName == sharedPrefix {
			s.DebugLog("cannot select shared namespace root", "mailbox", mboxName)
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeCannot,
				Text: "The shared namespace root cannot be selected. Select mailboxes under it instead",
			}
		}
	}

	// Phase 1: Read session state with read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.WarnLog("failed to acquire read lock within timeout")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}
	AccountID := s.AccountID()
	release()

	// Create a context that signals to use the master DB if the session is pinned.
	readCtx := s.ctx
	if s.useMasterDB {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	// Phase 2: Database operations outside lock
	mailbox, err := s.server.rdb.GetMailboxByNameWithRetry(readCtx, AccountID, mboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.DebugLog("mailbox does not exist", "mailbox", mboxName, "account_id", s.AccountID())
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mboxName),
			}
		}

		return nil, s.internalError("failed to fetch mailbox '%s' for user %d: %v", mboxName, s.AccountID(), err)
	}

	// Check ACL permissions for shared mailboxes (requires 'r' read right)
	// The has_mailbox_right function returns TRUE for owners, so this works for both personal and shared mailboxes
	hasReadRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(readCtx, mailbox.ID, AccountID, 'r')
	if err != nil {
		return nil, s.internalError("failed to check read permission for mailbox '%s': %v", mboxName, err)
	}
	if !hasReadRight {
		s.DebugLog("user does not have read permission on mailbox", "account_id", AccountID, "mailbox", mboxName)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to select this mailbox",
		}
	}

	currentSummary, err := s.server.rdb.GetMailboxSummaryWithRetry(readCtx, mailbox.ID)
	if err != nil {
		return nil, s.internalError("failed to get current summary for selected mailbox '%s': %v", mboxName, err)
	}

	// First, acquire the read lock once to read necessary session state
	acquired, release = s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.WarnLog("failed to acquire second read lock within timeout")
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
		release()
		s.DebugLog("context already cancelled before selecting mailbox", "mailbox", mboxName)
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Session closed during select operation"}
	}
	release()

	// Now perform all database operations outside the lock
	var numRecent uint32

	if isReselectOfPrevious {
		s.DebugLog("mailbox reselected", "mailbox", mboxName)
		// This mailbox was the one most recently selected (and then unselected by the imapserver library).
		// Count messages with UID > uidToCompareAgainst. Use the potentially master-pinned context.
		count, dbErr := s.server.rdb.CountMessagesGreaterThanUIDWithRetry(readCtx, mailbox.ID, uidToCompareAgainst)
		if dbErr != nil {
			s.DebugLog("error counting messages greater than UID, defaulting RECENT to total", "uid", uidToCompareAgainst, "mailbox_id", mailbox.ID, "error", dbErr)
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
	acquired, release = s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.WarnLog("failed to acquire write lock within timeout")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}
	defer release()

	// Check again if the context was cancelled during DB operations
	if s.ctx.Err() != nil {
		s.DebugLog("request aborted during mailbox selection, aborting state update", "mailbox", mboxName)
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
		s.DebugLog("first unseen message", "seq", currentSummary.FirstUnseenSeqNum)
	}

	s.selectedMailbox = mailbox
	s.mailboxTracker = imapserver.NewMailboxTracker(s.currentNumMessages.Load())
	s.sessionTracker = s.mailboxTracker.NewSession()

	// Track domain and user command activity
	if s.IMAPUser != nil {
		metrics.TrackDomainCommand("imap", s.IMAPUser.Address.Domain(), "SELECT")
		metrics.TrackUserActivity("imap", s.IMAPUser.Address.FullAddress(), "command", 1)
	}

	// Get flags for this mailbox and store them for filtering FETCH responses
	displayFlags := getDisplayFlags(readCtx, s.server.rdb, mailbox)
	s.announcedFlags = make(map[imap.Flag]struct{}, len(displayFlags))
	for _, f := range displayFlags {
		s.announcedFlags[f] = struct{}{}
	}

	selectData := &imap.SelectData{
		// Flags defined for this mailbox (system flags, common keywords, and in-use custom flags)
		Flags: displayFlags,
		// Flags that can be changed, including \* for custom
		PermanentFlags:    getPermanentFlags(),
		NumMessages:       s.currentNumMessages.Load(),
		UIDNext:           imap.UID(currentSummary.UIDNext),
		UIDValidity:       s.selectedMailbox.UIDValidity,
		NumRecent:         numRecent,
		FirstUnseenSeqNum: s.firstUnseenSeqNum.Load(),
	}

	// Only include HighestModSeq if CONDSTORE capability is enabled
	if s.GetCapabilities().Has(imap.CapCondStore) {
		selectData.HighestModSeq = s.currentHighestModSeq.Load()
	}

	return selectData, nil
}

func (s *IMAPSession) Unselect() error {
	// If the session is closing, don't try to unselect.
	if s.ctx.Err() != nil {
		s.DebugLog("session context is cancelled, skipping unselect")
		return nil
	}

	acquired, release := s.mutexHelper.AcquireWriteLockWithTimeout()
	if !acquired {
		s.WarnLog("failed to acquire write lock within timeout")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}
	defer release()

	if s.selectedMailbox != nil {
		s.DebugLog("mailbox cleared from session state", "mailbox", s.selectedMailbox.Name, "mailbox_id", s.selectedMailbox.ID)
		// The s.lastSelectedMailboxID and s.lastHighestUID fields are intentionally *not* cleared here.
		// They hold the state of the mailbox that was just active, so the next Select
		// can use them to determine "new" messages for that specific mailbox.
	}
	s.clearSelectedMailboxStateLocked()
	return nil
}
