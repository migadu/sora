package imap

import (
	"fmt"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Status(mboxName string, options *imap.StatusOptions) (*imap.StatusData, error) {
	// First phase: Read validation with read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.WarnLog("failed to acquire read lock")
		return nil, s.internalError("failed to acquire lock for status")
	}
	AccountID := s.AccountID()
	release()

	// Middle phase: Database operations outside lock
	mailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, AccountID, mboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.DebugLog("mailbox does not exist", "mailbox", mboxName)
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mboxName),
			}
		}
		return nil, s.internalError("failed to fetch mailbox '%s': %v", mboxName, err)
	}

	// Check ACL permissions - requires 'r' (read) right
	hasReadRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, mailbox.ID, AccountID, 'r')
	if err != nil {
		return nil, s.internalError("failed to check read permission: %v", err)
	}
	if !hasReadRight {
		s.DebugLog("user does not have read permission on mailbox", "mailbox", mboxName)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to get status of this mailbox",
		}
	}

	summary, err := s.server.rdb.GetMailboxSummaryWithRetry(s.ctx, mailbox.ID)
	if err != nil {
		return nil, s.internalError("failed to get mailbox summary for '%s': %v", mboxName, err)
	}

	statusData := &imap.StatusData{
		Mailbox:     mailbox.Name,
		UIDValidity: mailbox.UIDValidity,
	}

	if options.NumMessages {
		num := uint32(summary.NumMessages)

		// We DO NOT update s.currentNumMessages here even if this is the selected mailbox.
		// s.currentNumMessages must stay in sync with s.mailboxTracker's internal count.
		// Updating it here without updating the tracker causes desync panics later
		// during Poll or Append if the database count decreased (e.g., due to expunges).

		statusData.NumMessages = &num
	}
	if options.UIDNext {
		statusData.UIDNext = imap.UID(summary.UIDNext)
	}
	if options.NumRecent {
		num := uint32(summary.RecentCount)
		statusData.NumRecent = &num
	}
	if options.NumUnseen {
		// Defensive: clamp negative values to 0 to prevent uint32 wraparound
		// (database bug in migration 000025 could cause negative unseen_count)
		unseenCount := summary.UnseenCount
		if unseenCount < 0 {
			s.WarnLog("negative unseen_count detected, clamping to 0", "mailbox", mboxName, "unseen_count", unseenCount)
			unseenCount = 0
		}
		num := uint32(unseenCount)
		statusData.NumUnseen = &num
	}
	if s.GetCapabilities().Has(imap.CapCondStore) && options.HighestModSeq {
		statusData.HighestModSeq = summary.HighestModSeq
	}
	if options.AppendLimit && s.server.appendLimit > 0 {
		limit := uint32(s.server.appendLimit)
		statusData.AppendLimit = &limit
	}

	numMessagesStr := "n/a"
	if statusData.NumMessages != nil {
		numMessagesStr = fmt.Sprint(*statusData.NumMessages)
	}

	s.DebugLog("mailbox status", "mailbox", mboxName, "num_messages", numMessagesStr, "uid_next", statusData.UIDNext, "highest_modseq", statusData.HighestModSeq)

	return statusData, nil
}
