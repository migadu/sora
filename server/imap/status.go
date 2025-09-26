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
		s.Log("[STATUS] Failed to acquire read lock")
		return nil, s.internalError("failed to acquire lock for status")
	}
	userID := s.UserID()
	release()

	// Middle phase: Database operations outside lock
	mailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, userID, mboxName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.Log("[STATUS] mailbox '%s' does not exist", mboxName)
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mboxName),
			}
		}
		return nil, s.internalError("failed to fetch mailbox '%s': %v", mboxName, err)
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

		// Update currentNumMessages using atomic operation, no lock needed
		s.currentNumMessages.Store(num)

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
		num := uint32(summary.UnseenCount)
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

	s.Log("[STATUS] mailbox '%s': NumMessages=%s, UIDNext=%v, HighestModSeq=%v",
		mboxName,
		numMessagesStr,
		statusData.UIDNext,
		statusData.HighestModSeq)

	return statusData, nil
}
