package imap

import (
	"fmt"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Status(mboxName string, options *imap.StatusOptions) (*imap.StatusData, error) {
	// First phase: Read validation with read lock
	s.mutex.RLock()
	userID := s.UserID()
	s.mutex.RUnlock()

	// Middle phase: Database operations outside lock
	mailbox, err := s.server.db.GetMailboxByName(s.ctx, userID, mboxName)
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

	summary, err := s.server.db.GetMailboxSummary(s.ctx, mailbox.ID)
	if err != nil {
		return nil, s.internalError("failed to get mailbox summary for '%s': %v", mboxName, err)
	}

	statusData := &imap.StatusData{
		Mailbox:     mailbox.Name,
		UIDValidity: mailbox.UIDValidity,
	}

	if options.NumMessages {
		num := uint32(summary.NumMessages)

		// Need write lock to update currentNumMessages
		s.mutex.Lock()
		s.currentNumMessages = num
		s.mutex.Unlock()

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
	if options.HighestModSeq {
		statusData.HighestModSeq = summary.HighestModSeq
	}

	s.Log("[STATUS] mailbox '%s': NumMessages=%v, UIDNext=%v, HighestModSeq=%v",
		mboxName,
		statusData.NumMessages,
		statusData.UIDNext,
		statusData.HighestModSeq)

	return statusData, nil
}
