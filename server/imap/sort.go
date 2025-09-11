package imap

import (
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

// Sort implements the SORT extension (RFC 5256), SORT=DISPLAY extension (RFC 5957),
// and ESORT extension (RFC 5267). It returns a list of message numbers sorted
// according to the provided criteria.
func (s *IMAPSession) Sort(numKind imapserver.NumKind, criteria *imap.SearchCriteria, sortCriteria []imap.SortCriterion) ([]uint32, error) {
	criteria = s.decodeSearchCriteria(criteria)

	if s.currentNumMessages.Load() == 0 && len(criteria.SeqNum) > 0 {
		s.Log("[SORT] skipping SORT because mailbox is empty")
		return []uint32{}, nil
	}

	// Pass both search criteria and sort criteria to the database layer
	messages, err := s.server.rdb.GetMessagesSorted(s.ctx, s.selectedMailbox.ID, criteria, sortCriteria)
	if err != nil {
		return nil, s.internalError("failed to sort messages: %v", err)
	}

	// Prepare the sorted list of message numbers (UIDs or sequence numbers)
	var nums []uint32
	for _, msg := range messages {
		if numKind == imapserver.NumKindUID {
			nums = append(nums, uint32(msg.UID))
		} else {
			nums = append(nums, s.sessionTracker.EncodeSeqNum(msg.Seq))
		}
	}

	return nums, nil
}
