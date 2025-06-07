package imap

import (
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

// Sort implements the SORT extension (RFC 5256) and SORT=DISPLAY extension (RFC 5957)
// It returns a list of message numbers sorted according to the provided criteria.
func (s *IMAPSession) Sort(numKind imapserver.NumKind, criteria *imap.SearchCriteria, sortCriteria []imap.SortCriterion) (*imapserver.SortData, error) {
	criteria = s.decodeSearchCriteria(criteria)

	if s.currentNumMessages == 0 && len(criteria.SeqNum) > 0 {
		s.Log("[SORT] skipping SORT because mailbox is empty")
		return &imapserver.SortData{
			Nums: []uint32{},
		}, nil
	}

	// Pass both search criteria and sort criteria to the database layer
	messages, err := s.server.db.GetMessagesSorted(s.ctx, s.selectedMailbox.ID, criteria, sortCriteria)
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

	return &imapserver.SortData{
		Nums: nums,
	}, nil
}
