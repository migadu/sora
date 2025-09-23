package imap

import (
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

// Sort implements the SORT extension (RFC 5256), SORT=DISPLAY extension (RFC 5957),
// and ESORT extension (RFC 5267). It returns sorted message data according to the provided criteria.
func (s *IMAPSession) Sort(numKind imapserver.NumKind, sortCriteria []imap.SortCriterion, charset string, searchCriteria *imap.SearchCriteria, options *imap.SortOptions) (*imap.SortData, error) {
	searchCriteria = s.decodeSearchCriteria(searchCriteria)

	if s.currentNumMessages.Load() == 0 && len(searchCriteria.SeqNum) > 0 {
		s.Log("[SORT] skipping SORT because mailbox is empty")
		return &imap.SortData{All: []uint32{}}, nil
	}

	// Acquire a read lock to safely get a snapshot of the session tracker.
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.Log("[SORT] Failed to acquire read lock for session tracker")
		return nil, s.internalError("failed to acquire lock for sort")
	}
	sessionTrackerSnapshot := s.sessionTracker
	selectedMailboxID := s.selectedMailbox.ID
	release()

	if sessionTrackerSnapshot == nil {
		return nil, s.internalError("no session tracker available for sort")
	}

	// Pass both search criteria and sort criteria to the database layer
	messages, err := s.server.rdb.GetMessagesSorted(s.ctx, selectedMailboxID, searchCriteria, sortCriteria)
	if err != nil {
		return nil, s.internalError("failed to sort messages: %v", err)
	}

	// Prepare the sorted list of message numbers (UIDs or sequence numbers)
	var nums []uint32
	for _, msg := range messages {
		if numKind == imapserver.NumKindUID {
			nums = append(nums, uint32(msg.UID))
		} else {
			nums = append(nums, sessionTrackerSnapshot.EncodeSeqNum(msg.Seq))
		}
	}

	// Create SortData with the results
	sortData := &imap.SortData{
		All: nums,
	}

	// Handle ESORT options if provided
	if options != nil {
		if options.ReturnCount {
			sortData.Count = uint32(len(nums))
		}
		if options.ReturnMin && len(nums) > 0 {
			sortData.Min = nums[0]
		}
		if options.ReturnMax && len(nums) > 0 {
			sortData.Max = nums[len(nums)-1]
		}
	}

	return sortData, nil
}
