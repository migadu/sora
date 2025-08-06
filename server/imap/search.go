package imap

import (
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

func (s *IMAPSession) Search(numKind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	// First safely read and decode session state
	var selectedMailboxID int64
	var currentNumMessages uint32
	var sessionTrackerSnapshot *imapserver.SessionTracker

	// Acquire read mutex to safely read session state
	acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.Log("[SEARCH] Failed to acquire read lock within timeout")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}

	if s.selectedMailbox == nil {
		s.mutex.RUnlock()
		cancel()
		s.Log("[SEARCH] no mailbox selected")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "No mailbox selected",
		}
	}
	selectedMailboxID = s.selectedMailbox.ID
	currentNumMessages = s.currentNumMessages.Load()
	sessionTrackerSnapshot = s.sessionTracker
	s.mutex.RUnlock()
	cancel()

	// Now decode search criteria using decodeSearchCriteriaLocked helper that we'll create
	criteria = s.decodeSearchCriteria(criteria)

	if currentNumMessages == 0 && len(criteria.SeqNum) > 0 {
		s.Log("[SEARCH] skipping UID SEARCH because mailbox is empty")
		return &imap.SearchData{
			All:   imap.UIDSet{},
			Count: 0,
		}, nil
	}

	// Database operations outside of lock
	messages, err := s.server.db.GetMessagesWithCriteria(s.ctx, selectedMailboxID, criteria)
	if err != nil {
		return nil, s.internalError("failed to search messages: %v", err)
	}

	searchData := &imap.SearchData{}
	searchData.Count = uint32(len(messages))
	

	if options != nil {
		s.Log("[SEARCH ESEARCH] ESEARCH options provided: Min=%v, Max=%v, All=%v, CountReturnOpt=%v",
			options.ReturnMin, options.ReturnMax, options.ReturnAll, options.ReturnCount)

		// iOS Mail compatibility: Fall back to standard SEARCH response for certain ESEARCH patterns
		// that iOS Mail has trouble with, particularly when requesting ALL results
		if options.ReturnAll && !options.ReturnMin && !options.ReturnMax && !options.ReturnCount {
			s.Log("[SEARCH ESEARCH] Converting ESEARCH ALL to standard SEARCH for iOS Mail compatibility")
			// Return as standard SEARCH instead of ESEARCH to avoid iOS Mail infinite retry
			var uids imap.UIDSet
			var seqNums imap.SeqSet
			for _, msg := range messages {
				uids.AddNum(msg.UID)
				// Use our snapshot of sessionTracker which is thread-safe
				if sessionTrackerSnapshot != nil {
					seqNums.AddNum(sessionTrackerSnapshot.EncodeSeqNum(msg.Seq))
				} else {
					// Fallback to just using the sequence number if session tracker isn't available
					seqNums.AddNum(msg.Seq)
				}
			}
			if numKind == imapserver.NumKindUID {
				searchData.All = uids
			} else {
				searchData.All = seqNums
			}
			// Clear ESEARCH-specific fields to force standard SEARCH response
			searchData.Min = 0
			searchData.Max = 0
			return searchData, nil
		}

		if options.ReturnMin || options.ReturnMax || options.ReturnAll || options.ReturnCount {
			if len(messages) > 0 {
				if options.ReturnMin {
					searchData.Min = uint32(messages[0].UID)
				}
				if options.ReturnMax {
					searchData.Max = uint32(messages[len(messages)-1].UID)
				}
			}

			if options.ReturnAll {
				var uids imap.UIDSet
				var seqNums imap.SeqSet
				for _, msg := range messages {
					uids.AddNum(msg.UID)
					// Use our snapshot of sessionTracker which is thread-safe
					if sessionTrackerSnapshot != nil {
						seqNums.AddNum(sessionTrackerSnapshot.EncodeSeqNum(msg.Seq))
					} else {
						// Fallback to just using the sequence number if session tracker isn't available
						seqNums.AddNum(msg.Seq)
					}
				}
				if numKind == imapserver.NumKindUID {
					searchData.All = uids
				} else {
					searchData.All = seqNums
				}
			}

			// RFC 4731: For ESEARCH, COUNT should be included unless explicitly excluded
			// The Count field is always set (line 59), but we need to ensure it's included in the response
			// The go-imap library will include Count in ESEARCH responses when it's set
			
		} else {
			// All ReturnMin, ReturnMax, ReturnAll, ReturnCount are false.
			// This means client used ESEARCH form (e.g. SEARCH RETURN ()) and expects default.
			// RFC 4731: "server SHOULD behave as if RETURN (COUNT) was specified."
			s.Log("[SEARCH ESEARCH] No specific RETURN options (MIN/MAX/ALL/COUNT) requested, defaulting to COUNT only.")
		}
	} else { // Standard SEARCH command (options == nil)
		s.Log("[SEARCH] Standard SEARCH, returning ALL and COUNT.")
		var uids imap.UIDSet
		var seqNums imap.SeqSet
		for _, msg := range messages {
			uids.AddNum(msg.UID)
			// Use our snapshot of sessionTracker which is thread-safe
			if sessionTrackerSnapshot != nil {
				seqNums.AddNum(sessionTrackerSnapshot.EncodeSeqNum(msg.Seq))
			} else {
				// Fallback to just using the sequence number if session tracker isn't available
				seqNums.AddNum(msg.Seq)
			}
		}

		if numKind == imapserver.NumKindUID {
			searchData.All = uids
		} else {
			searchData.All = seqNums
		}
	}

	// Always enable CONDSTORE functionality when ModSeq criteria is provided
	if criteria.ModSeq != nil {
		var highestModSeq uint64
		for _, msg := range messages {
			var msgModSeq int64
			msgModSeq = msg.CreatedModSeq

			if msg.UpdatedModSeq != nil && *msg.UpdatedModSeq > msgModSeq {
				msgModSeq = *msg.UpdatedModSeq
			}

			if msg.ExpungedModSeq != nil && *msg.ExpungedModSeq > msgModSeq {
				msgModSeq = *msg.ExpungedModSeq
			}

			if uint64(msgModSeq) > highestModSeq {
				highestModSeq = uint64(msgModSeq)
			}
		}

		if highestModSeq > 0 {
			searchData.ModSeq = highestModSeq
		}
	}

	return searchData, nil
}

// decodeSearchCriteriaLocked translates sequence numbers in search criteria.
// IMPORTANT: The caller MUST hold s.mutex (either read or write lock) when calling this method.
func (s *IMAPSession) decodeSearchCriteriaLocked(criteria *imap.SearchCriteria) *imap.SearchCriteria {
	decoded := *criteria // make a shallow copy

	decoded.SeqNum = make([]imap.SeqSet, len(criteria.SeqNum))
	for i, seqSet := range criteria.SeqNum {
		decoded.SeqNum[i] = s.decodeNumSetLocked(seqSet).(imap.SeqSet)
	}

	// UID sets don't need decoding like sequence numbers do
	// The * wildcard should already be handled by the go-imap library

	decoded.Not = make([]imap.SearchCriteria, len(criteria.Not))
	for i, not := range criteria.Not {
		decoded.Not[i] = *s.decodeSearchCriteriaLocked(&not)
	}
	decoded.Or = make([][2]imap.SearchCriteria, len(criteria.Or))
	for i := range criteria.Or {
		for j := range criteria.Or[i] {
			decoded.Or[i][j] = *s.decodeSearchCriteriaLocked(&criteria.Or[i][j])
		}
	}

	return &decoded
}

// decodeSearchCriteria safely acquires the read mutex and translates sequence numbers in search criteria.
func (s *IMAPSession) decodeSearchCriteria(criteria *imap.SearchCriteria) *imap.SearchCriteria {
	acquired, cancel := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.Log("[SEARCH] Failed to acquire read lock for decodeSearchCriteria within timeout")
		// Return unmodified criteria if we can't acquire the lock
		return criteria
	}
	defer func() {
		s.mutex.RUnlock()
		cancel()
	}()

	return s.decodeSearchCriteriaLocked(criteria)
}
