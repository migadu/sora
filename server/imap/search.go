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
	s.mutex.RLock()
	if s.selectedMailbox == nil {
		s.mutex.RUnlock()
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
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.decodeSearchCriteriaLocked(criteria)
}
