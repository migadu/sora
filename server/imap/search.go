package imap

import (
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

func (s *IMAPSession) Search(numKind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	criteria = s.decodeSearchCriteria(criteria)

	if s.currentNumMessages == 0 && len(criteria.SeqNum) > 0 {
		s.Log("[SEARCH] skipping UID SEARCH because mailbox is empty")
		return &imap.SearchData{
			All:   imap.UIDSet{},
			Count: 0,
		}, nil
	}

	messages, err := s.server.db.GetMessagesWithCriteria(s.ctx, s.selectedMailbox.ID, criteria)
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
					seqNums.AddNum(s.sessionTracker.EncodeSeqNum(msg.Seq))
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
			seqNums.AddNum(s.sessionTracker.EncodeSeqNum(msg.Seq))
		}

		if numKind == imapserver.NumKindUID {
			searchData.All = uids
		} else {
			searchData.All = seqNums
		}
	}

	// hasModSeqCriteria := criteria.ModSeq != nil
	// _, hasCondStore := s.server.caps[imap.CapCondStore]

	// if hasCondStore && hasModSeqCriteria {
	// 	var highestModSeq uint64
	// 	for _, msg := range messages {
	// 		var msgModSeq int64
	// 		msgModSeq = msg.CreatedModSeq

	// 		if msg.UpdatedModSeq != nil && *msg.UpdatedModSeq > msgModSeq {
	// 			msgModSeq = *msg.UpdatedModSeq
	// 		}

	// 		if msg.ExpungedModSeq != nil && *msg.ExpungedModSeq > msgModSeq {
	// 			msgModSeq = *msg.ExpungedModSeq
	// 		}

	// 		if uint64(msgModSeq) > highestModSeq {
	// 			highestModSeq = uint64(msgModSeq)
	// 		}
	// 	}

	// 	if highestModSeq > 0 {
	// 		searchData.ModSeq = highestModSeq
	// 	}
	// }

	return searchData, nil
}

func (s *IMAPSession) decodeSearchCriteria(criteria *imap.SearchCriteria) *imap.SearchCriteria {
	decoded := *criteria // make a shallow copy

	decoded.SeqNum = make([]imap.SeqSet, len(criteria.SeqNum))
	for i, seqSet := range criteria.SeqNum {
		decoded.SeqNum[i] = s.decodeNumSet(seqSet).(imap.SeqSet)
	}

	decoded.Not = make([]imap.SearchCriteria, len(criteria.Not))
	for i, not := range criteria.Not {
		decoded.Not[i] = *s.decodeSearchCriteria(&not)
	}
	decoded.Or = make([][2]imap.SearchCriteria, len(criteria.Or))
	for i := range criteria.Or {
		for j := range criteria.Or[i] {
			decoded.Or[i][j] = *s.decodeSearchCriteria(&criteria.Or[i][j])
		}
	}

	return &decoded
}
