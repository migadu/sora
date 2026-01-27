package imap

import (
	"fmt"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/pkg/metrics"
)

func (s *IMAPSession) Search(numKind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	// Check search rate limit first (before any expensive operations)
	if s.server.searchRateLimiter != nil && s.IMAPUser != nil {
		if err := s.server.searchRateLimiter.CanSearch(s.ctx, s.IMAPUser.AccountID()); err != nil {
			s.InfoLog("rate limited", "user", s.IMAPUser.FullAddress(), "account_id", s.IMAPUser.AccountID(), "error", err)
			metrics.ProtocolErrors.WithLabelValues("imap", "SEARCH", "rate_limited", "client_error").Inc()
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Text: err.Error(),
			}
		}
	}

	// First safely read and decode session state
	var selectedMailboxID int64
	var currentNumMessages uint32

	// If the session is closing, don't try to search.
	if s.ctx.Err() != nil {
		s.DebugLog("session context is cancelled, skipping search")
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Session closed"}
	}

	// Acquire read mutex to safely read session state
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.DebugLog("failed to acquire read lock within timeout")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}

	if s.selectedMailbox == nil {
		release() // Release read lock
		s.DebugLog("no mailbox selected")
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNonExistent,
			Text: "No mailbox selected",
		}
	}
	selectedMailboxID = s.selectedMailbox.ID
	currentNumMessages = s.currentNumMessages.Load()
	release() // Release read lock

	// Now decode search criteria using decodeSearchCriteriaLocked helper that we'll create
	criteria = s.decodeSearchCriteria(criteria)

	if currentNumMessages == 0 && len(criteria.SeqNum) > 0 {
		s.DebugLog("skipping SEARCH because mailbox is empty")
		if numKind == imapserver.NumKindUID {
			return &imap.SearchData{All: imap.UIDSet{}, Count: 0}, nil
		} else {
			return &imap.SearchData{All: imap.SeqSet{}, Count: 0}, nil
		}
	}

	// The configured search_timeout is now automatically applied by the resilient DB layer.
	messages, err := s.server.rdb.GetMessagesWithCriteriaWithRetry(s.ctx, selectedMailboxID, criteria)
	if err != nil {
		// The resilient layer already logs retry attempts. We just log the final error.
		s.DebugLog("[SEARCH] final error after retries", "error", err)
		s.classifyAndTrackError("SEARCH", err, nil)
		return nil, s.internalError("failed to search messages: %v", err)
	}

	// Track memory for search results (approximate: 200 bytes per message metadata)
	resultMemory := int64(len(messages) * 200)
	if s.memTracker != nil && resultMemory > 0 {
		if allocErr := s.memTracker.Allocate(resultMemory); allocErr != nil {
			metrics.SessionMemoryLimitExceeded.WithLabelValues("imap").Inc()
			return nil, s.internalError("session memory limit exceeded: %v", allocErr)
		}
		defer s.memTracker.Free(resultMemory)
	}

	searchData := &imap.SearchData{}

	var optionsStr string
	if options != nil {
		optionsStr = fmt.Sprintf("Min:%v Max:%v All:%v Count:%v Save:%v",
			options.ReturnMin, options.ReturnMax, options.ReturnAll, options.ReturnCount, options.ReturnSave)
	} else {
		optionsStr = "nil"
	}
	s.DebugLog("SEARCH command", "numKind", numKind, "options", optionsStr, "results", len(messages))

	// Check if this is actually an ESEARCH command (has RETURN options)
	// The library may pass an empty options struct for standard SEARCH, so we need to check if any options are actually set
	isESEARCH := options != nil && (options.ReturnMin || options.ReturnMax || options.ReturnAll || options.ReturnCount || options.ReturnSave)

	// If client uses ESEARCH syntax but ESEARCH capability is filtered, return error
	// RFC 5530 defines CLIENTBUG for when client violates server's advertised capabilities
	if isESEARCH && !s.GetCapabilities().Has(imap.CapESearch) {
		s.DebugLog("client using ESEARCH RETURN syntax but ESEARCH capability is filtered")
		metrics.ProtocolErrors.WithLabelValues("imap", "SEARCH", "esearch_not_advertised", "client_error").Inc()
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeClientBug,
			Text: "ESEARCH is not supported for this client",
		}
	}

	if isESEARCH && options != nil {
		s.InfoLog("ESEARCH options provided", "min", options.ReturnMin, "max", options.ReturnMax, "all", options.ReturnAll, "count", options.ReturnCount)

		// At this point, isESEARCH is true and capability is verified
		if options.ReturnMin || options.ReturnMax || options.ReturnAll || options.ReturnCount {
			// Only set count if explicitly requested
			// RFC 4731: COUNT should only be included when ReturnCount is true
			// Setting it unconditionally breaks iOS Mail parsing
			if options.ReturnCount {
				searchData.Count = uint32(len(messages))
			}

			// Always initialize All as empty set for ESEARCH to work around go-imap encoder bug
			// The encoder checks if All is nil/empty AFTER writing "ALL", causing parse errors
			var uids imap.UIDSet
			var seqNums imap.SeqSet

			if len(messages) > 0 {
				// Set fields for ESEARCH responses when we have results
				// Messages are returned in DESC order (newest first) from database
				// So messages[0] has the highest UID (MAX) and messages[len-1] has the lowest UID (MIN)
				// MIN and MAX should be UIDs for UID SEARCH, sequence numbers for regular SEARCH
				if options.ReturnMin {
					if numKind == imapserver.NumKindUID {
						// MIN is the smallest UID - last element in DESC order
						searchData.Min = uint32(messages[len(messages)-1].UID)
					} else {
						// For sequence number search, use the database sequence number directly
						// (see fetch.go for explanation of why we don't use EncodeSeqNum)
						searchData.Min = messages[len(messages)-1].Seq
					}
				}
				if options.ReturnMax {
					if numKind == imapserver.NumKindUID {
						// MAX is the largest UID - first element in DESC order
						searchData.Max = uint32(messages[0].UID)
					} else {
						// For sequence number search, use the database sequence number directly
						// (see fetch.go for explanation of why we don't use EncodeSeqNum)
						searchData.Max = messages[0].Seq
					}
				}

				// Populate ALL with actual results
				for _, msg := range messages {
					uids.AddNum(msg.UID)
					// Use database sequence numbers directly (no encoding needed)
					seqNums.AddNum(msg.Seq)
				}
			}

			// Always set All (even if empty) to ensure go-imap encoder works correctly
			if numKind == imapserver.NumKindUID {
				searchData.All = uids
			} else {
				searchData.All = seqNums
			}

			// RFC 4731: For ESEARCH, COUNT should be included unless explicitly excluded
			// The Count field is always set (line 59), but we need to ensure it's included in the response
			// The go-imap library will include Count in ESEARCH responses when it's set

		} else {
			// All ReturnMin, ReturnMax, ReturnAll, ReturnCount are false.
			// This means client used ESEARCH form (e.g. SEARCH RETURN ()) and expects default.
			// RFC 4731: "server SHOULD behave as if RETURN (COUNT) was specified."
			s.InfoLog("no specific RETURN options requested, defaulting to COUNT only")
			// Set count for default ESEARCH responses
			searchData.Count = uint32(len(messages))

			// Include ALL for ESEARCH responses when there are results
			// Note: When empty, we don't set All at all (not even empty sets)
			// This ensures go-imap outputs "ESEARCH (TAG ...) UID" without the "ALL" keyword
			if len(messages) > 0 {
				var uids imap.UIDSet
				var seqNums imap.SeqSet
				for _, msg := range messages {
					uids.AddNum(msg.UID)
					// Use database sequence numbers directly (no encoding needed)
					seqNums.AddNum(msg.Seq)
				}
				if numKind == imapserver.NumKindUID {
					searchData.All = uids
				} else {
					searchData.All = seqNums
				}
			}
		}
	}

	// Standard SEARCH response logic (when not using ESEARCH, i.e., no RETURN clause).
	// To generate a standard `* SEARCH` response, we only populate the `All` field.
	// The go-imap/v2 library will correctly generate an untagged `* SEARCH` response.
	// If we populated `Count`, it would incorrectly generate an `* ESEARCH` response.
	if !isESEARCH {
		s.DebugLog("standard SEARCH command, preparing untagged SEARCH response")

		if len(messages) > 0 {
			var uids imap.UIDSet
			var seqNums imap.SeqSet
			for _, msg := range messages {
				uids.AddNum(msg.UID)
				// Use database sequence numbers directly (no encoding needed)
				seqNums.AddNum(msg.Seq)
			}

			if numKind == imapserver.NumKindUID {
				searchData.All = uids
			} else {
				searchData.All = seqNums
			}
		}
	}

	// CONDSTORE functionality - only process if capability is enabled
	if s.GetCapabilities().Has(imap.CapCondStore) && criteria.ModSeq != nil {
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

	// Track domain and user command activity - SEARCH is expensive!
	if s.IMAPUser != nil {
		metrics.TrackDomainCommand("imap", s.IMAPUser.Address.Domain(), "SEARCH")
		metrics.TrackUserActivity("imap", s.IMAPUser.Address.FullAddress(), "command", 1)
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
	if s.ctx.Err() != nil {
		s.DebugLog("session context is cancelled, skipping decodeSearchCriteria")
		// Return unmodified criteria if context is cancelled
		return criteria
	}

	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.DebugLog("failed to acquire read lock for decodeSearchCriteria within timeout")
		// Return unmodified criteria if we can't acquire the lock
		return criteria
	}
	defer release()

	return s.decodeSearchCriteriaLocked(criteria)
}
