package imap

import (
	"fmt"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/db"
)

// MultiSearch implements imapserver.SessionMultiSearch for cross-mailbox searches.
func (s *IMAPSession) MultiSearch(numKind imapserver.NumKind, mailboxes []string, criteria *imap.SearchCriteria, options *imap.SearchOptions) ([]*imap.SearchData, error) {
	if s.server.searchRateLimiter != nil && s.IMAPUser != nil {
		if err := s.server.searchRateLimiter.CanSearch(s.ctx, s.IMAPUser.AccountID()); err != nil {
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Text: err.Error(),
			}
		}
	}

	if s.ctx.Err() != nil {
		s.DebugLog("session context is cancelled, skipping multisearch")
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Session closed"}
	}

	// Reject pathologically complex/deep criteria before decoding or building a query.
	if err := s.validateSearchCriteria("MULTISEARCH", criteria); err != nil {
		return nil, err
	}

	accountID := s.IMAPUser.AccountID()

	// Get all mailboxes for the account to resolve names to IDs
	allMailboxes, err := s.server.rdb.GetMailboxesWithRetry(s.ctx, accountID, false)
	if err != nil {
		s.DebugLog("[MULTISEARCH] failed to fetch mailboxes", "error", err)
		return nil, s.internalError("failed to retrieve mailboxes: %v", err)
	}

	mailboxMap := make(map[string]*db.DBMailbox)
	for _, m := range allMailboxes {
		mailboxMap[m.Name] = m
	}

	criteria = s.decodeSearchCriteria(criteria)

	var results []*imap.SearchData

	for _, mboxName := range mailboxes {
		mbox, exists := mailboxMap[mboxName]
		if !exists {
			// RFC 7377: "If a specified mailbox doesn't exist, the server SHOULD return a NO response."
			// However, typically IMAP ignores non-existent mailboxes in some contexts. We will return NO here.
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("Mailbox does not exist: %s", mboxName),
			}
		}

		// Execute search for this mailbox
		messages, err := s.server.rdb.SearchMessagesWithCriteriaWithRetry(s.ctx, mbox.ID, criteria, 0)
		if err != nil {
			s.DebugLog("[MULTISEARCH] final error after retries", "mailbox", mboxName, "error", err)
			s.classifyAndTrackError("MULTISEARCH", err, nil)
			return nil, s.internalError("failed to search messages in %s: %v", mboxName, err)
		}

		if len(messages) == 0 {
			// RFC 7377 §2.1: A server MUST NOT send an ESEARCH response for a
			// mailbox if the search does not match any messages in that mailbox.
			continue
		}

		// For MultiSearch we need to build SearchData.
		searchData := &imap.SearchData{
			Mailbox: mboxName,
		}

		if numKind == imapserver.NumKindUID {
			all := imap.UIDSet{}
			for _, m := range messages {
				all.AddNum(imap.UID(m.UID))
			}
			searchData.All = all
		} else {
			// Sequence numbers require mapping from DB to current sequence.
			// MULTISEARCH using sequence numbers is complex because each mailbox has its own sequence numbers.
			// Usually MULTISEARCH is done with UID MULTISEARCH.
			// For simplicity and correctness, if sequence numbers are requested, we'd need to load the SeqNum mapping.
			// Since MULTISEARCH across unselected mailboxes doesn't have a defined SeqNum context in Sora currently
			// without loading the whole mailbox cache, we return an error for Seq MULTISEARCH.
			if numKind == imapserver.NumKindSeq {
				return nil, &imap.Error{
					Type: imap.StatusResponseTypeBad,
					Text: "MULTISEARCH with sequence numbers is not supported across mailboxes. Use UID MULTISEARCH.",
				}
			}
		}

		// Calculate Min/Max/Count
		var count uint32
		var min, max uint32
		first := true

		if numKind == imapserver.NumKindUID {
			for _, m := range messages {
				count++
				uid := uint32(m.UID)
				if first {
					min = uid
					max = uid
					first = false
				} else {
					if uid < min {
						min = uid
					}
					if uid > max {
						max = uid
					}
				}
			}
		}

		if options != nil {
			if options.ReturnCount {
				searchData.Count = count
			}
			if options.ReturnMin {
				searchData.Min = min
			}
			if options.ReturnMax {
				searchData.Max = max
			}
		}

		results = append(results, searchData)
	}

	return results, nil
}
