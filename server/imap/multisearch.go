package imap

import (
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// MultiSearch implements imapserver.SessionMultiSearch — the RFC 7377 ESEARCH
// command with an "IN (source-options)" clause. The server layer parses the
// source into an *imap.SearchSource; here we resolve those scopes to a concrete,
// ACL-checked set of mailboxes and UID-search each. ESEARCH always reports UIDs
// (sequence numbers are meaningless for unselected mailboxes), and every result
// carries its Mailbox + UIDValidity so returned UIDs are unambiguous.
func (s *IMAPSession) MultiSearch(source *imap.SearchSource, criteria *imap.SearchCriteria, options *imap.SearchOptions) ([]*imap.SearchData, error) {
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

	// Fetch all mailboxes visible to the account (owned + shared). Each mailbox's
	// Subscribed flag is already sourced from the name-based subscriptions table
	// for this accessing user (migration 000046).
	allMailboxes, err := s.server.rdb.GetMailboxesWithRetry(s.ctx, accountID, false)
	if err != nil {
		s.DebugLog("[MULTISEARCH] failed to fetch mailboxes", "error", err)
		return nil, s.internalError("failed to retrieve mailboxes: %v", err)
	}

	// Resolve the source scopes to a concrete, ordered, de-duplicated mailbox set.
	mailboxes, err := s.resolveSearchSource(source, allMailboxes)
	if err != nil {
		return nil, err
	}

	criteria = s.decodeSearchCriteria(criteria)

	var results []*imap.SearchData

	for _, mbox := range mailboxes {
		// RFC 4314: SEARCH requires the 'r' (read) right. GetMailboxes also lists
		// shared mailboxes that are visible with only the 'l' (lookup) right, and
		// scope verbs may resolve to them; skip any the user cannot read so ESEARCH
		// cannot leak message UIDs/counts from them.
		hasRead, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, mbox.ID, accountID, 'r')
		if err != nil {
			return nil, s.internalError("failed to check read permission for %s: %v", mbox.Name, err)
		}
		if !hasRead {
			continue
		}

		messages, err := s.server.rdb.SearchMessagesWithCriteriaWithRetry(s.ctx, mbox.ID, criteria, 0)
		if err != nil {
			s.DebugLog("[MULTISEARCH] final error after retries", "mailbox", mbox.Name, "error", err)
			s.classifyAndTrackError("MULTISEARCH", err, nil)
			return nil, s.internalError("failed to search messages in %s: %v", mbox.Name, err)
		}

		if len(messages) == 0 {
			// RFC 7377 §2.1: a server MUST NOT send an ESEARCH response for a
			// mailbox in which the search matched no messages.
			continue
		}

		searchData := &imap.SearchData{
			Mailbox:     mbox.Name,
			UIDValidity: mbox.UIDValidity,
		}

		all := imap.UIDSet{}
		var count, min, max uint32
		first := true
		for _, m := range messages {
			uid := uint32(m.UID)
			all.AddNum(imap.UID(m.UID))
			count++
			if first {
				min, max = uid, uid
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
		searchData.All = all

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

// resolveSearchSource turns an ESEARCH source spec into an ordered, de-duplicated
// list of mailboxes to search, drawn from the account's visible mailboxes. Scope
// verbs (selected/inboxes/personal/subscribed/subtree/subtree-one) silently
// resolve to whatever exists; an explicitly named mailbox that does not exist
// yields NO [NONEXISTENT] (RFC 7377 §2.1). ACL filtering happens later, per result.
func (s *IMAPSession) resolveSearchSource(source *imap.SearchSource, allMailboxes []*db.DBMailbox) ([]*db.DBMailbox, error) {
	accountID := s.IMAPUser.AccountID()
	delim := string(consts.MailboxDelimiter)

	byLower := make(map[string]*db.DBMailbox, len(allMailboxes))
	for _, m := range allMailboxes {
		byLower[strings.ToLower(m.Name)] = m
	}

	var out []*db.DBMailbox
	seen := make(map[int64]struct{})
	add := func(m *db.DBMailbox) {
		if m == nil {
			return
		}
		if _, ok := seen[m.ID]; ok {
			return
		}
		seen[m.ID] = struct{}{}
		out = append(out, m)
	}

	if source.Selected && s.selectedMailbox != nil {
		if m, ok := byLower[strings.ToLower(s.selectedMailbox.Name)]; ok {
			add(m)
		} else {
			add(s.selectedMailbox)
		}
	}
	if source.Inboxes {
		add(byLower["inbox"])
	}
	if source.Personal {
		// The user's own namespace: owned mailboxes only (exclude shared, whose
		// AccountID is the sharing owner's).
		for _, m := range allMailboxes {
			if m.AccountID == accountID {
				add(m)
			}
		}
	}
	if source.Subscribed {
		// mbox.Subscribed is per accessing-user (name-based subscriptions table).
		for _, m := range allMailboxes {
			if m.Subscribed {
				add(m)
			}
		}
	}
	for _, root := range source.Subtree {
		lroot := strings.ToLower(root)
		prefix := lroot + delim
		for _, m := range allMailboxes {
			lname := strings.ToLower(m.Name)
			if lname == lroot || strings.HasPrefix(lname, prefix) {
				add(m)
			}
		}
	}
	for _, root := range source.SubtreeOne {
		lroot := strings.ToLower(root)
		prefix := lroot + delim
		for _, m := range allMailboxes {
			lname := strings.ToLower(m.Name)
			if lname == lroot {
				add(m)
				continue
			}
			if rest, ok := strings.CutPrefix(lname, prefix); ok && !strings.Contains(rest, delim) {
				add(m)
			}
		}
	}
	for _, name := range source.Mailboxes {
		m, ok := byLower[strings.ToLower(name)]
		if !ok {
			// RFC 7377: "If a specified mailbox doesn't exist, the server SHOULD
			// return a NO response." (Applies only to explicitly named mailboxes.)
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("Mailbox does not exist: %s", name),
			}
		}
		add(m)
	}

	return out, nil
}
