package imap

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// MultiSearch implements imapserver.SessionMultiSearch — the RFC 7377 ESEARCH
// command with an "IN (source-options)" clause. The server layer parses the
// source into an *imap.SearchSource; here we resolve those scopes to a concrete,
// ACL-checked set of mailboxes and UID-search each. ESEARCH always reports UIDs
// (sequence numbers are meaningless for unselected mailboxes), and every result
// carries its Mailbox + UIDValidity so returned UIDs are unambiguous.
func (s *IMAPSession) MultiSearch(ctx context.Context, source *imap.SearchSource, criteria *imap.SearchCriteria, options *imap.SearchOptions) (_ []*imap.SearchData, err error) {
	// RFC 7377 §2: the ESEARCH command, with or without IN, is MULTISEARCH's.
	if err := s.requireCapability(imap.CapMultiSearch, "ESEARCH"); err != nil {
		return nil, err
	}

	if options != nil && options.ReturnSave {
		defer func() { s.emptySavedSearchOnNo(err) }()
	}

	if ctx.Err() != nil {
		s.DebugLog("session context is cancelled, skipping multisearch")
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "Session closed"}
	}

	// Reject pathologically complex/deep criteria before decoding or building a query.
	if err := s.validateSearchCriteria("MULTISEARCH", criteria); err != nil {
		return nil, err
	}

	// A multi-mailbox search runs one search per mailbox in scope, so it is always
	// charged to the SEARCH rate limit, whatever its criteria.
	if err := s.chargeSearch(ctx); err != nil {
		return nil, err
	}

	// The selected mailbox's sequence numbering holds still while MultiSearch
	// translates through it (seqViewMu); taken before s.mutex.
	s.seqViewMu.RLock()
	defer s.seqViewMu.RUnlock()

	if s.useMasterDB.Load() {
		ctx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	}
	accountID := s.IMAPUser.AccountID()

	// Fetch all mailboxes visible to the account (owned + shared). Each mailbox's
	// Subscribed flag is already sourced from the name-based subscriptions table
	// for this accessing user (migration 000046).
	allMailboxes, err := s.server.rdb.GetMailboxesWithRetry(ctx, accountID, false)
	if err != nil {
		s.DebugLog("[MULTISEARCH] failed to fetch mailboxes", "error", err)
		return nil, s.internalError("failed to retrieve mailboxes: %v", err)
	}

	// Resolve the source scopes to a concrete, ordered, de-duplicated mailbox set.
	mailboxes, err := s.resolveSearchSource(ctx, source, allMailboxes)
	if err != nil {
		return nil, err
	}

	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		return nil, s.internalError("failed to acquire lock for multisearch")
	}
	// "$" holds UIDs of the selected mailbox, so it names no message in any other.
	var selectedMailboxID int64
	if s.selectedMailbox != nil {
		selectedMailboxID = s.selectedMailbox.ID
	}
	savedSearchUIDs := s.savedSearchResultLocked()
	view := s.seqViewLocked()
	release()

	var results []*imap.SearchData
	condStore := s.GetCapabilities().Has(imap.CapCondStore)

	// RETURN (SAVE) sets "$" as SEARCH does. go-imap allows it only when the
	// selected mailbox is the sole source (RFC 7377 §2.2), so at most one mailbox
	// contributes; one with no match leaves the saved set empty.
	var saved imap.UIDSet
	for _, mbox := range mailboxes {
		// RFC 4314: SEARCH requires the 'r' (read) right. GetMailboxes also lists
		// shared mailboxes that are visible with only the 'l' (lookup) right, and
		// scope verbs may resolve to them; skip any the user cannot read so ESEARCH
		// cannot leak message UIDs/counts from them. The owner has every right
		// (has_mailbox_right returns TRUE for it first), so only a mailbox another
		// account owns costs the round trip, as in NOTIFY's STATUS fan-in.
		if mbox.AccountID != accountID {
			hasRead, err := s.server.rdb.CheckMailboxPermissionWithRetry(ctx, mbox.ID, accountID, db.ACLRightRead)
			if err != nil {
				return nil, s.internalError("failed to check read permission for %s: %v", mbox.Name, err)
			}
			if !hasRead {
				continue
			}
		}

		// mbox.AccountID, never the session accountID above: for a shared mailbox the FTS
		// rows belong to the owner. No message count is available per mailbox here, so 0
		// selects the default (per-message probe) query shape.
		mboxSaved := imap.UIDSet{}
		if mbox.ID == selectedMailboxID {
			mboxSaved = savedSearchUIDs
		}
		mboxCriteria := searchResAsUIDs(criteria, mboxSaved)
		searchCtx := ctx
		if mbox.ID == selectedMailboxID && view.tracker != nil {
			mboxCriteria = view.decodeCriteria(mboxCriteria)
			searchCtx = view.context(ctx)
		}
		mboxCriteria, err = s.withSessionRecent(mboxCriteria, mbox.ID)
		if err != nil {
			return nil, err
		}
		messages, err := s.server.rdb.SearchMessagesWithCriteriaWithRetry(searchCtx, mbox.ID, mbox.AccountID, mboxCriteria, 0, 0)
		if errors.Is(err, db.ErrSearchTooManyResults) {
			return nil, s.searchResultLimitError("MULTISEARCH", "mailbox", mbox.Name)
		}
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
		var minIdx, maxIdx int
		first := true
		for i, m := range messages {
			uid := uint32(m.UID)
			all.AddNum(imap.UID(m.UID))
			count++
			if first {
				min, max = uid, uid
				first = false
			} else {
				if uid < min {
					min, minIdx = uid, i
				}
				if uid > max {
					max, maxIdx = uid, i
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
		if condStore {
			searchData.ModSeq = returnedModSeq(messages, minIdx, maxIdx, options)
		}
		if options != nil && options.ReturnSave {
			saved = savedSearchSet(messages, minIdx, maxIdx, options)
		}

		results = append(results, searchData)
	}

	if options != nil && options.ReturnSave {
		s.setSavedSearchResult(saved)
		s.DebugLog("saved ESEARCH result for '$'", "count", len(saved))
	}

	return results, nil
}

// resolveSearchSource turns an ESEARCH source spec into an ordered, de-duplicated
// list of mailboxes to search, drawn from the account's visible mailboxes. Scope
// verbs (selected/inboxes/personal/subscribed/subtree/subtree-one) require lookup
// visibility. Explicit names additionally allow read-only ACL visibility (r without
// l); inaccessible names are ignored (RFC 7377 §2.2). Read checks follow per result.
//
// Names are matched as the database matches them, by LOWER(name) under its
// collation, which no Go case mapping matches (under ICU "İNBOX" is not the
// INBOX): the mailboxes carry it as NameKey, and the names the source gives, and
// INBOX, are resolved to theirs in one query. The selected mailbox is taken by ID.
func (s *IMAPSession) resolveSearchSource(ctx context.Context, source *imap.SearchSource, allMailboxes []*db.DBMailbox) ([]*db.DBMailbox, error) {
	accountID := s.IMAPUser.AccountID()
	delim := string(consts.MailboxDelimiter)
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		return nil, s.internalError("failed to snapshot selected ESEARCH source")
	}
	var selected *db.DBMailbox
	if s.selectedMailbox != nil {
		copy := *s.selectedMailbox
		selected = &copy
	}
	release()

	var names []string
	if source.Inboxes {
		names = append(names, consts.MailboxInbox)
	}
	names = append(names, source.Subtree...)
	names = append(names, source.SubtreeOne...)
	names = append(names, source.Mailboxes...)
	var keys []string
	if len(names) > 0 {
		var err error
		if keys, err = s.server.rdb.MailboxNameKeysWithRetry(ctx, names); err != nil {
			return nil, s.internalError("failed to resolve search mailbox names: %v", err)
		}
	}
	// nextKeys returns the keys of the next n names, in the order they were added.
	nextKeys := func(n int) []string {
		k := keys[:n]
		keys = keys[n:]
		return k
	}

	byKey := make(map[string]*db.DBMailbox, len(allMailboxes))
	for _, m := range allMailboxes {
		byKey[m.NameKey] = m
	}

	var out []*db.DBMailbox
	seen := make(map[int64]struct{})
	add := func(m *db.DBMailbox) {
		if m == nil {
			return
		}
		// Apply Sora's \Noselect shared-root policy to message searches too.
		// NOTIFY tree-event source matching remains separate.
		if s.server.config != nil && s.server.config.SharedMailboxes.IsNamespaceRoot(m.Name) {
			return
		}
		if _, ok := seen[m.ID]; ok {
			return
		}
		seen[m.ID] = struct{}{}
		out = append(out, m)
	}

	if source.Selected && selected != nil {
		m := selected
		if i := slices.IndexFunc(allMailboxes, func(live *db.DBMailbox) bool { return live.ID == selected.ID }); i >= 0 {
			m = allMailboxes[i]
		}
		add(m)
	}
	if source.Inboxes {
		add(byKey[nextKeys(1)[0]])
	}
	if source.Personal {
		// RFC 5465 §6.2: all selectable mailboxes in the personal namespace(s), as
		// NOTIFY's PERSONAL watches them. A shared mailbox the user owns is not one.
		sharedRoot := s.sharedNamespaceRoot()
		for _, m := range allMailboxes {
			if !inSharedNamespace(m.Name, sharedRoot) {
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
	// A descendant's key starts with its ancestor's: lower() leaves the hierarchy
	// delimiter alone, as the database relies on when it matches descendants by
	// LOWER(name) LIKE LOWER(prefix) || '%'.
	for _, root := range nextKeys(len(source.Subtree)) {
		if root == "" {
			continue // names no mailbox
		}
		prefix := root + delim
		for _, m := range allMailboxes {
			if m.NameKey == root || strings.HasPrefix(m.NameKey, prefix) {
				add(m)
			}
		}
	}
	for _, root := range nextKeys(len(source.SubtreeOne)) {
		if root == "" {
			continue // names no mailbox
		}
		prefix := root + delim
		for _, m := range allMailboxes {
			if m.NameKey == root {
				add(m)
				continue
			}
			if rest, ok := strings.CutPrefix(m.NameKey, prefix); ok && !strings.Contains(rest, delim) {
				add(m)
			}
		}
	}
	for i, key := range nextKeys(len(source.Mailboxes)) {
		m, ok := byKey[key]
		if !ok {
			var err error
			m, err = s.server.rdb.GetMailboxByNameForRightWithRetry(ctx, accountID, source.Mailboxes[i], db.ACLRightRead)
			if errors.Is(err, consts.ErrMailboxNotFound) {
				continue
			}
			if err != nil {
				return nil, s.internalError("failed to resolve explicit search mailbox: %v", err)
			}
		}
		add(m)
	}

	return out, nil
}
