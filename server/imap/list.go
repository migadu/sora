package imap

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

func (s *IMAPSession) List(ctx context.Context, w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	// If no patterns, just return a simple response without any database operations
	if len(patterns) == 0 {
		return w.WriteList(&imap.ListData{
			Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect},
			Delim: consts.MailboxDelimiter,
		})
	}

	// Create a context that signals to use the master DB if the session is pinned.
	readCtx := ctx
	if s.useMasterDB.Load() {
		readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	}

	// Database operations should be done outside of lock
	// For LSUB, we need all mailboxes to find parents of subscribed ones
	mboxes, err := s.server.rdb.GetMailboxesWithRetry(readCtx, s.AccountID(), false)
	if err != nil {
		return s.internalError("failed to fetch mailboxes: %v", err)
	}

	// Each mbox.Subscribed is already sourced from the name-based subscriptions
	// table (migration 000046) by GetMailboxes. We additionally fetch the full
	// subscribed-name set here so LSUB / LIST (SUBSCRIBED) can also report
	// subscribed names that have NO live mailbox (RFC 3501 §6.3.6 / RFC 9051
	// §6.3.7). subscribedSet maps LOWER(name) -> the stored spelling.
	subNames, err := s.server.rdb.GetSubscribedMailboxNamesWithRetry(readCtx, s.AccountID())
	if err != nil {
		return s.internalError("failed to fetch subscriptions: %v", err)
	}
	subscribedSet := make(map[string]string, len(subNames))
	for _, n := range subNames {
		subscribedSet[strings.ToLower(n)] = n
	}

	// Build name -> DBMailbox mapping for batch STATUS lookups
	nameToMailbox := make(map[string]*db.DBMailbox, len(mboxes))
	for _, mbox := range mboxes {
		nameToMailbox[mbox.Name] = mbox
	}

	// Shared-namespace root (e.g. "Shared" for prefix "Shared/"), used to mark that
	// root \Noselect. Empty when shared mailboxes are disabled.
	sharedNamespaceRoot := ""
	if s.server.config != nil && s.server.config.SharedMailboxes.Enabled {
		sharedNamespaceRoot = strings.TrimSuffix(s.server.config.SharedMailboxes.NamespacePrefix, string(consts.MailboxDelimiter))
	}

	var l []imap.ListData
	if options.SelectSubscribed {
		// SUBSCRIBED selection (RFC 5258 §3.5), including RECURSIVEMATCH/CHILDINFO
		// and non-existent subscribed names. LSUB arrives here too — the go-imap
		// layer dispatches it as LIST (SUBSCRIBED RECURSIVEMATCH) and renders the
		// CHILDINFO parents as \Noselect.
		l = buildSubscribedList(ref, patterns, options, mboxes, subscribedSet, s.GetCapabilities(), sharedNamespaceRoot)
	} else {
		for _, mbox := range mboxes {
			if !matchesAnyPattern(mbox.Name, ref, patterns) {
				continue
			}
			data := listMailbox(mbox, options, s.GetCapabilities(), sharedNamespaceRoot)
			if data != nil {
				l = append(l, *data)
			}
		}
	}

	sort.Slice(l, func(i, j int) bool {
		return l[i].Mailbox < l[j].Mailbox
	})

	hasListStatusCap := s.GetCapabilities().Has(imap.CapListStatus)

	// Now handle STATUS returns if needed - after we've processed all mailboxes
	// Use batch query to fetch all summaries in a single database round-trip
	// instead of N individual Status() calls (which each do 3 queries).
	if options.ReturnStatus != nil && hasListStatusCap {
		// Collect mailbox IDs for all listed mailboxes
		var mailboxIDs []int64
		for _, data := range l {
			if data.Mailbox == "" {
				continue
			}
			if mbox, ok := nameToMailbox[data.Mailbox]; ok {
				mailboxIDs = append(mailboxIDs, mbox.ID)
			}
		}

		if len(mailboxIDs) > 0 {
			// Single batch query replaces N * 3 individual queries
			summaries, err := s.server.rdb.GetMailboxSummariesBatchWithRetry(readCtx, mailboxIDs)
			if err != nil {
				s.DebugLog("failed to get batch mailbox summaries", "error", err)
			} else {
				// Populate STATUS data from batch results
				for i := range l {
					data := &l[i]
					if data.Mailbox == "" {
						continue
					}
					mbox, ok := nameToMailbox[data.Mailbox]
					if !ok {
						continue
					}
					// RFC 4314: STATUS data requires the 'r' (read) right. A shared mailbox can
					// be listed with only 'l' (lookup); don't leak its counts via LIST-STATUS.
					// Owned mailboxes (owner == this account) always have 'r', so only the few
					// shared ones incur an ACL check — the batch fast path is preserved.
					if mbox.AccountID != s.AccountID() {
						hasRead, permErr := s.server.rdb.CheckMailboxPermissionWithRetry(readCtx, mbox.ID, s.AccountID(), 'r')
						if permErr != nil {
							s.DebugLog("LIST-STATUS: skipping STATUS, ACL read-check failed", "mailbox", data.Mailbox, "error", permErr)
							continue
						}
						if !hasRead {
							continue
						}
					}
					summary, ok := summaries[mbox.ID]
					if !ok {
						continue
					}

					statusData := &imap.StatusData{
						Mailbox:     data.Mailbox,
						UIDValidity: mbox.UIDValidity,
					}

					if options.ReturnStatus.NumMessages {
						num := uint32(summary.NumMessages)
						statusData.NumMessages = &num
					}
					if options.ReturnStatus.UIDNext {
						statusData.UIDNext = imap.UID(summary.UIDNext)
					}
					if options.ReturnStatus.NumRecent {
						num := uint32(summary.RecentCount)
						statusData.NumRecent = &num
					}
					if options.ReturnStatus.NumUnseen {
						// The unseen_count cache can underflow below zero under concurrent
						// flag/expunge races (see db.lockMailboxStats). Self-heal by
						// recomputing from the authoritative message_state, then use the
						// repaired value; fall back to clamping if the repair fails.
						unseenCount := summary.UnseenCount
						if unseenCount < 0 {
							s.WarnLog("negative unseen_count detected in LIST, recomputing", "mailbox", mbox.Name, "unseen_count", unseenCount)
							if repaired, rErr := s.server.rdb.RecomputeMailboxUnseenWithRetry(ctx, mbox.ID); rErr != nil {
								s.WarnLog("failed to recompute unseen_count in LIST, clamping to 0", "mailbox", mbox.Name, "err", rErr)
								unseenCount = 0
							} else {
								unseenCount = int(repaired)
							}
						}
						num := uint32(unseenCount)
						statusData.NumUnseen = &num
					}
					if s.GetCapabilities().Has(imap.CapCondStore) && options.ReturnStatus.HighestModSeq {
						statusData.HighestModSeq = summary.HighestModSeq
					}
					if options.ReturnStatus.AppendLimit && s.server.appendLimit > 0 {
						limit := uint32(s.server.appendLimit)
						statusData.AppendLimit = &limit
					}
					if options.ReturnStatus.Size {
						size := summary.TotalSize
						statusData.Size = &size
					}

					data.Status = statusData

					numMessagesStr := "n/a"
					if statusData.NumMessages != nil {
						numMessagesStr = fmt.Sprint(*statusData.NumMessages)
					}
					numUnseenStr := "n/a"
					if statusData.NumUnseen != nil {
						numUnseenStr = fmt.Sprint(*statusData.NumUnseen)
					}

					s.DebugLog("mailbox status", "mailbox", data.Mailbox, "num_messages", numMessagesStr, "uid_next", statusData.UIDNext, "uid_validity", statusData.UIDValidity, "num_unseen", numUnseenStr, "highest_modseq", statusData.HighestModSeq)
				}
			}
		}
	}

	// Write all responses
	for _, data := range l {
		if err := w.WriteList(&data); err != nil {
			return err
		}
	}
	return nil
}

// matchesAnyPattern reports whether name matches any of the LIST patterns given
// the reference name.
func matchesAnyPattern(name, ref string, patterns []string) bool {
	for _, pattern := range patterns {
		if imapserver.MatchList(name, consts.MailboxDelimiter, ref, pattern) {
			return true
		}
	}
	return false
}

// hasSubscribedDescendant reports whether any subscribed name is a proper
// descendant of lowerName (i.e. lives under "lowerName<delim>…"). The keys of
// subscribedSet are already lower-cased, and lowerName must be lower-cased too.
func hasSubscribedDescendant(lowerName, delim string, subscribedSet map[string]string) bool {
	prefix := lowerName + delim
	for s := range subscribedSet {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// buildSubscribedList implements the SUBSCRIBED selection option (RFC 5258 §3.5),
// including RECURSIVEMATCH/CHILDINFO and subscriptions to non-existent names. It
// returns, for names matching the pattern:
//
//   - every subscribed name (live → its real attributes; non-live →
//     \NonExistent), flagged \Subscribed; and
//   - when RECURSIVEMATCH is set, any name that is NOT itself subscribed but has
//     a subscribed descendant, carrying a CHILDINFO (SUBSCRIBED) extended data
//     item (plus \NonExistent when the name has no live mailbox). This is the
//     "% wildcard returns the parent" case of RFC 3501 §6.3.9; the go-imap LSUB
//     writer renders such CHILDINFO parents as \Noselect.
//
// Without RECURSIVEMATCH, only subscribed names are returned — plain
// LIST (SUBSCRIBED) must NOT synthesize non-subscribed parents.
//
// subscribedSet maps LOWER(name) -> stored spelling.
func buildSubscribedList(ref string, patterns []string, options *imap.ListOptions,
	mboxes []*db.DBMailbox, subscribedSet map[string]string,
	serverCaps imap.CapSet, sharedNamespaceRoot string) []imap.ListData {

	recursive := options.SelectRecursiveMatch
	delim := string(consts.MailboxDelimiter)

	liveByLower := make(map[string]*db.DBMailbox, len(mboxes))
	for _, m := range mboxes {
		liveByLower[strings.ToLower(m.Name)] = m
	}

	// Candidate universe, keyed by LOWER(name) -> display spelling: live
	// mailboxes, subscribed names, and — for RECURSIVEMATCH — the ancestors of
	// every subscribed name (so a non-existent parent of a subscribed child can
	// still be reported with CHILDINFO).
	candidates := make(map[string]string, len(mboxes)+len(subscribedSet))
	for _, m := range mboxes {
		candidates[strings.ToLower(m.Name)] = m.Name
	}
	for lname, disp := range subscribedSet {
		if _, ok := candidates[lname]; !ok {
			candidates[lname] = disp
		}
	}
	if recursive {
		for _, disp := range subscribedSet {
			parts := strings.Split(disp, delim)
			for i := 1; i < len(parts); i++ {
				anc := strings.Join(parts[:i], delim)
				la := strings.ToLower(anc)
				if _, ok := candidates[la]; !ok {
					candidates[la] = anc
				}
			}
		}
	}

	var l []imap.ListData
	for lname, name := range candidates {
		if !matchesAnyPattern(name, ref, patterns) {
			continue
		}
		_, isSub := subscribedSet[lname]
		hasSubChild := recursive && hasSubscribedDescendant(lname, delim, subscribedSet)
		if !isSub && !hasSubChild {
			continue // not subscribed and no subscribed descendant → not in SUBSCRIBED response
		}

		var data imap.ListData
		if m, ok := liveByLower[lname]; ok {
			md := listMailbox(m, options, serverCaps, sharedNamespaceRoot)
			if md == nil {
				continue // filtered out (e.g. SELECT SPECIAL-USE with no special-use)
			}
			data = *md
			// listMailbox has already appended \Subscribed iff the mailbox is
			// subscribed, which matches isSub.
		} else {
			// A subscribed-or-ancestor name with no live mailbox cannot carry a
			// special-use attribute, so it is excluded from SELECT SPECIAL-USE.
			if options.SelectSpecialUse {
				continue
			}
			data = imap.ListData{
				Mailbox: name,
				Delim:   consts.MailboxDelimiter,
				Attrs:   []imap.MailboxAttr{imap.MailboxAttrNonExistent},
			}
			if isSub {
				data.Attrs = append(data.Attrs, imap.MailboxAttrSubscribed)
			}
		}

		if hasSubChild {
			data.ChildInfo = &imap.ListDataChildInfo{Subscribed: true}
		}
		l = append(l, data)
	}
	return l
}

func listMailbox(mbox *db.DBMailbox, options *imap.ListOptions, serverCaps imap.CapSet, sharedNamespaceRoot string) *imap.ListData {
	attributes := []imap.MailboxAttr{}

	// Add \Noselect for the shared-namespace root (e.g. "Shared" for prefix
	// "Shared/", or the configured namespace_prefix). This prevents clients from
	// trying to SELECT the namespace prefix itself. sharedNamespaceRoot is empty
	// when shared mailboxes are disabled, so a personal folder that happens to be
	// named like the prefix is not falsely marked \Noselect.
	if sharedNamespaceRoot != "" && strings.EqualFold(mbox.Name, sharedNamespaceRoot) && mbox.HasChildren {
		attributes = append(attributes, imap.MailboxAttrNoSelect)
	}

	if serverCaps.Has(imap.CapChildren) {
		if mbox.HasChildren {
			attributes = append(attributes, imap.MailboxAttrHasChildren)
		} else {
			attributes = append(attributes, imap.MailboxAttrHasNoChildren)
		}
	}

	// RFC 6154 special-use is a persisted per-mailbox attribute (see the
	// special_use column / migration 000045), not derived from the folder name.
	// This makes it survive RENAME/localization and honors CREATE ... USE.
	hasSpecialUse := mbox.SpecialUse != ""

	// SELECT (SPECIAL-USE): return only mailboxes that actually carry a
	// special-use attribute.
	if options.SelectSpecialUse && !hasSpecialUse {
		return nil
	}

	if hasSpecialUse {
		if serverCaps.Has(imap.CapSpecialUse) || options.ReturnSpecialUse || options.SelectSpecialUse {
			attributes = append(attributes, imap.MailboxAttr(mbox.SpecialUse))
		}
	}

	data := imap.ListData{
		Mailbox: mbox.Name,
		Delim:   consts.MailboxDelimiter,
		Attrs:   attributes,
	}
	if mbox.Subscribed {
		data.Attrs = append(data.Attrs, imap.MailboxAttrSubscribed)
	}
	return &data
}
