package imap

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

func (s *IMAPSession) List(ctx context.Context, w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	// RFC 5258 §3: each LIST option is "enabled by a capability string", and "a
	// client MUST NOT send an option for which the server has not advertised
	// support". go-imap refuses the LIST-EXTENDED syntax itself; the SPECIAL-USE
	// selection and return options are SPECIAL-USE's (RFC 6154 §2), the STATUS
	// return option is LIST-STATUS's (RFC 5819 §2) and the METADATA return option
	// LIST-METADATA's (RFC 9590 §1), which the default capabilities leave out.
	if options.SelectSpecialUse || options.ReturnSpecialUse {
		if err := s.requireCapability(imap.CapSpecialUse, "LIST SPECIAL-USE"); err != nil {
			return err
		}
	}
	if options.ReturnStatus != nil {
		if err := s.requireCapability(imap.CapListStatus, "LIST RETURN (STATUS)"); err != nil {
			return err
		}
		if err := s.checkStatusItems(options.ReturnStatus); err != nil {
			return err
		}
	}
	if options.ReturnMetadata != nil {
		if err := s.requireCapability(imap.CapListMetadata, "LIST RETURN (METADATA)"); err != nil {
			return err
		}
	}

	// go-imap omits "" from patterns for both plain LIST ref "" and extended LIST
	// with selection or return options. Per RFC 5258 §3 and RFC 9051 §6.3.9.1, an
	// empty "" mailbox name argument has no special meaning when any selection or
	// return options are specified and returns no LIST responses because there is
	// no mailbox with an empty name.
	if len(patterns) == 0 {
		if hasListOptions(options) {
			return nil
		}
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

	// Build name -> DBMailbox mapping for batch STATUS lookups
	nameToMailbox := make(map[string]*db.DBMailbox, len(mboxes))
	for _, mbox := range mboxes {
		nameToMailbox[mbox.Name] = mbox
	}

	// Shared-namespace root (e.g. "Shared" for prefix "Shared/"), used to mark that
	// root \Noselect. Empty when shared mailboxes are disabled.
	sharedNamespaceRoot := s.sharedNamespaceRoot()

	// The capability set cannot change during a command, so read its immutable
	// snapshot once rather than per mailbox.
	caps := s.GetCapabilities()

	superiors := visibleSuperiors(mboxes)

	var l []imap.ListData
	if options.SelectSubscribed {
		// SUBSCRIBED selection (RFC 5258 §3.5), including RECURSIVEMATCH/CHILDINFO
		// and non-existent subscribed names. LSUB arrives here too — the go-imap
		// layer dispatches it as LIST (SUBSCRIBED RECURSIVEMATCH) and renders the
		// CHILDINFO parents as \Noselect.
		//
		// Each mbox.Subscribed is already sourced from the name-based subscriptions
		// table (migration 000046) by GetMailboxes. The full subscribed-name set is
		// fetched as well so LSUB / LIST (SUBSCRIBED) can also report subscribed
		// names that have NO live mailbox (RFC 3501 §6.3.6 / RFC 9051 §6.3.7).
		subscribed, err := s.server.rdb.GetSubscribedMailboxNamesByKeyWithRetry(readCtx, s.AccountID())
		if err != nil {
			return s.internalError("failed to fetch subscriptions: %v", err)
		}
		l = buildSubscribedList(ref, patterns, options, mboxes, superiors, subscribed, caps, sharedNamespaceRoot)
	} else {
		for _, mbox := range mboxes {
			if !matchesAnyPattern(mbox.Name, ref, patterns) {
				continue
			}
			data := listMailbox(mbox, superiors[mbox.NameKey], options, caps, sharedNamespaceRoot)
			if data != nil {
				l = append(l, *data)
			}
		}
	}

	sort.Slice(l, func(i, j int) bool {
		return l[i].Mailbox < l[j].Mailbox
	})

	// Now handle STATUS returns if needed - after we've processed all mailboxes
	// Use batch query to fetch all summaries in a single database round-trip
	// instead of N individual Status() calls (which each do 3 queries).
	if options.ReturnStatus != nil {
		// Collect the listed entries that get a STATUS response: selectable
		// mailboxes that matched the selection options and that this user may
		// read (RFC 5819 §2 / RFC 9051 §6.3.9.2).
		var wanted []int // indices into l
		var mailboxIDs []int64
		for i := range l {
			data := &l[i]
			if !listEntryWantsStatus(data, options) {
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
					// RFC 5819 §2: on unexpected problems the server "MAY drop the
					// corresponding STATUS reply".
					s.DebugLog("LIST-STATUS: skipping STATUS, ACL read-check failed", "mailbox", data.Mailbox, "error", permErr)
					continue
				}
				if !hasRead {
					// RFC 5819 §2: when STATUS fails because the mailbox can't be
					// selected ("l" granted, "r" not), "the STATUS response MUST NOT
					// be returned and the LIST response MUST include the \NoSelect
					// attribute".
					data.Attrs = append(data.Attrs, imap.MailboxAttrNoSelect)
					continue
				}
			}
			wanted = append(wanted, i)
			mailboxIDs = append(mailboxIDs, mbox.ID)
		}

		if len(mailboxIDs) > 0 {
			// Single batch query replaces N * 3 individual queries
			summaries, err := s.server.rdb.GetMailboxSummariesBatchWithRetry(readCtx, mailboxIDs)
			var deleted map[int64]uint32
			if err == nil && options.ReturnStatus.NumDeleted {
				deleted, err = s.server.rdb.CountDeletedMessagesWithRetry(readCtx, mailboxIDs)
			}
			if err != nil {
				// RFC 5819 §2: on unexpected problems the server "MAY drop the
				// corresponding STATUS reply".
				s.DebugLog("failed to get batch mailbox status", "error", err)
			} else {
				// Populate STATUS data from batch results
				for _, i := range wanted {
					data := &l[i]
					mbox := nameToMailbox[data.Mailbox]
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
						num := s.statusNumRecent(readCtx, mbox.ID, summary)
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
					if caps.Has(imap.CapCondStore) && options.ReturnStatus.HighestModSeq {
						statusData.HighestModSeq = summary.HighestModSeq
					}
					if options.ReturnStatus.AppendLimit {
						limit := s.AppendLimit()
						statusData.AppendLimit = &limit
					}
					if options.ReturnStatus.NumDeleted {
						num := deleted[mbox.ID]
						statusData.NumDeleted = &num
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

// hasListOptions reports whether any LIST-EXTENDED selection or return option
// is set on options. Empty option lists (() and RETURN ()) leave all fields
// unset, which RFC 5258 §3 defines as equivalent to specifying no options.
func hasListOptions(options *imap.ListOptions) bool {
	if options == nil {
		return false
	}
	return options.SelectSubscribed || options.SelectRemote ||
		options.SelectRecursiveMatch || options.SelectSpecialUse ||
		options.ReturnSubscribed || options.ReturnChildren ||
		options.ReturnSpecialUse || options.ReturnStatus != nil ||
		options.ReturnMetadata != nil
}

// listEntryWantsStatus reports whether LIST ... RETURN (STATUS (...)) should
// emit a STATUS response for data. RFC 5819 §2 and RFC 9051 §6.3.9.2 require:
//   - no STATUS response for mailboxes listed with \Noselect or \NonExistent;
//   - STATUS responses only for mailboxes that themselves match the selection
//     options (excluding unsubscribed parents returned solely via RECURSIVEMATCH).
//
// A mailbox matches the SUBSCRIBED selection when it is listed \Subscribed, which
// it is when the database matched a subscription to it (DBMailbox.Subscribed).
func listEntryWantsStatus(data *imap.ListData, options *imap.ListOptions) bool {
	if data == nil || data.Mailbox == "" {
		return false
	}
	subscribed := false
	for _, attr := range data.Attrs {
		if strings.EqualFold(string(attr), string(imap.MailboxAttrNoSelect)) ||
			strings.EqualFold(string(attr), string(imap.MailboxAttrNonExistent)) {
			return false
		}
		if strings.EqualFold(string(attr), string(imap.MailboxAttrSubscribed)) {
			subscribed = true
		}
	}
	return options == nil || !options.SelectSubscribed || subscribed
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

// hasDescendant reports whether any key of names is a proper descendant of key
// (i.e. lives under "key<delim>…"). The keys are names as the database keys them,
// LOWER(name), never a Go case mapping of a name.
func hasDescendant[V any](key, delim string, names map[string]V) bool {
	prefix := key + delim
	for s := range names {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// visibleSuperiors returns the key of every name that one of mboxes is below, i.e.
// the names that have a child the user can see. RFC 5258 §4 defines the child
// attributes by what the user can access: \HasNoChildren "indicates that the mailbox
// has NO child mailboxes that are accessible to the currently authenticated user",
// and "A server SHOULD NOT set [\HasChildren] if there are child mailboxes and the
// user does not have permission to access any of them." So LIST takes them from the
// mailboxes GetMailboxes returned (everything the user can look up), not from the
// database's has_children, which looks at the owner's own hierarchy only: it missed
// another owner's shared mailbox below the user's own shared namespace root, and
// counted a shared child the user cannot look up. NOTIFY derives them the same way
// (diffNotifySnapshots). Each mailbox walks only its own ancestors, so this is linear
// in the number of mailboxes.
func visibleSuperiors(mboxes []*db.DBMailbox) map[string]bool {
	superiors := make(map[string]bool)
	for _, m := range mboxes {
		// lower() leaves the delimiter alone, so the key has the name's levels.
		for i := strings.LastIndexByte(m.NameKey, consts.MailboxDelimiter); i > 0 && !superiors[m.NameKey[:i]]; i = strings.LastIndexByte(m.NameKey[:i], consts.MailboxDelimiter) {
			superiors[m.NameKey[:i]] = true
		}
	}
	return superiors
}

// childAttr is the RFC 5258 §4 child attribute for a mailbox name.
func childAttr(hasChildren bool) imap.MailboxAttr {
	if hasChildren {
		return imap.MailboxAttrHasChildren
	}
	return imap.MailboxAttrHasNoChildren
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
// Names are matched as the database matches them, by LOWER(name) under its
// collation: mboxes carry it as NameKey, and subscribed maps it to the stored
// spelling of each subscribed name (GetSubscribedMailboxNamesByKey). A Go case
// mapping would part ways with it, e.g. strings.ToLower("İx") is "ix" while ICU's
// lower() keeps the two names apart.
func buildSubscribedList(ref string, patterns []string, options *imap.ListOptions,
	mboxes []*db.DBMailbox, superiors map[string]bool, subscribed map[string]string,
	serverCaps imap.CapSet, sharedNamespaceRoot string) []imap.ListData {

	recursive := options.SelectRecursiveMatch
	delim := string(consts.MailboxDelimiter)

	liveByKey := make(map[string]*db.DBMailbox, len(mboxes))
	for _, m := range mboxes {
		liveByKey[m.NameKey] = m
	}

	// Candidate universe, keyed by LOWER(name) -> display spelling: live
	// mailboxes, subscribed names, and — for RECURSIVEMATCH — the ancestors of
	// every subscribed name (so a non-existent parent of a subscribed child can
	// still be reported with CHILDINFO).
	candidates := make(map[string]string, len(mboxes)+len(subscribed))
	for _, m := range mboxes {
		candidates[m.NameKey] = m.Name
	}
	for key, name := range subscribed {
		if _, ok := candidates[key]; !ok {
			candidates[key] = name
		}
	}
	if recursive {
		// An ancestor's key is the leading levels of the subscribed name's key:
		// lower() leaves the hierarchy delimiter alone, as the database relies on
		// when it matches descendants by LOWER(name) LIKE LOWER(prefix) || '%'.
		for key, name := range subscribed {
			keyParts := strings.Split(key, delim)
			parts := strings.Split(name, delim)
			if len(keyParts) != len(parts) {
				continue
			}
			for i := 1; i < len(parts); i++ {
				ancKey := strings.Join(keyParts[:i], delim)
				if _, ok := candidates[ancKey]; !ok {
					candidates[ancKey] = strings.Join(parts[:i], delim)
				}
			}
		}
	}

	var l []imap.ListData
	for key, name := range candidates {
		if !matchesAnyPattern(name, ref, patterns) {
			continue
		}
		_, isSub := subscribed[key]
		hasSubChild := recursive && hasDescendant(key, delim, subscribed)
		if !isSub && !hasSubChild {
			continue // not subscribed and no subscribed descendant → not in SUBSCRIBED response
		}

		var data imap.ListData
		if m, ok := liveByKey[key]; ok {
			md := listMailbox(m, superiors[key], options, serverCaps, sharedNamespaceRoot)
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
			// RFC 5258 §4: "If the CHILDREN return option is present, the server
			// MUST return these attributes". A name without a mailbox has
			// children when a visible mailbox lives under it, e.g. a shared
			// mailbox whose parent the user cannot see (§3.5: "\NonExistent
			// \HasChildren").
			if options.ReturnChildren {
				data.Attrs = append(data.Attrs, childAttr(superiors[key]))
			}
		}

		if hasSubChild {
			data.ChildInfo = &imap.ListDataChildInfo{Subscribed: true}
		}
		l = append(l, data)
	}
	return l
}

func listMailbox(mbox *db.DBMailbox, hasChildren bool, options *imap.ListOptions, serverCaps imap.CapSet, sharedNamespaceRoot string) *imap.ListData {
	attributes := []imap.MailboxAttr{}

	// Add \Noselect for the shared-namespace root (e.g. "Shared" for prefix
	// "Shared/", or the configured namespace_prefix). This prevents clients from
	// trying to SELECT the namespace prefix itself (which SELECT always refuses
	// with NO [CANNOT], even when no child mailboxes currently remain under it).
	// sharedNamespaceRoot is empty when shared mailboxes are disabled, so a
	// personal folder that happens to be named like the prefix is not falsely
	// marked \Noselect.
	if isSharedNamespaceRoot(mbox.Name, sharedNamespaceRoot) {
		attributes = append(attributes, imap.MailboxAttrNoSelect)
	}

	// RFC 5258 §4: "If the CHILDREN return option is present, the server MUST
	// return these attributes even if their computation is expensive." The
	// option belongs to LIST-EXTENDED, which stays advertised when CHILDREN is
	// disabled; without it a disabled CHILDREN keeps them off.
	if serverCaps.Has(imap.CapChildren) || options.ReturnChildren {
		attributes = append(attributes, childAttr(hasChildren))
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
