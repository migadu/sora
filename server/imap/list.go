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

func (s *IMAPSession) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	// If no patterns, just return a simple response without any database operations
	if len(patterns) == 0 {
		return w.WriteList(&imap.ListData{
			Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect},
			Delim: consts.MailboxDelimiter,
		})
	}

	// Create a context that signals to use the master DB if the session is pinned.
	readCtx := s.ctx
	if s.useMasterDB {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
	}

	// Database operations should be done outside of lock
	// For LSUB, we need all mailboxes to find parents of subscribed ones
	mboxes, err := s.server.rdb.GetMailboxesWithRetry(readCtx, s.AccountID(), false)
	if err != nil {
		return s.internalError("failed to fetch mailboxes: %v", err)
	}

	var parentFolders map[string]bool
	if options.SelectSubscribed {
		parentFolders = calculateParentFolders(mboxes)
	}

	var l []imap.ListData
	for _, mbox := range mboxes {
		// Check if mailbox matches any of the patterns
		match := false
		for _, pattern := range patterns {
			if imapserver.MatchList(mbox.Name, consts.MailboxDelimiter, ref, pattern) {
				match = true
				break
			}
		}
		if !match {
			continue
		}

		// For LSUB, only include subscribed mailboxes or their parents
		if options.SelectSubscribed {
			if !mbox.Subscribed && !parentFolders[mbox.Name] {
				continue
			}
		}

		// Determine if the mailbox is a parent folder for LSUB response attributes.
		// A folder is a "parent" if it's being listed as part of an LSUB response
		// because it's an ancestor of a subscribed folder.
		isParentForLsub := false
		if parentFolders != nil {
			isParentForLsub = parentFolders[mbox.Name]
		}

		data := listMailbox(mbox, options, s.GetCapabilities(), isParentForLsub)
		if data != nil {
			l = append(l, *data)
		}
	}

	sort.Slice(l, func(i, j int) bool {
		return l[i].Mailbox < l[j].Mailbox
	})

	hasListStatusCap := s.GetCapabilities().Has(imap.CapListStatus)

	// Now handle STATUS returns if needed - after we've processed all mailboxes
	// This avoids the deadlock when Status() tries to acquire a write lock
	if options.ReturnStatus != nil && hasListStatusCap {
		// Process STATUS returns in a separate loop to avoid lock contention
		for i := range l {
			data := &l[i]
			if data.Mailbox != "" {
				statusData, err := s.Status(data.Mailbox, options.ReturnStatus)
				if err == nil && statusData != nil {
					data.Status = statusData

					numMessagesStr := "n/a"
					if statusData.NumMessages != nil {
						numMessagesStr = fmt.Sprint(*statusData.NumMessages)
					}
					numUnseenStr := "n/a"
					if statusData.NumUnseen != nil {
						numUnseenStr = fmt.Sprint(*statusData.NumUnseen)
					}

					s.InfoLog("[LIST-STATUS] Mailbox '%s': NumMessages=%s, UIDNext=%v, UIDValidity=%v, NumUnseen=%s, HighestModSeq=%v",
						data.Mailbox,
						numMessagesStr,
						statusData.UIDNext,
						statusData.UIDValidity,
						numUnseenStr,
						statusData.HighestModSeq)
				} else {
					s.InfoLog("[LIST-STATUS] Failed to get status for mailbox '%s': %v", data.Mailbox, err) // err can be nil if statusData is nil
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

// calculateParentFolders finds all parent folders of subscribed mailboxes.
// This is used for LSUB command to include non-subscribed parent mailboxes
// in the response, marking them as \Noselect.
func calculateParentFolders(mboxes []*db.DBMailbox) map[string]bool {
	subscribedMailboxes := make(map[string]bool)
	for _, mbox := range mboxes {
		if mbox.Subscribed {
			subscribedMailboxes[mbox.Name] = true
		}
	}

	parentFolders := make(map[string]bool)
	for subscribedName := range subscribedMailboxes {
		parts := strings.Split(subscribedName, string(consts.MailboxDelimiter))
		// Add all parent paths (e.g., for "A/B/C", add "A" and "A/B")
		for i := 1; i < len(parts); i++ {
			parentPath := strings.Join(parts[:i], string(consts.MailboxDelimiter))
			if parentPath != "" {
				parentFolders[parentPath] = true
			}
		}
	}
	return parentFolders
}

func listMailbox(mbox *db.DBMailbox, options *imap.ListOptions, serverCaps imap.CapSet, isParentFolder bool) *imap.ListData {
	attributes := []imap.MailboxAttr{}

	// Add \noselect for parent folders that aren't directly subscribed
	if isParentFolder && !mbox.Subscribed {
		attributes = append(attributes, imap.MailboxAttrNoSelect)
	}

	// Add \noselect for shared namespace root (e.g., "Shared" for prefix "Shared/")
	// This prevents clients from trying to SELECT the namespace prefix itself
	if mbox.Name == "Shared" && mbox.HasChildren {
		attributes = append(attributes, imap.MailboxAttrNoSelect)
	}

	if serverCaps.Has(imap.CapChildren) {
		if mbox.HasChildren {
			attributes = append(attributes, imap.MailboxAttrHasChildren)
		} else {
			attributes = append(attributes, imap.MailboxAttrHasNoChildren)
		}
	}

	isStandardSpecialMailbox := false
	var specialUseAttributeIfApplicable imap.MailboxAttr
	switch strings.ToUpper(mbox.Name) {
	case "SENT":
		isStandardSpecialMailbox = true
		specialUseAttributeIfApplicable = imap.MailboxAttrSent
	case "TRASH":
		isStandardSpecialMailbox = true
		specialUseAttributeIfApplicable = imap.MailboxAttrTrash
	case "DRAFTS":
		isStandardSpecialMailbox = true
		specialUseAttributeIfApplicable = imap.MailboxAttrDrafts
	case "ARCHIVE":
		isStandardSpecialMailbox = true
		specialUseAttributeIfApplicable = imap.MailboxAttrArchive
	case "JUNK":
		isStandardSpecialMailbox = true
		specialUseAttributeIfApplicable = imap.MailboxAttrJunk
	}

	// Default mailboxes should always be visible to IMAP clients, regardless of special-use flags
	// Only filter out special-use mailboxes if the client specifically requests filtering

	if options.SelectSpecialUse && !isStandardSpecialMailbox {
		return nil
	}

	if isStandardSpecialMailbox {
		if serverCaps.Has(imap.CapSpecialUse) || options.ReturnSpecialUse || options.SelectSpecialUse {
			attributes = append(attributes, specialUseAttributeIfApplicable)
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
