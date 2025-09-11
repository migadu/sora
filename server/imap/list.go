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
	mboxes, err := s.server.rdb.GetMailboxesWithRetry(readCtx, s.UserID(), false)
	if err != nil {
		return s.internalError("failed to fetch mailboxes: %v", err)
	}

	var l []imap.ListData

	// For LSUB, we need to include parent folders of subscribed mailboxes
	if options.SelectSubscribed {
		// First, collect all subscribed mailboxes
		subscribedMailboxes := make(map[string]bool)
		for _, mbox := range mboxes {
			if mbox.Subscribed {
				subscribedMailboxes[mbox.Name] = true
			}
		}

		// Then, find all parent folders that should be included
		parentFolders := make(map[string]bool)
		for subscribedName := range subscribedMailboxes {
			parts := strings.Split(subscribedName, string(consts.MailboxDelimiter))
			// Add all parent paths
			for i := 1; i < len(parts); i++ {
				parentPath := strings.Join(parts[:i], string(consts.MailboxDelimiter))
				if parentPath != "" {
					parentFolders[parentPath] = true
					// Also try with trailing delimiter
					parentFolders[parentPath+string(consts.MailboxDelimiter)] = true
				}
			}
		}

		// Process mailboxes for LSUB
		for _, mbox := range mboxes {
			match := false
			for _, pattern := range patterns {
				match = imapserver.MatchList(mbox.Name, consts.MailboxDelimiter, ref, pattern)
				if match {
					break
				}
			}
			if !match {
				continue
			}

			// Include if subscribed or if it's a parent of a subscribed mailbox
			if mbox.Subscribed || parentFolders[mbox.Name] {
				data := listMailbox(mbox, options, s.server.caps, parentFolders[mbox.Name])
				if data != nil {
					l = append(l, *data)
				}
			}
		}
	} else {
		// Regular LIST behavior
		for _, mbox := range mboxes {
			match := false
			for _, pattern := range patterns {
				match = imapserver.MatchList(mbox.Name, consts.MailboxDelimiter, ref, pattern)
				if match {
					break
				}
			}
			if !match {
				continue
			}

			data := listMailbox(mbox, options, s.server.caps, false)
			if data != nil {
				l = append(l, *data)
			}
		}
	}

	sort.Slice(l, func(i, j int) bool {
		return l[i].Mailbox < l[j].Mailbox
	})

	// We only need read locks when accessing server capabilities
	s.mutex.RLock()
	hasListStatusCap := s.server.caps.Has(imap.CapListStatus)
	s.mutex.RUnlock()

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

					s.Log("[LIST-STATUS] Mailbox '%s': NumMessages=%s, UIDNext=%v, UIDValidity=%v, NumUnseen=%s, HighestModSeq=%v",
						data.Mailbox,
						numMessagesStr,
						statusData.UIDNext,
						statusData.UIDValidity,
						numUnseenStr,
						statusData.HighestModSeq)
				} else {
					s.Log("[LIST-STATUS] Failed to get status for mailbox '%s': %v", data.Mailbox, err) // err can be nil if statusData is nil
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

func listMailbox(mbox *db.DBMailbox, options *imap.ListOptions, serverCaps imap.CapSet, isParentFolder bool) *imap.ListData {
	attributes := []imap.MailboxAttr{}

	// Add \noselect for parent folders that aren't directly subscribed
	if isParentFolder && !mbox.Subscribed {
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

	if options.SelectSpecialUse && !isStandardSpecialMailbox {
		return nil
	}

	if isStandardSpecialMailbox {
		addTheAttribute := false
		if serverCaps.Has(imap.CapSpecialUse) {
			addTheAttribute = true
		} else {
			if options.ReturnSpecialUse || options.SelectSpecialUse {
				addTheAttribute = true
			}
		}
		if addTheAttribute {
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
