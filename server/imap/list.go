package imap

import (
	"sort"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

func (s *IMAPSession) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if len(patterns) == 0 {
		return w.WriteList(&imap.ListData{
			Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect},
			Delim: consts.MailboxDelimiter,
		})
	}

	mboxes, err := s.server.db.GetMailboxes(s.ctx, s.UserID(), options.SelectSubscribed)
	if err != nil {
		return s.internalError("failed to fetch mailboxes: %v", err)
	}

	var l []imap.ListData
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

		data := listMailbox(mbox, options, s.server.caps)
		if data != nil {
			if options.ReturnStatus != nil && data.Mailbox != "" && s.server.caps.Has(imap.CapListStatus) {
				statusData, err := s.Status(data.Mailbox, options.ReturnStatus)
				if err == nil && statusData != nil {
					data.Status = statusData
					s.Log("[LIST-STATUS] Mailbox '%s': NumMessages=%v, UIDNext=%v, UIDValidity=%v, NumUnseen=%v, HighestModSeq=%v",
						data.Mailbox,
						statusData.NumMessages,
						statusData.UIDNext,
						statusData.UIDValidity,
						statusData.NumUnseen,
						statusData.HighestModSeq)
				} else {
					s.Log("[LIST-STATUS] Failed to get status for mailbox '%s': %v", data.Mailbox, err)
				}
			}

			l = append(l, *data)
		}
	}

	sort.Slice(l, func(i, j int) bool {
		return l[i].Mailbox < l[j].Mailbox
	})

	for _, data := range l {
		if err := w.WriteList(&data); err != nil {
			return err
		}
	}
	return nil
}

func listMailbox(mbox *db.DBMailbox, options *imap.ListOptions, serverCaps imap.CapSet) *imap.ListData {
	if options.SelectSubscribed && !mbox.Subscribed {
		return nil
	}

	attributes := []imap.MailboxAttr{}

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
