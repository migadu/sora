package imap

import (
	"context"
	"sort"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

func (s *IMAPSession) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if len(patterns) == 0 {
		return w.WriteList(&imap.ListData{
			Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect},
			Delim: consts.MailboxDelimiter,
		})
	}

	// Fetch mailboxes, converting them to IMAP mailboxes
	mboxes, err := s.server.db.GetMailboxes(context.Background(), s.UserID(), options.SelectSubscribed)
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

		data := listMailbox(mbox, options)
		if data != nil {
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

func listMailbox(mbox *db.DBMailbox, options *imap.ListOptions) *imap.ListData {
	// Check if the mailbox should be listed
	if options.SelectSubscribed && !mbox.Subscribed {
		return nil
	}

	// Prepare attributes
	attributes := []imap.MailboxAttr{}

	if mbox.HasChildren {
		attributes = append(attributes, imap.MailboxAttrHasChildren)
	} else {
		attributes = append(attributes, imap.MailboxAttrHasNoChildren)
	}

	// Add special attributes
	switch strings.ToUpper(mbox.Name) {
	case "SENT":
		attributes = append(attributes, imap.MailboxAttrSent)
	case "TRASH":
		attributes = append(attributes, imap.MailboxAttrTrash)
	case "DRAFTS":
		attributes = append(attributes, imap.MailboxAttrDrafts)
	case "ARCHIVE":
		attributes = append(attributes, imap.MailboxAttrArchive)
	case "JUNK":
		attributes = append(attributes, imap.MailboxAttrJunk)
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
