package imap

import (
	"context"
	"sort"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/consts"
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
	for _, dbmbox := range mboxes {
		mbox := NewMailbox(dbmbox)
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

		data := mbox.list(options)
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
