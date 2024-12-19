package imap

import (
	"context"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/db"
)

func (s *IMAPSession) Poll(w *imapserver.UpdateWriter, b bool) error {
	if s.mailbox == nil {
		// TODO: Why is poll called if no mailbox is selected? E.g. LIST will call poll, why?
		return nil
	}

	ctx := context.Background()
	updates, numMessages, err := s.server.db.GetMailboxUpdates(ctx, s.mailbox.ID, s.mailbox.lastPollAt)
	if err != nil {
		return s.internalError("failed to get mailbox updates: %v", err)
	}

	s.mailbox.numMessages = numMessages

	for _, update := range updates {
		if update.IsExpunge {
			if err := w.WriteExpunge(uint32(update.SeqNum)); err != nil {
				return s.internalError("failed to write expunge update: %v", err)
			}
		} else if update.FlagsChanged {
			if err := w.WriteMessageFlags(uint32(update.SeqNum), imap.UID(update.ID), db.BitwiseToFlags(update.BitwiseFlags)); err != nil {
				return s.internalError("failed to write flag update: %v", err)
			}
		}
	}

	if err := w.WriteNumMessages(uint32(numMessages)); err != nil {
		return s.internalError("failed to write number of messages: %v", err)
	}

	s.mailbox.lastPollAt = time.Now()

	return nil
}
