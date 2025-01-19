package imap

import (
	"context"

	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/db"
)

func (s *IMAPSession) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	if s.mailbox == nil {
		// TODO: Why is poll called if no mailbox is selected? E.g. LIST will call poll, why?
		return nil
	}

	ctx := context.Background()
	poll, err := s.server.db.PollMailbox(ctx, s.mailbox.ID, s.mailbox.highestModSeq)
	if err != nil {
		return s.internalError("failed to poll mailbox: %v", err)
	}

	var numExpunged uint32
	for _, update := range poll.Updates {
		if update.IsExpunge {
			s.mailbox.mboxTracker.QueueExpunge(update.SeqNum)
			numExpunged++
		} else {
			flags := db.BitwiseToFlags(update.BitwiseFlags)
			s.mailbox.mboxTracker.QueueMessageFlags(update.SeqNum, update.UID, flags, nil)
		}
	}

	if s.mailbox.numMessages-numExpunged != poll.NumMessages {
		s.mailbox.mboxTracker.QueueNumMessages(uint32(poll.NumMessages))
	}

	s.mailbox.numMessages = poll.NumMessages
	s.mailbox.highestModSeq = poll.ModSeq

	return s.mailbox.sessionTracker.Poll(w, allowExpunge)
}
