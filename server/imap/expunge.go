package imap

import (
	"context"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

func (s *IMAPSession) Expunge(w *imapserver.ExpungeWriter, uidSet *imap.UIDSet) error {
	ctx := context.Background()

	// Fetch the list of messages marked as \Deleted in the selected mailbox
	messages, err := s.server.db.GetMessagesByFlag(ctx, s.mailbox.ID, imap.FlagDeleted)
	if err != nil {
		return s.internalError("failed to fetch deleted messages: %v", err)
	}

	// If an UIDSet is provided, filter the messages to match the UIDs
	var expungeIDs []imap.UID
	if uidSet != nil {
		for _, msg := range messages {
			if uidSet.Contains(msg.UID) {
				expungeIDs = append(expungeIDs, msg.UID)
			}
		}
	} else {
		for _, msg := range messages {
			expungeIDs = append(expungeIDs, msg.UID)
		}
	}

	// Perform the actual expunge operation
	err = s.server.db.ExpungeMessageUIDs(ctx, s.mailbox.ID, expungeIDs...)
	if err != nil {
		return s.internalError("failed to expunge messages: %v", err)
	}

	s.Log("Expunged %d messages", len(expungeIDs))
	return nil
}
