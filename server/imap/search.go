package imap

import (
	"context"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

func (s *IMAPSession) Search(numKind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	ctx := context.Background()

	messages, err := s.server.db.GetMessagesWithCriteria(ctx, s.mailbox.ID, numKind, criteria)
	if err != nil {
		return nil, s.internalError("failed to search messages: %v", err)
	}

	var uids imap.UIDSet
	for _, msg := range messages {
		uids.AddNum(msg.UID) // Collect the message UIDs
	}

	searchData := &imap.SearchData{
		All:   uids,
		UID:   numKind == imapserver.NumKindUID, // Set UID flag if searching by UID
		Count: uint32(len(uids)),                // Set the count of matching messages
	}

	searchData.Count = uint32(len(messages))

	return searchData, nil
}
