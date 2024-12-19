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

	var ids []uint32
	for _, msg := range messages {
		ids = append(ids, uint32(msg.ID)) // Collect the message IDs (UIDs)
	}

	searchData := &imap.SearchData{
		All:   imap.SeqSetNum(ids...),           // Initialize the NumSet with the collected IDs
		UID:   numKind == imapserver.NumKindUID, // Set UID flag if searching by UID
		Count: uint32(len(ids)),                 // Set the count of matching messages
	}

	searchData.Count = uint32(len(messages))

	return searchData, nil
}
