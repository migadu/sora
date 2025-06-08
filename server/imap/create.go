package imap

import (
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

// Create a new mailbox
func (s *IMAPSession) Create(name string, options *imap.CreateOptions) error {
	// First phase: validation and mailbox lookup using read lock
	s.mutex.RLock()
	userID := s.UserID()
	s.mutex.RUnlock()

	// Split the mailbox name by the delimiter to check if it's nested
	parts := strings.Split(name, string(consts.MailboxDelimiter))

	var parentMailboxID *int64

	// Check if this is a nested mailbox (i.e., it has a parent)
	if len(parts) > 1 {
		_, err := s.server.db.GetMailboxByName(s.ctx, userID, name)
		if err == nil {
			s.Log("[CREATE] mailbox '%s' already exists", name)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeAlreadyExists,
				Text: "Mailbox already exists",
			}
		}

		// Fetch the parent mailbox, if it exists
		parentPathComponents := parts[:len(parts)-1]
		parentPath := strings.Join(parentPathComponents, string(consts.MailboxDelimiter))

		parentMailbox, err := s.server.db.GetMailboxByName(s.ctx, userID, parentPath)
		if err != nil {
			if err == consts.ErrMailboxNotFound {
				s.Log("[CREATE] parent mailbox '%s' does not exist", parentPath)
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeNonExistent,
					Text: fmt.Sprintf("parent mailbox '%s' does not exist", parentPath),
				}
			}
			return s.internalError("failed to fetch parent mailbox '%s': %v", parentPath, err)
		}
		if parentMailbox != nil {
			parentMailboxID = &parentMailbox.ID
		}
	}

	// Final phase: actual creation - no locks needed as it's a DB operation
	err := s.server.db.CreateMailbox(s.ctx, userID, name, parentMailboxID)
	if err != nil {
		return s.internalError("failed to create mailbox '%s': %v", name, err)
	}

	s.Log("[CREATE] mailbox created: %s", name)
	return nil
}
