package imap

import (
	"fmt"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Rename(existingName, newName string, options *imap.RenameOptions) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if existingName == newName {
		s.Log("[RENAME] the new mailbox name is the same as the current one.")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAlreadyExists,
			Text: "The new mailbox name is the same as the current one.",
		}
	}

	oldMailbox, err := s.server.db.GetMailboxByName(s.ctx, s.UserID(), existingName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.Log("[RENAME] mailbox '%s' does not exist", existingName)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", existingName),
			}
		}
		return s.internalError("failed to fetch mailbox '%s': %v", existingName, err)
	}

	_, err = s.server.db.GetMailboxByName(s.ctx, s.UserID(), newName)
	if err == nil {
		s.Log("[RENAME] mailbox '%s' already exists", newName)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAlreadyExists,
			Text: fmt.Sprintf("mailbox '%s' already exists", newName),
		}
	} else {
		if err != consts.ErrMailboxNotFound {
			return s.internalError("failed to check if mailbox '%s' already exists: %v", newName, err)
		}
	}

	err = s.server.db.RenameMailbox(s.ctx, oldMailbox.ID, s.UserID(), newName)
	if err != nil {
		return s.internalError("failed to rename mailbox '%s' to '%s': %v", existingName, newName, err)
	}

	s.Log("[RENAME] mailbox renamed: %s -> %s", existingName, newName)
	return nil
}
