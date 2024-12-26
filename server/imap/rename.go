package imap

import (
	"context"
	"fmt"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Rename(existingName, newName string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if existingName == newName {
		s.Log("The new mailbox name is the same as the current one.")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAlreadyExists,
			Text: "The new mailbox name is the same as the current one.",
		}
	}

	ctx := context.Background()

	oldMailbox, err := s.server.db.GetMailboxByName(ctx, s.UserID(), existingName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.Log("Mailbox '%s' does not exist", existingName)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", existingName),
			}
		}
		return s.internalError("failed to fetch mailbox '%s': %v", existingName, err)
	}

	// Check if the new mailbox name already exists
	_, err = s.server.db.GetMailboxByName(ctx, s.UserID(), newName)
	if err == nil {
		s.Log("Mailbox '%s' already exists", newName)
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

	// Perform the rename operation
	err = s.server.db.RenameMailbox(ctx, oldMailbox.ID, s.UserID(), newName)
	if err != nil {
		return s.internalError("failed to rename mailbox '%s' to '%s': %v", existingName, newName, err)
	}

	s.Log("Mailbox renamed: %s -> %s", existingName, newName)
	return nil
}
