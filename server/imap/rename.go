package imap

import (
	"context"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Rename(existingName, newName string) error {
	if existingName == newName {
		s.Log("The new mailbox name is the same as the current one.")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAlreadyExists,
			Text: "The new mailbox name is the same as the current one.",
		}
	}

	ctx := context.Background()
	// Fetch the old mailbox based on its current name
	oldMailboxPathComponents := strings.Split(existingName, string(consts.MailboxDelimiter))
	oldMailbox, err := s.server.db.GetMailboxByFullPath(ctx, s.UserID(), oldMailboxPathComponents)
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

	// Parse new mailbox path components
	newMailboxPathComponents := strings.Split(newName, string(consts.MailboxDelimiter))
	var newParentPath *string

	// Check if the new mailbox name has a parent
	if len(newMailboxPathComponents) > 1 {
		parentMailboxComponents := newMailboxPathComponents[:len(newMailboxPathComponents)-1]
		newName = newMailboxPathComponents[len(newMailboxPathComponents)-1]

		// Check if the parent mailbox of the new name exists
		_, err = s.server.db.GetMailboxByFullPath(ctx, s.UserID(), parentMailboxComponents)
		if err != nil {
			if err == consts.ErrMailboxNotFound {
				s.Log("Parent mailbox for '%s' does not exist", newName)
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeNonExistent,
					Text: fmt.Sprintf("parent mailbox for '%s' does not exist", newName),
				}
			}
			return s.internalError("failed to check parent mailbox for '%s': %v", newName, err)
		}
		newParentPathStr := JoinMailboxPath(parentMailboxComponents)
		newParentPath = &newParentPathStr
	}

	// Perform the rename operation
	err = s.server.db.RenameMailbox(ctx, oldMailbox.ID, newName, newParentPath)
	if err != nil {
		return s.internalError("failed to rename mailbox '%s' to '%s': %v", existingName, newName, err)
	}

	s.Log("Mailbox renamed: %s -> %s", existingName, newName)
	return nil
}
