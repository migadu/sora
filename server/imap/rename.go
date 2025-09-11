package imap

import (
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Rename(existingName, newName string, options *imap.RenameOptions) error {
	// First phase: Read validation with read lock
	s.mutex.RLock()
	userID := s.UserID()
	s.mutex.RUnlock()

	if existingName == newName {
		s.Log("[RENAME] the new mailbox name is the same as the current one.")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAlreadyExists,
			Text: "The new mailbox name is the same as the current one.",
		}
	}

	// Middle phase: Database operations outside lock
	oldMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, userID, existingName)
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

	_, err = s.server.rdb.GetMailboxByNameWithRetry(s.ctx, userID, newName)
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

	// Determine the new parent mailbox ID
	var newParentMailboxID *int64
	newParts := strings.Split(newName, string(consts.MailboxDelimiter))
	if len(newParts) > 1 {
		newParentPath := strings.Join(newParts[:len(newParts)-1], string(consts.MailboxDelimiter))
		newParentMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, userID, newParentPath)
		if err != nil {
			if err == consts.ErrMailboxNotFound {
				s.Log("[RENAME] new parent mailbox '%s' for '%s' does not exist", newParentPath, newName)
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Text: fmt.Sprintf("Cannot rename mailbox to '%s' because parent mailbox '%s' does not exist", newName, newParentPath),
				}
			}
			return s.internalError("failed to fetch new parent mailbox '%s': %v", newParentPath, err)
		}
		newParentMailboxID = &newParentMailbox.ID
	}
	// If len(newParts) <= 1, newParentMailboxID remains nil, which is correct for a top-level mailbox.

	err = s.server.rdb.RenameMailboxWithRetry(s.ctx, oldMailbox.ID, userID, newName, newParentMailboxID)
	if err != nil {
		return s.internalError("failed to rename mailbox '%s' to '%s': %v", existingName, newName, err)
	}

	s.Log("[RENAME] mailbox renamed: %s -> %s", existingName, newName)
	return nil
}
