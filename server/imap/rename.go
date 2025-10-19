package imap

import (
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Rename(existingName, newName string, options *imap.RenameOptions) error {
	// First phase: Read validation with read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.Log("[RENAME] Failed to acquire read lock")
		return s.internalError("failed to acquire lock for rename")
	}
	userID := s.UserID()
	release()

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

	// Check ACL permissions - requires 'x' (delete) right on the mailbox being renamed
	hasDeleteRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, oldMailbox.ID, userID, 'x')
	if err != nil {
		return s.internalError("failed to check delete permission: %v", err)
	}
	if !hasDeleteRight {
		s.Log("[RENAME] user does not have delete permission on mailbox '%s'", existingName)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to rename this mailbox",
		}
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
		if err == consts.ErrMailboxNotFound {
			// Parent does not exist, so we need to create it.
			// This is a common expectation for IMAP clients.
			s.Log("[RENAME] new parent mailbox '%s' for '%s' does not exist, auto-creating", newParentPath, newName)
			createErr := s.server.rdb.CreateMailboxWithRetry(s.ctx, userID, newParentPath, nil)
			if createErr != nil {
				return s.internalError("failed to auto-create new parent mailbox '%s': %v", newParentPath, createErr)
			}
			// Fetch the newly created parent to get its ID.
			newParentMailbox, err = s.server.rdb.GetMailboxByNameWithRetry(s.ctx, userID, newParentPath)
			if err != nil {
				return s.internalError("failed to fetch auto-created new parent mailbox '%s': %v", newParentPath, err)
			}
		} else if err != nil {
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
