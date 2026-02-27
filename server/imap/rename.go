package imap

import (
	"errors"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

func (s *IMAPSession) Rename(existingName, newName string, options *imap.RenameOptions) error {
	// First phase: Read validation with read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.DebugLog("failed to acquire read lock")
		return s.internalError("failed to acquire lock for rename")
	}
	AccountID := s.AccountID()
	release()

	if strings.EqualFold(existingName, newName) {
		s.DebugLog("new mailbox name is the same as current one (case-insensitive)", "mailbox", existingName)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAlreadyExists,
			Text: "The new mailbox name is the same as the current one.",
		}
	}

	// Middle phase: Database operations outside lock
	oldMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, AccountID, existingName)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			s.DebugLog("mailbox does not exist", "mailbox", existingName)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", existingName),
			}
		}
		return s.internalError("failed to fetch mailbox '%s': %v", existingName, err)
	}

	// Check ACL permissions - requires 'x' (delete) right on the mailbox being renamed
	hasDeleteRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, oldMailbox.ID, AccountID, 'x')
	if err != nil {
		return s.internalError("failed to check delete permission: %v", err)
	}
	if !hasDeleteRight {
		s.DebugLog("user does not have delete permission on mailbox", "mailbox", existingName)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to rename this mailbox",
		}
	}

	_, err = s.server.rdb.GetMailboxByNameWithRetry(s.ctx, AccountID, newName)
	if err == nil {
		s.DebugLog("mailbox already exists", "mailbox", newName)
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

	// RFC 3501 §6.3.5: Renaming INBOX is special — moves messages to the new
	// mailbox while leaving INBOX intact (empty, same UID validity).
	if strings.EqualFold(existingName, consts.MailboxInbox) {
		// 1. Create the destination mailbox
		err = s.server.rdb.CreateMailboxWithRetry(s.ctx, AccountID, newName, nil)
		if err != nil {
			return s.internalError("failed to create destination mailbox '%s': %v", newName, err)
		}

		// 2. Get the new mailbox ID
		newMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, AccountID, newName)
		if err != nil {
			return s.internalError("failed to get new mailbox '%s': %v", newName, err)
		}

		// 3. Get all message UIDs from INBOX
		inboxMessages, err := s.server.rdb.ListMessagesWithRetry(s.ctx, oldMailbox.ID)
		if err != nil {
			return s.internalError("failed to list INBOX messages: %v", err)
		}

		if len(inboxMessages) > 0 {
			uids := make([]imap.UID, len(inboxMessages))
			for i, msg := range inboxMessages {
				uids[i] = msg.UID
			}

			// 4. Move all messages from INBOX to the new mailbox
			_, err = s.server.rdb.MoveMessagesWithRetry(s.ctx, &uids, oldMailbox.ID, newMailbox.ID, AccountID)
		}
		if err != nil {
			return s.internalError("failed to move messages from INBOX to '%s': %v", newName, err)
		}

		s.DebugLog("INBOX renamed (RFC 3501): messages moved to new mailbox, INBOX preserved empty",
			"new_name", newName)
		return nil
	}

	// Determine the new parent mailbox ID
	// Use the owner's AccountID for shared mailbox support
	ownerAccountID := oldMailbox.AccountID
	var newParentMailboxID *int64
	newParts := strings.Split(newName, string(consts.MailboxDelimiter))
	if len(newParts) > 1 {
		newParentPath := strings.Join(newParts[:len(newParts)-1], string(consts.MailboxDelimiter))
		newParentMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, ownerAccountID, newParentPath)
		if err == consts.ErrMailboxNotFound {
			// Parent does not exist, so we need to create it.
			// This is a common expectation for IMAP clients.
			s.DebugLog("new parent mailbox does not exist, auto-creating", "parent", newParentPath, "target", newName)
			createErr := s.server.rdb.CreateMailboxWithRetry(s.ctx, ownerAccountID, newParentPath, nil)
			if createErr != nil {
				// Handle race condition: another session may have created the parent concurrently
				if errors.Is(createErr, consts.ErrDBUniqueViolation) {
					s.DebugLog("parent mailbox already exists (concurrent create)", "parent", newParentPath)
				} else {
					return s.internalError("failed to auto-create new parent mailbox '%s': %v", newParentPath, createErr)
				}
			}
			// Fetch the newly created parent to get its ID.
			newParentMailbox, err = s.server.rdb.GetMailboxByNameWithRetry(s.ctx, ownerAccountID, newParentPath)
			if err != nil {
				return s.internalError("failed to fetch auto-created new parent mailbox '%s': %v", newParentPath, err)
			}
		} else if err != nil {
			return s.internalError("failed to fetch new parent mailbox '%s': %v", newParentPath, err)
		}
		newParentMailboxID = &newParentMailbox.ID
	}
	// If len(newParts) <= 1, newParentMailboxID remains nil, which is correct for a top-level mailbox.

	// Rename using the mailbox owner's AccountID
	err = s.server.rdb.RenameMailboxWithRetry(s.ctx, oldMailbox.ID, ownerAccountID, newName, newParentMailboxID)
	if err != nil {
		return s.internalError("failed to rename mailbox '%s' to '%s': %v", existingName, newName, err)
	}

	s.DebugLog("mailbox renamed", "old_name", existingName, "new_name", newName)
	return nil
}
