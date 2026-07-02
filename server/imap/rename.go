package imap

import (
	"errors"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
)

func (s *IMAPSession) Rename(w *imapserver.RenameWriter, existingName, newName string, options *imap.RenameOptions) error {
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

	// Reject path-traversal segments ("." / "..") in the destination with a
	// clean client error (db.RenameMailbox enforces this too, as defence-in-depth
	// for non-IMAP callers).
	if helpers.MailboxNameHasTraversal(newName) {
		s.DebugLog("rejecting rename to name with path traversal segment", "name", newName)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeCannot,
			Text: "Invalid mailbox name",
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
		// Resolve (auto-creating if needed) the destination's parent hierarchy so
		// a hierarchical target like "Archive/2026" is linked under "Archive",
		// consistent with CREATE and the non-INBOX RENAME path. INBOX is the
		// user's own mailbox, so owner == acting account here.
		var destParentID *int64
		newParts := strings.Split(newName, string(consts.MailboxDelimiter))
		if len(newParts) > 1 {
			newParentPath := strings.Join(newParts[:len(newParts)-1], string(consts.MailboxDelimiter))
			if permErr := s.checkCreateRightForHierarchy(newParentPath, AccountID, AccountID); permErr != nil {
				return permErr
			}
			parentID, perr := s.resolveOrCreateParentPath(newParentPath, AccountID)
			if perr != nil {
				return perr
			}
			destParentID = parentID
		}

		// 1. Create the destination mailbox, linked to its parent.
		err = s.server.rdb.CreateMailboxWithRetry(s.ctx, AccountID, newName, destParentID)
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

			// 4. Move all messages from INBOX to the new mailbox. This is a
			// same-account move, so the S3 owner is the account itself; resolve it
			// rather than swallowing the error (an empty domain/localpart would
			// corrupt the moved messages' S3 paths).
			domain, localpart, resolveErr := s.server.rdb.ResolveAccountS3Owner(s.ctx, AccountID)
			if resolveErr != nil {
				return s.internalError("failed to resolve S3 owner for INBOX rename: %v", resolveErr)
			}
			_, err = s.server.rdb.MoveMessagesWithRetry(s.ctx, &uids, oldMailbox.ID, newMailbox.ID, AccountID, domain, localpart, s.server.hostname)
		}
		if err != nil {
			return s.internalError("failed to move messages from INBOX to '%s': %v", newName, err)
		}

		s.DebugLog("INBOX renamed (RFC 3501): messages moved to new mailbox, INBOX preserved empty",
			"new_name", newName)
		s.useMasterDB.Store(true) // Pin session to master DB for read-your-writes consistency

		// RFC 9051 §6.3.6: RENAME INBOX is still a RENAME as far as the client is
		// concerned — the SHOULD-send-OLDNAME applies so a rev2 client learns where
		// the old INBOX contents now live (a fresh empty INBOX is left behind).
		s.writeRenameOldName(w, existingName, newName)
		return nil
	}

	// Determine the new parent mailbox ID
	// Use the owner's AccountID for shared mailbox support
	ownerAccountID := oldMailbox.AccountID
	var newParentMailboxID *int64
	newParts := strings.Split(newName, string(consts.MailboxDelimiter))
	if len(newParts) > 1 {
		newParentPath := strings.Join(newParts[:len(newParts)-1], string(consts.MailboxDelimiter))

		// RFC 4314 §4: moving a mailbox to a DIFFERENT parent requires the "k"
		// (create) right on the new parent — or, when the new parent must be
		// auto-created, on the nearest existing ancestor that CREATE would extend.
		// A pure rename that keeps the same parent needs no "k". (Owners hold "k".)
		oldParts := strings.Split(existingName, string(consts.MailboxDelimiter))
		oldParentPath := strings.Join(oldParts[:len(oldParts)-1], string(consts.MailboxDelimiter))
		if !strings.EqualFold(oldParentPath, newParentPath) {
			if permErr := s.checkCreateRightForHierarchy(newParentPath, ownerAccountID, AccountID); permErr != nil {
				return permErr
			}
		}

		parentID, perr := s.resolveOrCreateParentPath(newParentPath, ownerAccountID)
		if perr != nil {
			return perr
		}
		newParentMailboxID = parentID
	}
	// If len(newParts) <= 1, newParentMailboxID remains nil, which is correct for a top-level mailbox.

	// Rename using the mailbox owner's AccountID
	err = s.server.rdb.RenameMailboxWithRetry(s.ctx, oldMailbox.ID, ownerAccountID, newName, newParentMailboxID)
	if err != nil {
		return s.internalError("failed to rename mailbox '%s' to '%s': %v", existingName, newName, err)
	}

	s.DebugLog("mailbox renamed", "old_name", existingName, "new_name", newName)
	s.useMasterDB.Store(true) // Pin session to master DB for read-your-writes consistency

	// RFC 9051 §6.3.6: announce the new name to IMAP4rev2 clients via an untagged
	// LIST carrying the OLDNAME data item, before the tagged OK.
	s.writeRenameOldName(w, existingName, newName)
	return nil
}

// writeRenameOldName sends the RFC 9051 §6.3.6 OLDNAME notification for a
// successful RENAME: `* LIST () "<delim>" newName ("OLDNAME" (oldName))`.
// WriteOldName is itself a no-op for non-IMAP4rev2 sessions. The rename is
// already committed by the time we get here, so a failed write (typically a dead
// connection) is logged rather than surfaced as a command error — returning NO
// for a rename that actually happened would desync the client.
func (s *IMAPSession) writeRenameOldName(w *imapserver.RenameWriter, oldName, newName string) {
	if err := w.WriteOldName(&imap.ListData{
		Mailbox: newName,
		Delim:   consts.MailboxDelimiter,
		OldName: oldName,
	}); err != nil {
		s.WarnLog("failed to write OLDNAME LIST response after RENAME",
			"old_name", oldName, "new_name", newName, "error", err)
	}
}

// resolveOrCreateParentPath returns the mailbox ID of newParentPath, auto-creating
// it if it does not exist (a common IMAP-client expectation, matching CREATE).
// Shared by the INBOX-rename and regular-rename destination-parent resolution so
// both link a hierarchical target under its parent rather than storing a flat name.
func (s *IMAPSession) resolveOrCreateParentPath(newParentPath string, ownerAccountID int64) (*int64, error) {
	newParentMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, ownerAccountID, newParentPath)
	if err == consts.ErrMailboxNotFound {
		s.DebugLog("new parent mailbox does not exist, auto-creating", "parent", newParentPath)
		createErr := s.server.rdb.CreateMailboxWithRetry(s.ctx, ownerAccountID, newParentPath, nil)
		if createErr != nil {
			// Handle race condition: another session may have created the parent concurrently.
			if errors.Is(createErr, consts.ErrDBUniqueViolation) {
				s.DebugLog("parent mailbox already exists (concurrent create)", "parent", newParentPath)
			} else {
				return nil, s.internalError("failed to auto-create new parent mailbox '%s': %v", newParentPath, createErr)
			}
		}
		// Fetch the newly created parent to get its ID.
		newParentMailbox, err = s.server.rdb.GetMailboxByNameWithRetry(s.ctx, ownerAccountID, newParentPath)
		if err != nil {
			return nil, s.internalError("failed to fetch auto-created new parent mailbox '%s': %v", newParentPath, err)
		}
	} else if err != nil {
		return nil, s.internalError("failed to fetch new parent mailbox '%s': %v", newParentPath, err)
	}
	return &newParentMailbox.ID, nil
}

// checkCreateRightForHierarchy verifies the acting user holds the "k" (create)
// right on the nearest existing ancestor of newParentPath — the mailbox a CREATE
// would extend — per RFC 4314 §4. It returns nil when an existing ancestor grants
// "k", or when no ancestor exists yet (a top-level create in the user's own
// namespace). ownerAccountID owns the hierarchy; accountID is the acting user.
// This covers both an existing destination parent and one that must be auto-created.
func (s *IMAPSession) checkCreateRightForHierarchy(newParentPath string, ownerAccountID, accountID int64) error {
	parts := strings.Split(newParentPath, string(consts.MailboxDelimiter))
	for i := len(parts); i >= 1; i-- {
		ancestorPath := strings.Join(parts[:i], string(consts.MailboxDelimiter))
		ancestor, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, ownerAccountID, ancestorPath)
		if err == consts.ErrMailboxNotFound {
			continue
		}
		if err != nil {
			return s.internalError("failed to resolve ancestor mailbox '%s': %v", ancestorPath, err)
		}
		hasCreateRight, kerr := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, ancestor.ID, accountID, 'k')
		if kerr != nil {
			return s.internalError("failed to check create permission on '%s': %v", ancestorPath, kerr)
		}
		if !hasCreateRight {
			s.DebugLog("user lacks create permission on destination hierarchy", "ancestor", ancestorPath)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNoPerm,
				Text: "You do not have permission to create a mailbox under the destination parent",
			}
		}
		return nil
	}
	return nil
}
