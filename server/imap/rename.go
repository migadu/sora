package imap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
)

func (s *IMAPSession) Rename(ctx context.Context, w *imapserver.RenameWriter, existingName, newName string, options *imap.RenameOptions) error {
	// First phase: Read validation with read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		s.DebugLog("failed to acquire read lock")
		return s.internalError("failed to acquire lock for rename")
	}
	AccountID := s.AccountID()
	release()
	// The source, destination hierarchy and ACLs may have been created or
	// changed by an earlier command in this same session.
	if s.useMasterDB.Load() {
		ctx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	}

	// As in CREATE: a parent this RENAME creates inside the shared namespace must be a
	// shared mailbox, which CreateMailbox decides from the config in the context.
	if s.server.config != nil {
		ctx = context.WithValue(ctx, consts.ConfigContextKey, s.server.config)
	}

	// The new name is checked as CREATE checks its name: a trailing delimiter is no
	// part of it (RFC 9051 §6.3.4), and RENAME creates the superior names it needs
	// (§6.3.6), so an empty level ("r//s", "/lead") or a "." / ".." level (maildir
	// export path traversal) is refused before any of them is created.
	// db.RenameMailbox refuses these names too, for non-IMAP callers.
	created, err := helpers.MailboxNameToCreate(newName)
	if err != nil {
		s.DebugLog("rejecting rename to an invalid mailbox name", "name", newName)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeCannot,
			Text: "Invalid mailbox name",
		}
	}
	newName = created

	// Which mailbox a name names is the database's call: it matches names by
	// LOWER(name), which depends on its collation and which no Go case mapping
	// matches ("ſx" and "sx" are two mailboxes; under a libc collation "İNBOX" is
	// the INBOX). So names are not compared here: they are looked up, and the
	// mailboxes found are compared.

	// Middle phase: Database operations outside lock
	oldMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(ctx, AccountID, existingName)
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
	// RFC 3501 §6.3.5: renaming INBOX is special. The mailbox found is the INBOX when
	// its stored name is INBOX in any case; strings.EqualFold folds no non-ASCII
	// letter onto the letters of INBOX.
	isInbox := strings.EqualFold(oldMailbox.Name, consts.MailboxInbox)

	// Whether a mailbox is shared is settled when it is created in or outside the
	// shared namespace, so a RENAME never crosses it (issue #160). Checked before any
	// parent of the new name is created, and against the stored flag as
	// db.RenameMailbox does: a personal mailbox can sit under the shared prefix, and
	// may only be renamed out of it. The rename carries the mailbox's descendants
	// along, and each must stay on its side as well (issue #1229). RENAME INBOX moves
	// the messages of the personal INBOX into a new mailbox and leaves the children
	// in place, so only the new name counts there.
	if s.server.config != nil && s.server.config.SharedMailboxes.Enabled {
		crosses := s.server.config.SharedMailboxes.InNamespace(newName)
		if !isInbox {
			var sharedErr error
			crosses, sharedErr = s.server.rdb.RenameCrossesSharedBoundaryWithRetry(ctx, s.server.config.SharedMailboxes, oldMailbox, newName)
			if sharedErr != nil {
				return s.internalError("failed to check mailbox '%s' against the shared namespace: %v", existingName, sharedErr)
			}
		}
		if crosses {
			s.DebugLog("rejecting rename across the shared namespace boundary", "old_name", existingName, "new_name", newName)
			return sharedBoundaryError()
		}
	}

	// A mailbox cannot become its own descendant. Refused before the missing levels
	// of the new name are created, which would be below this mailbox. (RENAME INBOX
	// moves messages into a new mailbox instead, which may be below INBOX.)
	if !isInbox {
		below, belowErr := s.server.rdb.MailboxNameIsBelowWithRetry(ctx, newName, oldMailbox)
		if belowErr != nil {
			return s.internalError("failed to check whether '%s' is below '%s': %v", newName, existingName, belowErr)
		}
		if below {
			s.DebugLog("rejecting rename of a mailbox below itself", "old_name", existingName, "new_name", newName)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeCannot,
				Text: "A mailbox cannot be renamed to a name below itself",
			}
		}
	}

	// Check ACL permissions - requires 'x' (delete) right on the mailbox being renamed
	hasDeleteRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(ctx, oldMailbox.ID, AccountID, 'x')
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

	// The new name must name no mailbox, this one included.
	existing, err := s.server.rdb.GetMailboxByNameWithRetry(ctx, AccountID, newName)
	if err == nil {
		text := fmt.Sprintf("mailbox '%s' already exists", newName)
		if existing.ID == oldMailbox.ID {
			text = "The new mailbox name is the same as the current one."
		}
		s.DebugLog("mailbox already exists", "mailbox", newName, "same_mailbox", existing.ID == oldMailbox.ID)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAlreadyExists,
			Text: text,
		}
	} else {
		if err != consts.ErrMailboxNotFound {
			return s.internalError("failed to check if mailbox '%s' already exists: %v", newName, err)
		}
	}

	// RFC 3501 §6.3.5: Renaming INBOX is special — moves messages to the new
	// mailbox while leaving INBOX intact (empty, same UID validity).
	if isInbox {
		// Resolve (auto-creating if needed) the destination's parent hierarchy so
		// a hierarchical target like "Archive/2026" is linked under "Archive",
		// consistent with CREATE and the non-INBOX RENAME path. INBOX is the
		// user's own mailbox, so owner == acting account here.
		var destParentID *int64
		newParts := strings.Split(newName, string(consts.MailboxDelimiter))
		if len(newParts) > 1 {
			newParentPath := strings.Join(newParts[:len(newParts)-1], string(consts.MailboxDelimiter))
			if refusal := s.foreignParentRefusal(ctx, newParentPath, AccountID, AccountID); refusal != nil {
				return refusal
			}
			if permErr := s.checkCreateRightForHierarchy(ctx, newParentPath, AccountID, AccountID); permErr != nil {
				return permErr
			}
			parentID, perr := s.resolveOrCreateParentPath(ctx, newParentPath, AccountID)
			if perr != nil {
				return perr
			}
			destParentID = parentID
		}

		// 1. Create the destination mailbox, linked to its parent.
		err = s.server.rdb.CreateMailboxWithRetry(ctx, AccountID, newName, destParentID)
		if err != nil {
			return s.internalError("failed to create destination mailbox '%s': %v", newName, err)
		}

		// 2. Get the new mailbox ID
		newMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(ctx, AccountID, newName)
		if err != nil {
			return s.internalError("failed to get new mailbox '%s': %v", newName, err)
		}

		// 3. Get all message UIDs from INBOX
		inboxMessages, err := s.server.rdb.ListMessagesWithRetry(ctx, oldMailbox.ID)
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
			domain, localpart, resolveErr := s.server.rdb.ResolveAccountS3Owner(ctx, AccountID)
			if resolveErr != nil {
				return s.internalError("failed to resolve S3 owner for INBOX rename: %v", resolveErr)
			}
			_, err = s.server.rdb.MoveMessagesWithRetry(ctx, &uids, oldMailbox.ID, newMailbox.ID, AccountID, domain, localpart, s.server.instanceID, nil, nil, nil)
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

	var newParentPath string
	newParts := strings.Split(newName, string(consts.MailboxDelimiter))
	if len(newParts) > 1 {
		newParentPath = strings.Join(newParts[:len(newParts)-1], string(consts.MailboxDelimiter))

		// A mailbox stays with its owner, so it cannot move into another owner's
		// shared mailbox, whatever rights anyone holds there. That can never succeed
		// and is refused first: neither allow_user_create nor the "k" right, checked
		// below, has a say in it.
		if refusal := s.foreignParentRefusal(ctx, newParentPath, ownerAccountID, AccountID); refusal != nil {
			return refusal
		}
	}

	// With allow_user_create off, RENAME must not make a top-level shared mailbox
	// out of one inside an existing shared mailbox: that is creating one. Renaming
	// what already is a top-level shared mailbox adds none. Only the owner's own
	// shared mailboxes count as existing ones: the mailbox cannot be in another's.
	newRoot, rootErr := s.isRefusedSharedRoot(ctx, ownerAccountID, newName, true)
	if rootErr != nil {
		return rootErr
	}
	if newRoot {
		oldRoot, rootErr := s.isRefusedSharedRoot(ctx, ownerAccountID, existingName, true)
		if rootErr != nil {
			return rootErr
		}
		if !oldRoot {
			return s.sharedCreateRefusal(ctx, ownerAccountID, newName, true)
		}
	}

	var newParentMailboxID *int64
	if newParentPath != "" {
		// RFC 4314 §4: moving a mailbox to a DIFFERENT parent requires the "k"
		// (create) right on the new parent — or, when the new parent must be
		// auto-created, on the nearest existing ancestor that CREATE would extend.
		// A pure rename that keeps the same parent needs no "k". (Owners hold "k".)
		// Whether newParentPath names the current parent is the database's call.
		parentID, sameParent, parentErr := s.lookUpNewParent(ctx, newParentPath, oldMailbox)
		if parentErr != nil {
			return s.internalError("failed to resolve new parent mailbox %q: %v", newParentPath, parentErr)
		}
		if !sameParent {
			if permErr := s.checkCreateRightForHierarchy(ctx, newParentPath, ownerAccountID, AccountID); permErr != nil {
				return permErr
			}
		}

		if parentID == nil {
			var perr error
			if parentID, perr = s.resolveOrCreateParentPath(ctx, newParentPath, ownerAccountID); perr != nil {
				return perr
			}
		}
		newParentMailboxID = parentID
	}
	// If len(newParts) <= 1, newParentMailboxID remains nil, which is correct for a top-level mailbox.

	// Rename using the mailbox owner's AccountID
	err = s.server.rdb.RenameMailboxWithRetry(ctx, oldMailbox.ID, ownerAccountID, newName, newParentMailboxID)
	if err != nil {
		if errors.Is(err, consts.ErrMailboxSharedBoundary) {
			return sharedBoundaryError()
		}
		return s.internalError("failed to rename mailbox '%s' to '%s': %v", existingName, newName, err)
	}

	s.DebugLog("mailbox renamed", "old_name", existingName, "new_name", newName)
	s.useMasterDB.Store(true) // Pin session to master DB for read-your-writes consistency

	// NOTE: the subscription follows the rename ATOMICALLY inside db.RenameMailbox
	// (same transaction as the name update), so there is no separate call here — a
	// crash can't leave the mailbox renamed but the subscription orphaned.

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

// lookUpNewParent looks parentPath up in mbox's owner's hierarchy, as the database
// resolves names, and returns the ID of the mailbox found and whether it is mbox's
// current parent, the one whose ID ends mbox's path. The caller reuses the ID
// instead of looking the parent up again. For a top-level mailbox, which has no
// parent, nothing is looked up; (nil, false) leaves the parent to
// resolveOrCreateParentPath, as when parentPath names no mailbox.
func (s *IMAPSession) lookUpNewParent(ctx context.Context, parentPath string, mbox *db.DBMailbox) (*int64, bool, error) {
	currentParentPath := helpers.GetParentPathFromPath(mbox.Path)
	if currentParentPath == "" {
		return nil, false, nil
	}
	ctx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	id, err := s.server.rdb.GetOwnedMailboxIDByNameWithRetry(ctx, mbox.AccountID, parentPath)
	switch {
	case err == nil:
		return &id, strings.HasSuffix(currentParentPath, helpers.FormatMailboxID(id)), nil
	case errors.Is(err, consts.ErrMailboxNotFound):
		return nil, false, nil
	default:
		return nil, false, err
	}
}

// resolveOrCreateParentPath returns the mailbox ID of newParentPath, auto-creating
// it if it does not exist (a common IMAP-client expectation, matching CREATE).
// Shared by the INBOX-rename and regular-rename destination-parent resolution so
// both link a hierarchical target under its parent rather than storing a flat name.
// Every level is the owner's own; foreignParentRefusal has ruled out the path
// leading into another owner's shared mailbox.
func (s *IMAPSession) resolveOrCreateParentPath(ctx context.Context, newParentPath string, ownerAccountID int64) (*int64, error) {
	ctx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	id, err := s.server.rdb.GetOwnedMailboxIDByNameWithRetry(ctx, ownerAccountID, newParentPath)
	if err == nil {
		return &id, nil
	}
	if !errors.Is(err, consts.ErrMailboxNotFound) {
		return nil, s.internalError("failed to fetch new parent mailbox %q: %v", newParentPath, err)
	}
	// Policy applies only when creating a missing parent. Reusing an existing
	// shared mailbox is still allowed when user-created shared roots are disabled.
	if refusal := s.sharedCreateRefusal(ctx, ownerAccountID, newParentPath, true); refusal != nil {
		return nil, refusal
	}
	parentID, err := s.server.rdb.ResolveOrCreateMailboxPathWithRetry(ctx, ownerAccountID, newParentPath)
	if err != nil {
		return nil, s.internalError("failed to resolve new parent hierarchy %q: %v", newParentPath, err)
	}
	return parentID, nil
}

// foreignParentRefusal refuses a RENAME whose new parent path leads into another
// owner's shared mailbox. A mailbox stays with its owner, so it cannot move there;
// nor is a namesake hierarchy of the owner's created in front of it. The nearest
// existing level of the path decides: the owner's own mailbox, or a shared mailbox
// of someone else's that the owner or the acting user (accountID) can act in. Either
// of them may hold only the "k" right there, without the "l" a lookup by name needs,
// and the acting user may see one the owner cannot, their own included.
func (s *IMAPSession) foreignParentRefusal(ctx context.Context, newParentPath string, ownerAccountID, accountID int64) error {
	ctx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	viewers := []int64{ownerAccountID}
	if accountID != ownerAccountID {
		viewers = append(viewers, accountID)
	}
	parts := strings.Split(newParentPath, string(consts.MailboxDelimiter))
	for i := len(parts); i >= 1; i-- {
		path := strings.Join(parts[:i], string(consts.MailboxDelimiter))
		_, err := s.server.rdb.GetOwnedMailboxIDByNameWithRetry(ctx, ownerAccountID, path)
		if err == nil {
			return nil
		}
		if !errors.Is(err, consts.ErrMailboxNotFound) {
			return s.internalError("failed to fetch new parent mailbox %q: %v", path, err)
		}
		// The owner has no mailbox of this name, so a shared one is another owner's.
		for _, viewer := range viewers {
			_, err := s.server.rdb.GetSharedMailboxByNameForRightWithRetry(ctx, viewer, path, db.ACLRightCreate)
			if errors.Is(err, consts.ErrMailboxNotFound) {
				continue
			}
			if err != nil {
				return s.internalError("failed to look up shared mailbox %q: %v", path, err)
			}
			s.DebugLog("rejecting rename into another owner's shared mailbox", "parent", path)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeCannot,
				Text: "Mailboxes cannot be moved into another owner's shared mailbox",
			}
		}
	}
	return nil
}

// checkCreateRightForHierarchy verifies the acting user holds the "k" (create)
// right on the nearest existing ancestor of newParentPath — the mailbox a CREATE
// would extend — per RFC 4314 §4. It returns nil when an existing ancestor grants
// "k", or when no ancestor exists yet (a top-level create in the user's own
// namespace). ownerAccountID owns the hierarchy; accountID is the acting user.
// This covers both an existing destination parent and one that must be auto-created.
func (s *IMAPSession) checkCreateRightForHierarchy(ctx context.Context, newParentPath string, ownerAccountID, accountID int64) error {
	parts := strings.Split(newParentPath, string(consts.MailboxDelimiter))
	for i := len(parts); i >= 1; i-- {
		ancestorPath := strings.Join(parts[:i], string(consts.MailboxDelimiter))
		ancestor, err := s.server.rdb.GetMailboxByNameWithRetry(ctx, ownerAccountID, ancestorPath)
		if err == consts.ErrMailboxNotFound {
			continue
		}
		if err != nil {
			return s.internalError("failed to resolve ancestor mailbox '%s': %v", ancestorPath, err)
		}
		hasCreateRight, kerr := s.server.rdb.CheckMailboxPermissionWithRetry(ctx, ancestor.ID, accountID, 'k')
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

// sharedBoundaryError is the refusal of a RENAME into or out of the shared namespace:
// RFC 5530 CANNOT, an operation that can never succeed.
func sharedBoundaryError() *imap.Error {
	return &imap.Error{
		Type: imap.StatusResponseTypeNo,
		Code: imap.ResponseCodeCannot,
		Text: "Mailboxes cannot be moved into or out of the shared namespace",
	}
}
