package imap

import (
	"context"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// Create a new mailbox
func (s *IMAPSession) Create(name string, options *imap.CreateOptions) error {
	// First phase: validation and mailbox lookup using read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.DebugLog("[CREATE] Failed to acquire read lock")
		return s.internalError("failed to acquire lock for create")
	}
	AccountID := s.AccountID()
	release()

	// Add config to context for shared mailbox detection
	ctx := s.ctx
	if s.server.config != nil {
		ctx = context.WithValue(ctx, consts.ConfigContextKey, s.server.config)
	}

	// Prevent creating the shared namespace root explicitly
	// Users should create "Shared/Something", not just "Shared"
	if s.server.config != nil && s.server.config.SharedMailboxes.Enabled {
		sharedPrefix := strings.TrimSuffix(s.server.config.SharedMailboxes.NamespacePrefix, "/")
		if name == sharedPrefix {
			s.DebugLog("[CREATE] cannot create shared namespace root '%s' explicitly", name)
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeCannot,
				Text: "Cannot create the shared namespace root directly. Create mailboxes under it instead (e.g., Shared/FolderName)",
			}
		}
	}

	// Check if mailbox already exists
	_, err := s.server.rdb.GetMailboxByNameWithRetry(ctx, AccountID, name)
	if err == nil {
		s.DebugLog("[CREATE] mailbox '%s' already exists", name)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeAlreadyExists,
			Text: "Mailbox already exists",
		}
	}

	// Split the mailbox name by the delimiter to check if it's nested
	parts := strings.Split(name, string(consts.MailboxDelimiter))
	var parentMailboxID *int64

	// For nested mailboxes, we need to find the immediate parent
	if len(parts) > 1 {
		// Remove empty part if name ends with delimiter (e.g., "folder/" -> ["folder", ""])
		if parts[len(parts)-1] == "" && len(parts) > 1 {
			parts = parts[:len(parts)-1]
		}

		// Still nested after cleanup?
		if len(parts) > 1 {
			// Auto-create missing parent mailboxes (like Dovecot)
			var currentParentID *int64

			// Create each level of the hierarchy if it doesn't exist
			for i := 1; i < len(parts); i++ {
				parentPathWithoutDelim := strings.Join(parts[:i], string(consts.MailboxDelimiter))

				var parentMailbox *db.DBMailbox

				// Check if parent mailbox exists. If not, create it.
				parentMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(ctx, AccountID, parentPathWithoutDelim)
				if err == consts.ErrMailboxNotFound {
					// If parent doesn't exist and we have a grandparent, check 'k' right on grandparent
					if currentParentID != nil {
						hasCreateRight, checkErr := s.server.rdb.CheckMailboxPermissionWithRetry(ctx, *currentParentID, AccountID, 'k')
						if checkErr != nil {
							return s.internalError("failed to check create permission on parent: %v", checkErr)
						}
						if !hasCreateRight {
							s.DebugLog("[CREATE] user does not have create permission on parent mailbox")
							return &imap.Error{
								Type: imap.StatusResponseTypeNo,
								Code: imap.ResponseCodeNoPerm,
								Text: "You do not have permission to create child mailboxes under this parent",
							}
						}
					}

					s.DebugLog("[CREATE] auto-creating parent mailbox '%s'", parentPathWithoutDelim)
					err = s.server.rdb.CreateMailboxWithRetry(ctx, AccountID, parentPathWithoutDelim, currentParentID)
					if err != nil {
						return s.internalError("failed to auto-create parent mailbox '%s': %v", parentPathWithoutDelim, err)
					}

					parentMailbox, err = s.server.rdb.GetMailboxByNameWithRetry(ctx, AccountID, parentPathWithoutDelim)
					if err != nil {
						return s.internalError("failed to fetch auto-created parent mailbox '%s': %v", parentPathWithoutDelim, err)
					}
				} else if err != nil {
					return s.internalError("failed to check for parent mailbox '%s': %v", parentPathWithoutDelim, err)
				}

				if parentMailbox != nil {
					currentParentID = &parentMailbox.ID
				}
			}

			parentMailboxID = currentParentID
		}
	}

	// Check ACL permission on final parent - requires 'k' (create) right for creating child mailbox
	if parentMailboxID != nil {
		hasCreateRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(ctx, *parentMailboxID, AccountID, 'k')
		if err != nil {
			return s.internalError("failed to check create permission: %v", err)
		}
		if !hasCreateRight {
			s.DebugLog("[CREATE] user does not have create permission on parent mailbox")
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNoPerm,
				Text: "You do not have permission to create child mailboxes under this parent",
			}
		}
	}

	// Final phase: actual creation - no locks needed as it's a DB operation
	err = s.server.rdb.CreateMailboxWithRetry(ctx, AccountID, name, parentMailboxID)
	if err != nil {
		return s.internalError("failed to create mailbox '%s': %v", name, err)
	}

	s.DebugLog("[CREATE] mailbox created: %s", name)
	return nil
}
