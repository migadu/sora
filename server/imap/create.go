package imap

import (
	"context"
	"errors"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
)

// Create a new mailbox
func (s *IMAPSession) Create(name string, options *imap.CreateOptions) error {
	// RFC 6154: validate any CREATE ... USE (...) request up front so an
	// unsupported special-use is rejected with NO [USEATTR] before we create
	// anything. Sora persists at most one attribute per mailbox.
	var specialUse string
	if options != nil && len(options.SpecialUse) > 0 {
		var useErr *imap.Error
		specialUse, useErr = validateSpecialUse(options.SpecialUse)
		if useErr != nil {
			s.DebugLog("rejecting CREATE with unsupported special-use", "attrs", options.SpecialUse)
			return useErr
		}
	}

	// First phase: validation and mailbox lookup using read lock
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		s.DebugLog("failed to acquire read lock")
		return s.internalError("failed to acquire lock for create")
	}
	AccountID := s.AccountID()
	release()

	// Reject path-traversal segments ("." / "..") up front with a clean client
	// error. These names would let the maildir exporter escape its target
	// directory; db.CreateMailbox enforces this too, but checking here avoids a
	// misleading SERVERBUG response and short-circuits parent auto-creation.
	if helpers.MailboxNameHasTraversal(name) {
		s.DebugLog("rejecting mailbox name with path traversal segment", "name", name)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeCannot,
			Text: "Invalid mailbox name",
		}
	}

	// RFC 3501 §6.3.3: a trailing hierarchy separator is an intent marker
	// ("this mailbox may have inferiors"), not part of the stored name — so
	// CREATE "foo/" creates the mailbox "foo". Trim it before the existence
	// check, the shared-namespace check, and creation so the name is canonical.
	name = strings.TrimRight(name, string(consts.MailboxDelimiter))
	if name == "" {
		s.DebugLog("rejecting empty mailbox name after trimming trailing separators")
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeCannot,
			Text: "Invalid mailbox name",
		}
	}

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
			s.DebugLog("cannot create shared namespace root explicitly", "name", name)
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
		s.DebugLog("mailbox already exists", "mailbox", name)
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
							s.DebugLog("user does not have create permission on parent mailbox")
							return &imap.Error{
								Type: imap.StatusResponseTypeNo,
								Code: imap.ResponseCodeNoPerm,
								Text: "You do not have permission to create child mailboxes under this parent",
							}
						}
					}

					s.DebugLog("auto-creating parent mailbox", "mailbox", parentPathWithoutDelim)
					err = s.server.rdb.CreateMailboxWithRetry(ctx, AccountID, parentPathWithoutDelim, currentParentID)
					if err != nil {
						// Handle race condition: another session may have created the same parent
						// mailbox concurrently. If so, just fetch the existing one.
						if errors.Is(err, consts.ErrDBUniqueViolation) {
							s.DebugLog("parent mailbox already exists (concurrent create)", "mailbox", parentPathWithoutDelim)
						} else {
							return s.internalError("failed to auto-create parent mailbox '%s': %v", parentPathWithoutDelim, err)
						}
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
			s.DebugLog("user does not have create permission on parent mailbox")
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNoPerm,
				Text: "You do not have permission to create child mailboxes under this parent",
			}
		}
	}

	// RFC 6154 §5: a special-use attribute identifies at most one mailbox. Reject
	// up front if it is already in use, so we don't create the mailbox first. (The
	// partial unique index is the race-proof backstop, handled after creation.)
	if specialUse != "" {
		inUse, uErr := s.server.rdb.HasMailboxWithSpecialUseWithRetry(ctx, AccountID, specialUse)
		if uErr != nil {
			return s.internalError("failed to check special-use uniqueness: %v", uErr)
		}
		if inUse {
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCode("USEATTR"),
				Text: "Special-use attribute is already assigned to another mailbox",
			}
		}
	}

	// Final phase: actual creation - no locks needed as it's a DB operation.
	// When a special-use attribute is requested, create the mailbox and assign the
	// attribute in a single transaction so a failure can never leave a mailbox
	// without its attribute (RFC 6154), and LIST never observes a transient
	// attribute-less state. Auto-created parents above do not inherit it.
	if specialUse != "" {
		err = s.server.rdb.CreateMailboxWithSpecialUseWithRetry(ctx, AccountID, name, parentMailboxID, specialUse)
		if err != nil {
			if errors.Is(err, consts.ErrMailboxSpecialUseInUse) {
				// Lost the race with the pre-check: another mailbox claimed the
				// attribute concurrently (the partial unique index is the backstop).
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCode("USEATTR"),
					Text: "Special-use attribute is already assigned to another mailbox",
				}
			}
			if errors.Is(err, consts.ErrDBUniqueViolation) {
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeAlreadyExists,
					Text: "Mailbox already exists",
				}
			}
			return s.internalError("failed to create mailbox '%s': %v", name, err)
		}
		s.DebugLog("mailbox created with special-use", "mailbox", name, "special_use", specialUse)
		return nil
	}

	err = s.server.rdb.CreateMailboxWithRetry(ctx, AccountID, name, parentMailboxID)
	if err != nil {
		// Handle race condition: another session may have created the same mailbox
		// between our existence check and the actual INSERT.
		if errors.Is(err, consts.ErrDBUniqueViolation) {
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeAlreadyExists,
				Text: "Mailbox already exists",
			}
		}
		return s.internalError("failed to create mailbox '%s': %v", name, err)
	}

	s.DebugLog("mailbox created", "mailbox", name)
	return nil
}

// validateSpecialUse checks a CREATE ... USE request. Sora supports exactly the
// five RFC 6154 core attributes and stores at most one per mailbox. It returns
// the single attribute to persist, or a *imap.Error carrying [USEATTR] when the
// request is unsupported (an unknown attribute, or more than one).
func validateSpecialUse(attrs []imap.MailboxAttr) (string, *imap.Error) {
	if len(attrs) > 1 {
		return "", &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCode("USEATTR"),
			Text: "Only a single special-use attribute is supported per mailbox",
		}
	}
	switch attrs[0] {
	case imap.MailboxAttrSent, imap.MailboxAttrDrafts, imap.MailboxAttrArchive,
		imap.MailboxAttrJunk, imap.MailboxAttrTrash:
		return string(attrs[0]), nil
	default:
		return "", &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCode("USEATTR"),
			Text: "Unsupported special-use attribute",
		}
	}
}
