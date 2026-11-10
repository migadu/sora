package imap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// prepareACLIdentifier performs RFC 4314 §3 identifier preparation. Full SASLprep
// is not applied (ACL identifiers here are email addresses or "anyone"); instead
// we reject the cases a SASLprep pass would also reject — an empty/whitespace-only
// identifier ("results in an empty string") or one containing control characters
// (prohibited output). On failure the caller MUST respond BAD.
func prepareACLIdentifier(identifier imap.RightsIdentifier) error {
	id := string(identifier)
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("empty identifier")
	}
	// RFC 4314 §2: identifiers starting with "-" are reserved for "negative
	// rights". This server does not implement negative rights, so such an
	// identifier must be refused rather than treated as an ordinary account.
	if strings.HasPrefix(id, "-") {
		return fmt.Errorf("negative-right identifiers are not supported")
	}
	for _, r := range id {
		if unicode.IsControl(r) {
			return fmt.Errorf("identifier contains control characters")
		}
	}
	return nil
}

// ACL Extension (RFC 4314) Implementation
//
// The IMAPSession implements imapserver.SessionACL to provide ACL support.
// This enables shared mailbox functionality with fine-grained permissions.
//
// ACL Rights (RFC 4314):
//   l - lookup (mailbox visible in LIST/LSUB)
//   r - read (SELECT mailbox, FETCH, SEARCH)
//   s - keep seen/unseen status
//   w - write flags (except \Seen and \Deleted)
//   i - insert (APPEND, COPY into mailbox)
//   p - post (send mail to submission address for mailbox)
//   k - create child mailboxes
//   x - delete mailbox
//   t - delete messages (set/clear \Deleted flag)
//   e - expunge
//   a - administer (SETACL/DELETEACL/GETACL/LISTRIGHTS)

// MyRights returns the rights the current user has on a mailbox.
// RFC 4314 Section 3.7 - MYRIGHTS command
//
// This command does not require any special permissions.
func (s *IMAPSession) MyRights(ctx context.Context, mailbox string) (*imap.MyRightsData, error) {
	s.DebugLog("MYRIGHTS command", "mailbox", mailbox)

	// Get user ID
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}
	AccountID := s.AccountID()
	release()

	// Create context for database operations
	readCtx := ctx
	if s.useMasterDB.Load() {
		readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	}

	// Get mailbox
	mbox, err := s.server.rdb.GetMailboxByNameWithRetry(readCtx, AccountID, mailbox)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mailbox),
			}
		}
		return nil, s.internalError("failed to fetch mailbox '%s': %v", mailbox, err)
	}

	// Get user's rights on this mailbox
	rights, err := s.server.rdb.GetUserMailboxRightsWithRetry(readCtx, mbox.ID, AccountID)
	if err != nil {
		return nil, s.internalError("failed to get user rights for mailbox '%s': %v", mailbox, err)
	}

	// Convert string rights to RightSet
	rightSet := stringToRightSet(rights)

	s.DebugLog("user rights retrieved", "rights", rights, "mailbox", mailbox)

	return &imap.MyRightsData{
		Mailbox: mailbox,
		Rights:  rightSet,
	}, nil
}

// GetACL retrieves the access control list for a mailbox.
// RFC 4314 Section 3.3 - GETACL command
//
// The user must have the 'a' (administer) right on the mailbox (RFC 4314 §3.3).
func (s *IMAPSession) GetACL(ctx context.Context, mailbox string) (*imap.GetACLData, error) {
	s.DebugLog("GETACL command", "mailbox", mailbox)

	// Get user ID
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}
	AccountID := s.AccountID()
	release()

	// Create context for database operations
	readCtx := ctx
	if s.useMasterDB.Load() {
		readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	}

	// Get mailbox
	mbox, err := s.server.rdb.GetMailboxByNameWithRetry(readCtx, AccountID, mailbox)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mailbox),
			}
		}
		return nil, s.internalError("failed to fetch mailbox '%s': %v", mailbox, err)
	}

	// Check permission - RFC 4314 §3.3: GETACL requires the 'a' (administer) right.
	// The owner implicitly holds 'a'. A lookup-only user must NOT be able to read the
	// ACL (information disclosure), so 'l' alone is not accepted here.
	hasAdmin, err := s.server.rdb.CheckMailboxPermissionWithRetry(readCtx, mbox.ID, AccountID, db.ACLRightAdmin)
	if err != nil {
		return nil, s.internalError("failed to check admin permission: %v", err)
	}

	if !hasAdmin {
		s.DebugLog("user does not have admin permission to view ACL", "mailbox", mailbox)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to view ACL for this mailbox",
		}
	}

	// Get all ACL entries for this mailbox
	aclEntries, err := s.server.rdb.GetMailboxACLsWithRetry(readCtx, mbox.ID)
	if err != nil {
		return nil, s.internalError("failed to get ACL entries for mailbox '%s': %v", mailbox, err)
	}

	// Convert ACL entries to IMAP format
	// GetMailboxACLs lists each grantee under its current primary address, and the
	// owner with every right, which it holds whatever a stored row says.
	aclList := make([]imap.ACLEntry, 0, len(aclEntries)+1)
	ownerListed := false
	for _, entry := range aclEntries {
		if entry.AccountID != nil && *entry.AccountID == mbox.AccountID {
			ownerListed = true
		}
		aclList = append(aclList, imap.ACLEntry{
			Identifier: imap.RightsIdentifier(entry.Identifier),
			Rights:     stringToRightSet(entry.Rights),
		})
	}

	// RFC 4314 §3.3 example shows the mailbox owner listed with full rights. The
	// owner row is only materialized in mailbox_acls for shared mailboxes, so for
	// personal mailboxes (and any case where it is absent) synthesize it, ensuring
	// GETACL never returns an empty ACL that omits the owner. If the owner address
	// cannot be resolved (rare data-integrity case), omit the synthesized entry
	// rather than failing the whole command.
	if !ownerListed {
		if ownerEmail, ownerErr := s.server.rdb.GetPrimaryEmailForAccountWithRetry(readCtx, mbox.AccountID); ownerErr != nil {
			s.WarnLog("could not resolve mailbox owner for GETACL owner entry", "mailbox", mailbox, "error", ownerErr)
		} else {
			aclList = append(aclList, imap.ACLEntry{
				Identifier: imap.RightsIdentifier(ownerEmail.FullAddress()),
				Rights:     stringToRightSet(db.AllACLRights),
			})
		}
	}

	s.DebugLog("returning ACL entries", "count", len(aclList), "mailbox", mailbox)

	return &imap.GetACLData{
		Mailbox: mailbox,
		ACL:     aclList,
	}, nil
}

// SetACL sets or modifies the access control list for a mailbox.
// RFC 4314 Section 3.1 - SETACL command
//
// The user must have the 'a' (admin) right on the mailbox.
func (s *IMAPSession) SetACL(ctx context.Context, mailbox string, identifier imap.RightsIdentifier, modification imap.RightModification, rights imap.RightSet) error {
	s.DebugLog("SETACL command", "mailbox", mailbox, "identifier", identifier, "modification", modification, "rights", rights)

	// RFC 4314 §3: prepare the identifier; an empty/invalid identifier MUST be
	// refused with a BAD response.
	if err := prepareACLIdentifier(identifier); err != nil {
		return &imap.Error{
			Type: imap.StatusResponseTypeBad,
			Code: imap.ResponseCodeClientBug,
			Text: "Invalid ACL identifier",
		}
	}

	// RFC 4314 §3.1: an unrecognized right MUST cause a BAD response; the server
	// MUST NOT silently ignore unrecognized rights. Validate before any normalization
	// (rightSetToString silently drops unknown chars, which would otherwise let "ZZ"
	// collapse to an empty set and revoke the entry). The go-imap wire layer has
	// already expanded the obsolete virtual rights c/d to k/x/t/e, so the only valid
	// characters at this point are the standard rights in db.AllACLRights.
	for _, r := range rights {
		if !strings.ContainsRune(db.AllACLRights, rune(r)) {
			text := fmt.Sprintf("The %c right is not supported", rune(r))
			if rune(r) >= 'A' && rune(r) <= 'Z' {
				text = "Uppercase rights are not allowed"
			}
			return &imap.Error{
				Type: imap.StatusResponseTypeBad,
				Code: imap.ResponseCodeClientBug,
				Text: text,
			}
		}
	}

	// Get user ID
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}
	AccountID := s.AccountID()
	release()

	// Create context for database operations, with the config that decides whether
	// "anyone" may be granted rights ([shared_mailboxes] allow_anyone_identifier)
	writeCtx := ctx
	if s.useMasterDB.Load() {
		writeCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	}
	if s.server.config != nil {
		writeCtx = context.WithValue(writeCtx, consts.ConfigContextKey, s.server.config)
	}

	// Get mailbox
	mbox, err := s.server.rdb.GetMailboxByNameWithRetry(writeCtx, AccountID, mailbox)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mailbox),
			}
		}
		return s.internalError("failed to fetch mailbox '%s': %v", mailbox, err)
	}

	// Check permission - user needs 'a' (admin) right
	hasAdmin, err := s.server.rdb.CheckMailboxPermissionWithRetry(writeCtx, mbox.ID, AccountID, db.ACLRightAdmin)
	if err != nil {
		return s.internalError("failed to check admin permission: %v", err)
	}
	if !hasAdmin {
		s.DebugLog("user does not have admin permission", "mailbox", mailbox)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to modify ACL for this mailbox",
		}
	}

	identifierStr := string(identifier)
	var mod db.ACLModification
	switch modification {
	case imap.RightModificationReplace:
		mod = db.ACLReplace
	case imap.RightModificationAdd:
		mod = db.ACLAdd
	case imap.RightModificationRemove:
		mod = db.ACLRemove
	default:
		return &imap.Error{
			Type: imap.StatusResponseTypeBad,
			Code: imap.ResponseCodeClientBug,
			Text: "Invalid modification type",
		}
	}

	// By the ID whose 'a' right was checked: a concurrent rename can put a different
	// mailbox at this name, on which the caller has no permission. The database
	// resolves the identifier (any spelling or alias of an account names its one
	// entry) and checks 'a' again under the ACL lock.
	err = s.server.rdb.SetMailboxACLWithRetry(writeCtx, mbox.ID, AccountID, identifierStr, mod, rightSetToString(rights))
	if err != nil {
		return s.setACLError(mailbox, identifierStr, err)
	}

	s.DebugLog("ACL changed", "identifier", identifierStr, "modification", modification, "rights", rights, "mailbox", mailbox)
	s.useMasterDB.Store(true) // Pin session to master DB for read-your-writes consistency
	return nil
}

// setACLError turns a refused ACL change into the response the client can act on.
func (s *IMAPSession) setACLError(mailbox, identifier string, err error) error {
	no := func(code imap.ResponseCode, text string) error {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: code, Text: text}
	}
	switch {
	case errors.Is(err, consts.ErrMailboxNotFound):
		return no(imap.ResponseCodeNonExistent, fmt.Sprintf("mailbox '%s' no longer exists", mailbox))
	case errors.Is(err, consts.ErrUserNotFound):
		return no(imap.ResponseCodeNonExistent, fmt.Sprintf("user '%s' does not exist", identifier))
	case errors.Is(err, consts.ErrNotPermitted):
		return no(imap.ResponseCodeNoPerm, "You do not have permission to modify ACL for this mailbox")
	// RFC 5530 CANNOT: these changes can never succeed, which the client must be
	// able to tell from a server fault.
	case errors.Is(err, db.ErrMailboxNotShared):
		return no(imap.ResponseCodeCannot, "Only mailboxes in the shared namespace can be shared")
	case errors.Is(err, db.ErrCrossDomainGrant):
		return no(imap.ResponseCodeCannot, "Mailboxes can only be shared with users in the same domain")
	case errors.Is(err, db.ErrOwnerACL):
		return no(imap.ResponseCodeCannot, "The mailbox owner always holds every right")
	case errors.Is(err, db.ErrAnyoneDisabled):
		return no(imap.ResponseCodeCannot, `Sharing with "anyone" is disabled on this server`)
	}
	return s.internalError("failed to change ACL: %v", err)
}

// DeleteACL removes the access control list entry for an identifier.
// RFC 4314 Section 3.2 - DELETEACL command
//
// This is equivalent to SetACL with RightModificationReplace and empty rights.
// The user must have the 'a' (admin) right on the mailbox.
func (s *IMAPSession) DeleteACL(ctx context.Context, mailbox string, identifier imap.RightsIdentifier) error {
	s.DebugLog("DELETEACL command", "mailbox", mailbox, "identifier", identifier)

	// Use SetACL with empty rights and replace modification
	return s.SetACL(ctx, mailbox, identifier, imap.RightModificationReplace, imap.RightSet{})
}

// ListRights lists the rights that can be granted to an identifier on a mailbox.
// RFC 4314 Section 3.5 - LISTRIGHTS command
//
// The user must have the 'a' (admin) right on the mailbox.
func (s *IMAPSession) ListRights(ctx context.Context, mailbox string, identifier imap.RightsIdentifier) (*imap.ListRightsData, error) {
	s.DebugLog("LISTRIGHTS command", "mailbox", mailbox, "identifier", identifier)

	// RFC 4314 §3: an empty/invalid identifier MUST be refused with a BAD response.
	if err := prepareACLIdentifier(identifier); err != nil {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeBad,
			Code: imap.ResponseCodeClientBug,
			Text: "Invalid ACL identifier",
		}
	}

	// Get user ID
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}
	AccountID := s.AccountID()
	release()

	// Create context for database operations, with the config that decides whether
	// "anyone" may be granted rights ([shared_mailboxes] allow_anyone_identifier)
	readCtx := ctx
	if s.useMasterDB.Load() {
		readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	}
	if s.server.config != nil {
		readCtx = context.WithValue(readCtx, consts.ConfigContextKey, s.server.config)
	}

	// Get mailbox
	mbox, err := s.server.rdb.GetMailboxByNameWithRetry(readCtx, AccountID, mailbox)
	if err != nil {
		if err == consts.ErrMailboxNotFound {
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' does not exist", mailbox),
			}
		}
		return nil, s.internalError("failed to fetch mailbox '%s': %v", mailbox, err)
	}

	// Check permission - user needs 'a' (admin) right
	hasAdmin, err := s.server.rdb.CheckMailboxPermissionWithRetry(readCtx, mbox.ID, AccountID, db.ACLRightAdmin)
	if err != nil {
		return nil, s.internalError("failed to check admin permission: %v", err)
	}
	if !hasAdmin {
		s.DebugLog("user does not have admin permission", "mailbox", mailbox)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to list rights for this mailbox",
		}
	}

	// The database decides by the same checks SETACL makes, so LISTRIGHTS offers
	// exactly what SETACL grants and reveals no more about which addresses exist.
	identifierEmail := string(identifier)
	grantability, err := s.server.rdb.MailboxACLGrantabilityWithRetry(readCtx, mbox.ID, identifierEmail)
	if err != nil {
		if errors.Is(err, consts.ErrMailboxNotFound) {
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("mailbox '%s' no longer exists", mailbox),
			}
		}
		if errors.Is(err, consts.ErrUserNotFound) {
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("user '%s' does not exist", identifierEmail),
			}
		}
		return nil, s.internalError("failed to list rights for '%s': %v", identifierEmail, err)
	}

	// RFC 4314 §2: LISTRIGHTS tells a client what may be granted, and an
	// implementation MAY force rights to always or never be granted to an identifier.
	// The go-imap wire layer adds the obsolete virtual c/d rights as needed.
	requiredRights := imap.RightSet{}
	var optionalRights []imap.RightSet
	switch grantability {
	case db.ACLGrantOwner:
		// The owner always holds every right (has_mailbox_right), whatever the ACL says.
		requiredRights = stringToRightSet(db.AllACLRights)
	case db.ACLGrantAny:
		// RFC 4314 §3.7: rights listed in the same string are "tied" — the server
		// must grant them all or none. Sora grants every right independently, so each
		// right is returned as its own single-character group rather than one bundled
		// string (which would falsely advertise all 11 rights as an all-or-none unit).
		optionalRights = make([]imap.RightSet, 0, len(db.AllACLRights))
		for _, r := range db.AllACLRights {
			optionalRights = append(optionalRights, imap.RightSet{imap.Right(r)})
		}
	}

	s.DebugLog("returning available rights", "identifier", identifierEmail, "mailbox", mailbox)

	return &imap.ListRightsData{
		Mailbox:        mailbox,
		Identifier:     identifier,
		RequiredRights: requiredRights,
		OptionalRights: optionalRights,
	}, nil
}

// Helper functions

// stringToRightSet converts a rights string (e.g., "lrswipkxtea") to imap.RightSet
func stringToRightSet(rights string) imap.RightSet {
	rightSet := make(imap.RightSet, 0, len(rights))
	for _, r := range rights {
		rightSet = append(rightSet, imap.Right(r))
	}
	return rightSet
}

// rightSetToString converts imap.RightSet to a rights string
func rightSetToString(rights imap.RightSet) string {
	// Extract rights and sort them in standard order (lrswipkxtea)
	var result strings.Builder
	standardOrder := "lrswipkxtea"
	for _, r := range standardOrder {
		if strings.ContainsRune(string(rights), rune(r)) {
			result.WriteRune(r)
		}
	}
	return result.String()
}
