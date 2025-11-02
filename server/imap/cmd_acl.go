package imap

import (
	"context"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

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
func (s *IMAPSession) MyRights(mailbox string) (*imap.MyRightsData, error) {
	s.DebugLog("[MYRIGHTS] mailbox: %s", mailbox)

	// Get user ID
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
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
	readCtx := s.ctx
	if s.useMasterDB {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
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

	s.DebugLog("[MYRIGHTS] user has rights '%s' on mailbox '%s'", rights, mailbox)

	return &imap.MyRightsData{
		Mailbox: mailbox,
		Rights:  rightSet,
	}, nil
}

// GetACL retrieves the access control list for a mailbox.
// RFC 4314 Section 3.3 - GETACL command
//
// The user must have either the 'l' (lookup) or 'a' (admin) right on the mailbox.
func (s *IMAPSession) GetACL(mailbox string) (*imap.GetACLData, error) {
	s.DebugLog("[GETACL] mailbox: %s", mailbox)

	// Get user ID
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
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
	readCtx := s.ctx
	if s.useMasterDB {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
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

	// Check permission - user needs 'l' (lookup) or 'a' (admin) right
	hasLookup, err := s.server.rdb.CheckMailboxPermissionWithRetry(readCtx, mbox.ID, AccountID, db.ACLRightLookup)
	if err != nil {
		return nil, s.internalError("failed to check lookup permission: %v", err)
	}
	hasAdmin, err := s.server.rdb.CheckMailboxPermissionWithRetry(readCtx, mbox.ID, AccountID, db.ACLRightAdmin)
	if err != nil {
		return nil, s.internalError("failed to check admin permission: %v", err)
	}

	if !hasLookup && !hasAdmin {
		s.DebugLog("[GETACL] user does not have permission to view ACL for mailbox '%s'", mailbox)
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
	// Use the identifier field directly (email or "anyone")
	aclList := make([]imap.ACLEntry, 0, len(aclEntries))
	for _, entry := range aclEntries {
		aclList = append(aclList, imap.ACLEntry{
			Identifier: imap.RightsIdentifier(entry.Identifier),
			Rights:     stringToRightSet(entry.Rights),
		})
	}

	s.DebugLog("[GETACL] returning %d ACL entries for mailbox '%s'", len(aclList), mailbox)

	return &imap.GetACLData{
		Mailbox: mailbox,
		ACL:     aclList,
	}, nil
}

// SetACL sets or modifies the access control list for a mailbox.
// RFC 4314 Section 3.1 - SETACL command
//
// The user must have the 'a' (admin) right on the mailbox.
func (s *IMAPSession) SetACL(mailbox string, identifier imap.RightsIdentifier, modification imap.RightModification, rights imap.RightSet) error {
	s.DebugLog("[SETACL] mailbox: %s, identifier: %s, modification: %v, rights: %v", mailbox, identifier, modification, rights)

	// Get user ID
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
	if !acquired {
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}
	AccountID := s.AccountID()
	release()

	// Create context for database operations
	writeCtx := s.ctx
	if s.useMasterDB {
		writeCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
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
		s.DebugLog("[SETACL] user does not have admin permission on mailbox '%s'", mailbox)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to modify ACL for this mailbox",
		}
	}

	// Get identifier string (email address or "anyone")
	identifierStr := string(identifier)

	// Validate identifier - must be email or "anyone"
	if !db.IsSpecialIdentifier(identifierStr) {
		// Validate it's a valid email by checking if user exists
		_, err := s.server.rdb.GetAccountIDByAddressWithRetry(writeCtx, identifierStr)
		if err != nil {
			if err == consts.ErrUserNotFound {
				return &imap.Error{
					Type: imap.StatusResponseTypeNo,
					Code: imap.ResponseCodeNonExistent,
					Text: fmt.Sprintf("user '%s' does not exist", identifierStr),
				}
			}
			return s.internalError("failed to validate identifier '%s': %v", identifierStr, err)
		}
	}

	// Convert RightSet to string
	newRightsStr := rightSetToString(rights)

	// Handle modification type
	var finalRights string
	switch modification {
	case imap.RightModificationReplace:
		// Replace all rights
		finalRights = newRightsStr

	case imap.RightModificationAdd:
		// Add rights to existing (need to get existing ACL by identifier)
		existingRights := ""
		acls, err := s.server.rdb.GetMailboxACLsWithRetry(writeCtx, mbox.ID)
		if err != nil {
			return s.internalError("failed to get existing ACLs: %v", err)
		}
		for _, acl := range acls {
			if acl.Identifier == identifierStr {
				existingRights = acl.Rights
				break
			}
		}
		finalRights = mergeRights(existingRights, newRightsStr)

	case imap.RightModificationRemove:
		// Remove rights from existing
		existingRights := ""
		acls, err := s.server.rdb.GetMailboxACLsWithRetry(writeCtx, mbox.ID)
		if err != nil {
			return s.internalError("failed to get existing ACLs: %v", err)
		}
		for _, acl := range acls {
			if acl.Identifier == identifierStr {
				existingRights = acl.Rights
				break
			}
		}
		finalRights = removeRights(existingRights, newRightsStr)

	default:
		return &imap.Error{
			Type: imap.StatusResponseTypeBad,
			Code: imap.ResponseCodeClientBug,
			Text: "Invalid modification type",
		}
	}

	// If final rights are empty, this is a DELETEACL operation
	if finalRights == "" {
		err = s.server.rdb.RevokeMailboxAccessByIdentifierWithRetry(writeCtx, mbox.ID, identifierStr)
		if err != nil {
			return s.internalError("failed to revoke access: %v", err)
		}
		s.DebugLog("[SETACL] revoked all rights for identifier '%s' on mailbox '%s'", identifierStr, mailbox)
		return nil
	}

	// Grant access with final rights using identifier
	err = s.server.rdb.GrantMailboxAccessByIdentifierWithRetry(writeCtx, AccountID, identifierStr, mailbox, finalRights)
	if err != nil {
		return s.internalError("failed to grant access: %v", err)
	}

	s.DebugLog("[SETACL] granted rights '%s' to identifier '%s' on mailbox '%s'", finalRights, identifierStr, mailbox)
	return nil
}

// DeleteACL removes the access control list entry for an identifier.
// RFC 4314 Section 3.2 - DELETEACL command
//
// This is equivalent to SetACL with RightModificationReplace and empty rights.
// The user must have the 'a' (admin) right on the mailbox.
func (s *IMAPSession) DeleteACL(mailbox string, identifier imap.RightsIdentifier) error {
	s.DebugLog("[DELETEACL] mailbox: %s, identifier: %s", mailbox, identifier)

	// Use SetACL with empty rights and replace modification
	return s.SetACL(mailbox, identifier, imap.RightModificationReplace, imap.RightSet{})
}

// ListRights lists the rights that can be granted to an identifier on a mailbox.
// RFC 4314 Section 3.5 - LISTRIGHTS command
//
// The user must have the 'a' (admin) right on the mailbox.
func (s *IMAPSession) ListRights(mailbox string, identifier imap.RightsIdentifier) (*imap.ListRightsData, error) {
	s.DebugLog("[LISTRIGHTS] mailbox: %s, identifier: %s", mailbox, identifier)

	// Get user ID
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
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
	readCtx := s.ctx
	if s.useMasterDB {
		readCtx = context.WithValue(s.ctx, consts.UseMasterDBKey, true)
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
		s.DebugLog("[LISTRIGHTS] user does not have admin permission on mailbox '%s'", mailbox)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeNoPerm,
			Text: "You do not have permission to list rights for this mailbox",
		}
	}

	// Verify identifier exists
	identifierEmail := string(identifier)
	_, err = s.server.rdb.GetAccountIDByAddressWithRetry(readCtx, identifierEmail)
	if err != nil {
		if err == consts.ErrUserNotFound {
			return nil, &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: imap.ResponseCodeNonExistent,
				Text: fmt.Sprintf("user '%s' does not exist", identifierEmail),
			}
		}
		return nil, s.internalError("failed to get account ID for '%s': %v", identifierEmail, err)
	}

	// Return all available rights
	// Required rights: none (empty set)
	// Optional rights: all ACL rights (lrswipkxtea)
	allRights := stringToRightSet(db.AllACLRights)

	s.DebugLog("[LISTRIGHTS] returning available rights for '%s' on mailbox '%s'", identifierEmail, mailbox)

	return &imap.ListRightsData{
		Mailbox:        mailbox,
		Identifier:     identifier,
		RequiredRights: imap.RightSet{},            // No required rights
		OptionalRights: []imap.RightSet{allRights}, // All rights are optional
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

// mergeRights adds newRights to existingRights
func mergeRights(existingRights, newRights string) string {
	rightSet := stringToRightSet(existingRights)
	for _, r := range newRights {
		if !strings.ContainsRune(string(rightSet), r) {
			rightSet = append(rightSet, imap.Right(r))
		}
	}
	return rightSetToString(rightSet)
}

// removeRights removes removeRights from existingRights
func removeRights(existingRights, removeRights string) string {
	rightSet := stringToRightSet(existingRights)
	newRightSet := make(imap.RightSet, 0, len(rightSet))
	for _, r := range rightSet {
		if !strings.ContainsRune(removeRights, rune(r)) {
			newRightSet = append(newRightSet, r)
		}
	}
	return rightSetToString(newRightSet)
}
