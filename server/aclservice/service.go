package aclservice

import (
	"context"
	"fmt"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
)

// ACLEntry represents an ACL entry for API/CLI output
type ACLEntry struct {
	Identifier string `json:"identifier"` // Email address or "anyone"
	Rights     string `json:"rights"`     // ACL rights string (e.g., "lrs")
}

// Service provides ACL management operations
type Service struct {
	rdb *resilient.ResilientDatabase
}

// New creates a new ACL service
func New(rdb *resilient.ResilientDatabase) *Service {
	return &Service{rdb: rdb}
}

// Grant grants ACL rights to a user or identifier on a mailbox
// Parameters:
//   - owner: Email address of the mailbox owner
//   - mailboxName: Name of the mailbox (e.g., "Shared/Sales")
//   - identifier: Email address of the user or "anyone"
//   - rights: ACL rights string (e.g., "lrs")
func (s *Service) Grant(ctx context.Context, owner, mailboxName, identifier, rights string) error {
	// Validate rights string
	if err := db.ValidateACLRights(rights); err != nil {
		return fmt.Errorf("invalid rights: %w", err)
	}

	// Get owner account ID
	ownerAccountID, err := s.rdb.GetAccountIDByAddressWithRetry(ctx, owner)
	if err != nil {
		return fmt.Errorf("owner account not found: %w", err)
	}

	// Grant access using identifier
	err = s.rdb.GrantMailboxAccessByIdentifierWithRetry(ctx, ownerAccountID, identifier, mailboxName, rights)
	if err != nil {
		return fmt.Errorf("failed to grant access: %w", err)
	}

	return nil
}

// Revoke revokes ACL rights from a user or identifier on a mailbox
// Parameters:
//   - owner: Email address of the mailbox owner
//   - mailboxName: Name of the mailbox (e.g., "Shared/Sales")
//   - identifier: Email address of the user or "anyone"
func (s *Service) Revoke(ctx context.Context, owner, mailboxName, identifier string) error {
	// Get owner account ID
	ownerAccountID, err := s.rdb.GetAccountIDByAddressWithRetry(ctx, owner)
	if err != nil {
		return fmt.Errorf("owner account not found: %w", err)
	}

	// Get mailbox
	mailbox, err := s.rdb.GetMailboxByNameWithRetry(ctx, ownerAccountID, mailboxName)
	if err != nil {
		return fmt.Errorf("mailbox not found: %w", err)
	}

	// Revoke access using identifier
	err = s.rdb.RevokeMailboxAccessByIdentifierWithRetry(ctx, mailbox.ID, identifier)
	if err != nil {
		return fmt.Errorf("failed to revoke access: %w", err)
	}

	return nil
}

// List lists all ACL entries for a mailbox
// Parameters:
//   - owner: Email address of the mailbox owner
//   - mailboxName: Name of the mailbox (e.g., "Shared/Sales")
//
// Returns:
//   - List of ACL entries with identifier and rights
func (s *Service) List(ctx context.Context, owner, mailboxName string) ([]ACLEntry, error) {
	// Get owner account ID
	ownerAccountID, err := s.rdb.GetAccountIDByAddressWithRetry(ctx, owner)
	if err != nil {
		return nil, fmt.Errorf("owner account not found: %w", err)
	}

	// Get mailbox
	mailbox, err := s.rdb.GetMailboxByNameWithRetry(ctx, ownerAccountID, mailboxName)
	if err != nil {
		return nil, fmt.Errorf("mailbox not found: %w", err)
	}

	// Get ACLs from database
	dbACLs, err := s.rdb.GetMailboxACLsWithRetry(ctx, mailbox.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get ACLs: %w", err)
	}

	// Convert to service ACL entries
	entries := make([]ACLEntry, 0, len(dbACLs))
	for _, dbACL := range dbACLs {
		// Get identifier (email or "anyone")
		identifier := dbACL.Identifier
		if identifier == "" && dbACL.AccountID != nil {
			// Legacy entry with account_id only, get email
			addr, err := s.rdb.GetPrimaryEmailForAccountWithRetry(ctx, *dbACL.AccountID)
			if err != nil {
				// Skip if we can't resolve the email
				continue
			}
			identifier = addr.FullAddress()
		}

		entries = append(entries, ACLEntry{
			Identifier: identifier,
			Rights:     dbACL.Rights,
		})
	}

	return entries, nil
}
