package db

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
)

// ACLEntry represents a mailbox ACL entry
type ACLEntry struct {
	MailboxID  int64
	AccountID  *int64 // NULL for "anyone" identifier
	Identifier string // Email address or "anyone"
	Rights     string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// ACLRight represents individual IMAP ACL rights (RFC 4314)
type ACLRight rune

const (
	ACLRightLookup    ACLRight = 'l' // Mailbox is visible to LIST/LSUB
	ACLRightRead      ACLRight = 'r' // SELECT mailbox, FETCH, SEARCH
	ACLRightSeen      ACLRight = 's' // Keep seen/unseen status
	ACLRightWrite     ACLRight = 'w' // Set/clear flags except \Seen and \Deleted
	ACLRightInsert    ACLRight = 'i' // APPEND, COPY into mailbox
	ACLRightPost      ACLRight = 'p' // Send mail to submission address (LMTP)
	ACLRightCreate    ACLRight = 'k' // CREATE child mailboxes
	ACLRightDelete    ACLRight = 'x' // DELETE mailbox
	ACLRightDeleteMsg ACLRight = 't' // Set/clear \Deleted flag
	ACLRightExpunge   ACLRight = 'e' // EXPUNGE messages
	ACLRightAdmin     ACLRight = 'a' // Administer (SETACL/DELETEACL)
)

// AllACLRights contains all valid ACL rights
const AllACLRights = "lrswipkxtea"

// Special ACL identifiers (RFC 4314)
const (
	// AnyoneIdentifier grants rights to all users in the same domain
	// RFC 4314: "anyone" refers to the universal identity (all authenticted users)
	// We scope this to same-domain for security
	AnyoneIdentifier = "anyone"
)

// ValidateACLRights checks if a rights string contains only valid ACL rights
func ValidateACLRights(rights string) error {
	for _, r := range rights {
		if !strings.ContainsRune(AllACLRights, r) {
			return fmt.Errorf("invalid ACL right: %c", r)
		}
	}
	return nil
}

// IsSpecialIdentifier checks if an identifier is a special ACL identifier
func IsSpecialIdentifier(identifier string) bool {
	return identifier == AnyoneIdentifier
}

// GrantMailboxAccessByIdentifier grants access to a mailbox using an identifier (email or "anyone")
// Enforces same-domain restriction for security
func (db *Database) GrantMailboxAccessByIdentifier(ctx context.Context, ownerAccountID int64, identifier string, mailboxName string, rights string) error {
	// Validate rights string
	if err := ValidateACLRights(rights); err != nil {
		return err
	}

	// Start a transaction
	tx, err := db.GetWritePool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Get mailbox details
	mailbox, err := db.GetMailboxByName(ctx, ownerAccountID, mailboxName)
	if err != nil {
		return fmt.Errorf("mailbox not found: %w", err)
	}

	// Verify mailbox is shared and get owner domain
	var isShared bool
	var ownerDomain *string
	err = tx.QueryRow(ctx, `
		SELECT COALESCE(is_shared, FALSE), owner_domain
		FROM mailboxes
		WHERE id = $1
	`, mailbox.ID).Scan(&isShared, &ownerDomain)
	if err != nil {
		return fmt.Errorf("failed to check mailbox type: %w", err)
	}

	if !isShared {
		return fmt.Errorf("mailbox is not shared")
	}

	if ownerDomain == nil || *ownerDomain == "" {
		return fmt.Errorf("shared mailbox has no owner domain")
	}

	// Handle "anyone" identifier
	if identifier == AnyoneIdentifier {
		// Insert or update ACL for "anyone"
		_, err = tx.Exec(ctx, `
			INSERT INTO mailbox_acls (mailbox_id, account_id, identifier, rights, created_at, updated_at)
			VALUES ($1, NULL, $2, $3, now(), now())
			ON CONFLICT (mailbox_id, identifier)
			DO UPDATE SET rights = EXCLUDED.rights, updated_at = now()
		`, mailbox.ID, identifier, rights)
		if err != nil {
			return fmt.Errorf("failed to grant access to %s: %w", AnyoneIdentifier, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}

		return nil
	}

	// Handle regular user identifier (email address)
	// Get grantee's account ID and domain
	var granteeAccountID int64
	var granteeDomain string
	err = tx.QueryRow(ctx, `
		SELECT account_id, SPLIT_PART(address, '@', 2) as domain
		FROM credentials
		WHERE LOWER(address) = LOWER($1) AND primary_identity = TRUE
	`, identifier).Scan(&granteeAccountID, &granteeDomain)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("user %s not found", identifier)
		}
		return fmt.Errorf("failed to get grantee info: %w", err)
	}

	// Enforce same-domain restriction
	if *ownerDomain != granteeDomain {
		return fmt.Errorf("cannot grant access to user from different domain (owner: %s, grantee: %s)", *ownerDomain, granteeDomain)
	}

	// Insert or update ACL
	_, err = tx.Exec(ctx, `
		INSERT INTO mailbox_acls (mailbox_id, account_id, identifier, rights, created_at, updated_at)
		VALUES ($1, $2, $3, $4, now(), now())
		ON CONFLICT (mailbox_id, identifier)
		DO UPDATE SET rights = EXCLUDED.rights, updated_at = now()
	`, mailbox.ID, granteeAccountID, identifier, rights)
	if err != nil {
		return fmt.Errorf("failed to grant access: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// RevokeMailboxAccessByIdentifier removes ACL entry for an identifier
func (db *Database) RevokeMailboxAccessByIdentifier(ctx context.Context, mailboxID int64, identifier string) error {
	result, err := db.GetWritePool().Exec(ctx, `
		DELETE FROM mailbox_acls WHERE mailbox_id = $1 AND identifier = $2
	`, mailboxID, identifier)
	if err != nil {
		return fmt.Errorf("failed to revoke access: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("ACL entry not found for identifier %s", identifier)
	}

	return nil
}

// GetMailboxACLs retrieves all ACL entries for a mailbox
func (db *Database) GetMailboxACLs(ctx context.Context, mailboxID int64) ([]ACLEntry, error) {
	rows, err := db.GetReadPool().Query(ctx, `
		SELECT mailbox_id, account_id, identifier, rights, created_at, updated_at
		FROM mailbox_acls
		WHERE mailbox_id = $1
		ORDER BY identifier
	`, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("failed to query ACLs: %w", err)
	}
	defer rows.Close()

	var entries []ACLEntry
	for rows.Next() {
		var entry ACLEntry
		if err := rows.Scan(&entry.MailboxID, &entry.AccountID, &entry.Identifier, &entry.Rights, &entry.CreatedAt, &entry.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan ACL entry: %w", err)
		}
		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating ACL entries: %w", err)
	}

	return entries, nil
}

// CheckMailboxPermission checks if a user has a specific right on a mailbox
// Uses the PostgreSQL function for efficient permission checking
func (db *Database) CheckMailboxPermission(ctx context.Context, mailboxID, accountID int64, right ACLRight) (bool, error) {
	var hasRight bool
	err := db.GetReadPool().QueryRow(ctx, `
		SELECT has_mailbox_right($1, $2, $3)
	`, mailboxID, accountID, string(right)).Scan(&hasRight)
	if err != nil {
		return false, fmt.Errorf("failed to check permission: %w", err)
	}
	return hasRight, nil
}

// CheckMailboxPermissions checks if a user has all specified rights on a mailbox
func (db *Database) CheckMailboxPermissions(ctx context.Context, mailboxID, accountID int64, rights string) (bool, error) {
	for _, r := range rights {
		hasRight, err := db.CheckMailboxPermission(ctx, mailboxID, accountID, ACLRight(r))
		if err != nil {
			return false, err
		}
		if !hasRight {
			return false, nil
		}
	}
	return true, nil
}

// GetUserMailboxRights returns the rights a user has on a specific mailbox
// Returns empty string if user has no access
func (db *Database) GetUserMailboxRights(ctx context.Context, mailboxID, accountID int64) (string, error) {
	// First check if user owns the mailbox (owner always has full access)
	var isOwner bool
	var ownerDomain *string
	err := db.GetReadPool().QueryRow(ctx, `
		SELECT (account_id = $1), owner_domain
		FROM mailboxes
		WHERE id = $2
	`, accountID, mailboxID).Scan(&isOwner, &ownerDomain)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", consts.ErrMailboxNotFound
		}
		return "", fmt.Errorf("failed to check ownership: %w", err)
	}

	// Owners have all rights (both shared and non-shared mailboxes)
	if isOwner {
		return AllACLRights, nil
	}

	// Check ACL table for user-specific rights
	var rights string
	err = db.GetReadPool().QueryRow(ctx, `
		SELECT rights
		FROM mailbox_acls
		WHERE mailbox_id = $1 AND account_id = $2
	`, mailboxID, accountID).Scan(&rights)
	if err == nil {
		return rights, nil
	}
	if err != pgx.ErrNoRows {
		return "", fmt.Errorf("failed to query user ACL: %w", err)
	}

	// No user-specific ACL, check for "anyone" identifier (same domain only)
	if ownerDomain != nil {
		// Get user's domain
		var userDomain string
		err = db.GetReadPool().QueryRow(ctx, `
			SELECT SPLIT_PART(address, '@', 2)
			FROM credentials
			WHERE account_id = $1 AND primary_identity = TRUE
		`, accountID).Scan(&userDomain)
		if err != nil {
			if err == pgx.ErrNoRows {
				return "", nil // No primary credential, no access
			}
			return "", fmt.Errorf("failed to get user domain: %w", err)
		}

		// Check if user is in same domain and "anyone" ACL exists
		if userDomain == *ownerDomain {
			var anyoneRights string
			err = db.GetReadPool().QueryRow(ctx, `
				SELECT rights
				FROM mailbox_acls
				WHERE mailbox_id = $1 AND identifier = $2
			`, mailboxID, AnyoneIdentifier).Scan(&anyoneRights)
			if err == nil {
				return anyoneRights, nil
			}
			if err != pgx.ErrNoRows {
				return "", fmt.Errorf("failed to query 'anyone' ACL: %w", err)
			}
		}
	}

	// No access found
	return "", nil
}

// GetAccessibleMailboxes returns all mailboxes accessible to a user
// Includes both owned mailboxes and shared mailboxes with ACL access
func (db *Database) GetAccessibleMailboxes(ctx context.Context, accountID int64) ([]*DBMailbox, error) {
	// Use the PostgreSQL helper function
	rows, err := db.GetReadPool().Query(ctx, `
		SELECT mailbox_id, mailbox_name, is_shared, access_rights
		FROM get_accessible_mailboxes($1)
	`, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to query accessible mailboxes: %w", err)
	}
	defer rows.Close()

	var mailboxes []*DBMailbox
	for rows.Next() {
		var mailbox DBMailbox
		var isShared bool
		var rights string

		if err := rows.Scan(&mailbox.ID, &mailbox.Name, &isShared, &rights); err != nil {
			return nil, fmt.Errorf("failed to scan mailbox: %w", err)
		}

		// Fetch additional mailbox details
		fullMailbox, err := db.GetMailbox(ctx, mailbox.ID, accountID)
		if err != nil {
			// If GetMailbox fails for shared mailboxes (due to account_id mismatch),
			// we need a different approach - for now skip this mailbox
			continue
		}

		mailboxes = append(mailboxes, fullMailbox)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating mailboxes: %w", err)
	}

	return mailboxes, nil
}
