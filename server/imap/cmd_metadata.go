package imap

import (
	"errors"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
)

// GetMetadata implements the GETMETADATA command (RFC 5464).
// If mailbox is empty string "", retrieves server metadata.
func (s *IMAPSession) GetMetadata(mailbox string, entries []string, options *imap.GetMetadataOptions) (*imap.GetMetadataData, error) {
	// Validate entry names
	for _, entry := range entries {
		if err := validateMetadataEntry(entry); err != nil {
			return nil, err
		}
	}

	var mailboxID *int64
	var mailboxName string

	// If mailbox is specified, look it up
	if mailbox != "" {
		acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
		if !acquired {
			s.DebugLog("[GETMETADATA] failed to acquire read lock")
			return nil, fmt.Errorf("failed to acquire session lock")
		}
		defer release()

		dbMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, s.AccountID(), mailbox)
		if err != nil {
			if err == pgx.ErrNoRows {
				return nil, fmt.Errorf("mailbox not found: %s", mailbox)
			}
			return nil, fmt.Errorf("failed to get mailbox: %w", err)
		}

		// Check ACL permissions - requires 'r' (read) right for mailbox metadata
		hasReadRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, dbMailbox.ID, s.AccountID(), 'r')
		if err != nil {
			return nil, fmt.Errorf("failed to check read permission: %w", err)
		}
		if !hasReadRight {
			s.DebugLog("[GETMETADATA] user does not have read permission on mailbox '%s'", mailbox)
			return nil, fmt.Errorf("you do not have permission to get metadata for this mailbox")
		}

		mailboxID = &dbMailbox.ID
		mailboxName = dbMailbox.Name
	}

	// Fetch metadata from database
	result, err := s.server.rdb.GetMetadataWithRetry(s.ctx, s.AccountID(), mailboxID, entries, options)
	if err != nil {
		s.DebugLog("[GETMETADATA] failed to get metadata: %v", err)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: fmt.Sprintf("failed to get metadata: %v", err),
		}
	}

	result.Mailbox = mailboxName
	return result, nil
}

// SetMetadata implements the SETMETADATA command (RFC 5464).
// If mailbox is empty string "", sets server metadata.
// To remove an entry, set its value to nil.
func (s *IMAPSession) SetMetadata(mailbox string, entries map[string]*[]byte) error {
	// Validate entry names and check permissions
	for entryName := range entries {
		if err := validateMetadataEntry(entryName); err != nil {
			return err
		}

		// Check if entry is writable (entries under /shared/ require special permission)
		if strings.HasPrefix(entryName, "/shared/") {
			// For now, allow all /shared/ entries
			// In a production system, you'd check user permissions here
		} else if !strings.HasPrefix(entryName, "/private/") {
			return fmt.Errorf("invalid metadata entry: must start with /private/ or /shared/")
		}
	}

	var mailboxID *int64

	// If mailbox is specified, look it up
	if mailbox != "" {
		acquired, release := s.mutexHelper.AcquireReadLockWithTimeout()
		if !acquired {
			s.DebugLog("[SETMETADATA] failed to acquire read lock")
			return fmt.Errorf("failed to acquire session lock")
		}
		defer release()

		dbMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, s.AccountID(), mailbox)
		if err != nil {
			if err == pgx.ErrNoRows {
				return fmt.Errorf("mailbox not found: %s", mailbox)
			}
			return fmt.Errorf("failed to get mailbox: %w", err)
		}

		// Check ACL permissions
		// For /shared entries, requires 'w' (write) right
		// For /private entries, requires 'l' (lookup) right (implicit - user can access mailbox)
		needsWrite := false
		for entryName := range entries {
			if strings.HasPrefix(entryName, "/shared/") {
				needsWrite = true
				break
			}
		}

		if needsWrite {
			hasWriteRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, dbMailbox.ID, s.AccountID(), 'w')
			if err != nil {
				return fmt.Errorf("failed to check write permission: %w", err)
			}
			if !hasWriteRight {
				s.DebugLog("[SETMETADATA] user does not have write permission on mailbox '%s'", mailbox)
				return fmt.Errorf("you do not have permission to set shared metadata for this mailbox")
			}
		} else {
			// For /private entries, just verify user has lookup permission (already verified by GetMailboxByName)
			hasLookupRight, err := s.server.rdb.CheckMailboxPermissionWithRetry(s.ctx, dbMailbox.ID, s.AccountID(), 'l')
			if err != nil {
				return fmt.Errorf("failed to check lookup permission: %w", err)
			}
			if !hasLookupRight {
				s.DebugLog("[SETMETADATA] user does not have lookup permission on mailbox '%s'", mailbox)
				return fmt.Errorf("you do not have permission to set metadata for this mailbox")
			}
		}

		mailboxID = &dbMailbox.ID
	}

	// Prepare metadata limits from server config
	limits := &db.MetadataLimits{
		MaxEntrySize:         s.server.metadataMaxEntrySize,
		MaxEntriesPerMailbox: s.server.metadataMaxEntriesPerMailbox,
		MaxEntriesPerServer:  s.server.metadataMaxEntriesPerServer,
		MaxTotalSize:         s.server.metadataMaxTotalSize,
	}

	// Set metadata in database with limit enforcement
	err := s.server.rdb.SetMetadataWithRetry(s.ctx, s.AccountID(), mailboxID, entries, limits)
	if err != nil {
		// Check if it's a metadata-specific error
		var metaErr *db.MetadataError
		if errors.As(err, &metaErr) {
			s.DebugLog("[SETMETADATA] metadata limit exceeded: %v", metaErr)

			// Map MetadataError types to proper IMAP response codes
			var responseCode imap.ResponseCode
			switch metaErr.Type {
			case db.MetadataErrMaxSize:
				responseCode = imap.ResponseCodeTooBig
			case db.MetadataErrTooMany, db.MetadataErrQuotaExceeded:
				responseCode = imap.ResponseCodeTooMany
			case db.MetadataErrNoPrivate:
				responseCode = imap.ResponseCodeNoPrivate
			default:
				responseCode = imap.ResponseCodeLimit
			}

			// Return proper IMAP error with response code
			return &imap.Error{
				Type: imap.StatusResponseTypeNo,
				Code: responseCode,
				Text: metaErr.Message,
			}
		}

		s.DebugLog("[SETMETADATA] failed to set metadata: %v", err)
		return &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: fmt.Sprintf("failed to set metadata: %v", err),
		}
	}

	return nil
}

// validateMetadataEntry validates a metadata entry name according to RFC 5464.
// Entry names must start with /private/ or /shared/ and contain valid characters.
func validateMetadataEntry(entry string) error {
	if entry == "" {
		return fmt.Errorf("metadata entry name cannot be empty")
	}

	if !strings.HasPrefix(entry, "/private/") && !strings.HasPrefix(entry, "/shared/") {
		return fmt.Errorf("metadata entry must start with /private/ or /shared/")
	}

	// Entry names should contain only valid characters
	// RFC 5464 says: astring (any IMAP astring)
	// We allow alphanumeric, slash, dash, underscore, dot
	for _, ch := range entry {
		if !((ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '/' || ch == '-' || ch == '_' || ch == '.') {
			return fmt.Errorf("metadata entry contains invalid character: %c", ch)
		}
	}

	return nil
}
