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
			s.Log("[GETMETADATA] failed to acquire read lock")
			return nil, fmt.Errorf("failed to acquire session lock")
		}
		defer release()

		dbMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, s.UserID(), mailbox)
		if err != nil {
			if err == pgx.ErrNoRows {
				return nil, fmt.Errorf("mailbox not found: %s", mailbox)
			}
			return nil, fmt.Errorf("failed to get mailbox: %w", err)
		}
		mailboxID = &dbMailbox.ID
		mailboxName = dbMailbox.Name
	}

	// Fetch metadata from database
	result, err := s.server.rdb.GetMetadataWithRetry(s.ctx, s.UserID(), mailboxID, entries, options)
	if err != nil {
		s.Log("[GETMETADATA] failed to get metadata: %v", err)
		return nil, fmt.Errorf("failed to get metadata: %w", err)
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
			s.Log("[SETMETADATA] failed to acquire read lock")
			return fmt.Errorf("failed to acquire session lock")
		}
		defer release()

		dbMailbox, err := s.server.rdb.GetMailboxByNameWithRetry(s.ctx, s.UserID(), mailbox)
		if err != nil {
			if err == pgx.ErrNoRows {
				return fmt.Errorf("mailbox not found: %s", mailbox)
			}
			return fmt.Errorf("failed to get mailbox: %w", err)
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
	err := s.server.rdb.SetMetadataWithRetry(s.ctx, s.UserID(), mailboxID, entries, limits)
	if err != nil {
		// Check if it's a metadata-specific error
		var metaErr *db.MetadataError
		if errors.As(err, &metaErr) {
			s.Log("[SETMETADATA] metadata limit exceeded: %v", metaErr)
			// Return the error with the proper response code
			// The go-imap library will handle converting this to the proper IMAP response
			return fmt.Errorf("[%s] %s", metaErr.ResponseCode(), metaErr.Message)
		}

		s.Log("[SETMETADATA] failed to set metadata: %v", err)
		return fmt.Errorf("failed to set metadata: %w", err)
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
