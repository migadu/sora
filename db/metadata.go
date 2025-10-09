package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
)

// MetadataErrorType represents the type of metadata error.
type MetadataErrorType int

const (
	MetadataErrMaxSize       MetadataErrorType = iota // Entry value too large
	MetadataErrTooMany                                // Too many entries
	MetadataErrQuotaExceeded                          // Total quota exceeded
	MetadataErrNoPrivate                              // No permission for /private/ entries
)

// MetadataError represents a metadata operation error with RFC 5464 response codes.
type MetadataError struct {
	Type    MetadataErrorType
	Message string
}

func (e *MetadataError) Error() string {
	return e.Message
}

// ResponseCode returns the RFC 5464 METADATA response code for this error.
func (e *MetadataError) ResponseCode() string {
	switch e.Type {
	case MetadataErrMaxSize:
		return "METADATA MAXSIZE"
	case MetadataErrTooMany:
		return "METADATA TOOMANY"
	case MetadataErrQuotaExceeded:
		return "METADATA TOOMANY" // Use TOOMANY for quota as well
	case MetadataErrNoPrivate:
		return "METADATA NOPRIVATE"
	default:
		return "NO"
	}
}

// GetMetadata retrieves server or mailbox metadata entries.
// If mailboxID is nil, retrieves server metadata.
// entryNames is a list of entry paths to retrieve.
// options controls depth and size limits.
func (db *Database) GetMetadata(ctx context.Context, tx pgx.Tx, accountID int64, mailboxID *int64, entryNames []string, options *imap.GetMetadataOptions) (*imap.GetMetadataData, error) {
	if len(entryNames) == 0 {
		return &imap.GetMetadataData{
			Entries: make(map[string]*[]byte),
		}, nil
	}

	// Default depth is 0 (exact match only)
	depth := imap.GetMetadataDepthZero
	if options != nil && options.Depth != imap.GetMetadataDepthZero {
		depth = options.Depth
	}

	// Build query based on depth
	var query string
	var args []interface{}

	switch depth {
	case imap.GetMetadataDepthZero:
		// Exact match only
		query = `
			SELECT entry_name, entry_value
			FROM metadata
			WHERE account_id = $1
			  AND mailbox_id IS NOT DISTINCT FROM $2
			  AND entry_name = ANY($3)
			ORDER BY entry_name
		`
		args = []interface{}{accountID, mailboxID, entryNames}

	case imap.GetMetadataDepthOne:
		// Match exact entries and their immediate children
		var conditions []string
		argIdx := 3
		args = []interface{}{accountID, mailboxID}

		for _, name := range entryNames {
			// Exact match
			conditions = append(conditions, fmt.Sprintf("entry_name = $%d", argIdx))
			args = append(args, name)
			argIdx++

			// Immediate children (one level deeper, separated by /)
			conditions = append(conditions, fmt.Sprintf("entry_name LIKE $%d AND entry_name NOT LIKE $%d", argIdx, argIdx+1))
			args = append(args, name+"/%", name+"/%/%")
			argIdx += 2
		}

		query = fmt.Sprintf(`
			SELECT entry_name, entry_value
			FROM metadata
			WHERE account_id = $1
			  AND mailbox_id IS NOT DISTINCT FROM $2
			  AND (%s)
			ORDER BY entry_name
		`, strings.Join(conditions, " OR "))

	case imap.GetMetadataDepthInfinity:
		// Match exact entries and all descendants
		var conditions []string
		argIdx := 3
		args = []interface{}{accountID, mailboxID}

		for _, name := range entryNames {
			// Exact match or any descendant
			conditions = append(conditions, fmt.Sprintf("(entry_name = $%d OR entry_name LIKE $%d)", argIdx, argIdx+1))
			args = append(args, name, name+"/%")
			argIdx += 2
		}

		query = fmt.Sprintf(`
			SELECT entry_name, entry_value
			FROM metadata
			WHERE account_id = $1
			  AND mailbox_id IS NOT DISTINCT FROM $2
			  AND (%s)
			ORDER BY entry_name
		`, strings.Join(conditions, " OR "))
	}

	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query metadata: %w", err)
	}
	defer rows.Close()

	result := &imap.GetMetadataData{
		Entries: make(map[string]*[]byte),
	}

	totalSize := uint32(0)
	for rows.Next() {
		var entryName string
		var entryValue []byte

		if err := rows.Scan(&entryName, &entryValue); err != nil {
			return nil, fmt.Errorf("failed to scan metadata row: %w", err)
		}

		// Check MAXSIZE limit if specified
		if options != nil && options.MaxSize != nil {
			entrySize := uint32(len(entryValue))
			if totalSize+entrySize > *options.MaxSize {
				// TODO: Return METADATA response code with size exceeded
				break
			}
			totalSize += entrySize
		}

		// Store the value (nil means entry exists but has no value)
		if len(entryValue) > 0 {
			valueCopy := make([]byte, len(entryValue))
			copy(valueCopy, entryValue)
			result.Entries[entryName] = &valueCopy
		} else {
			result.Entries[entryName] = nil
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating metadata rows: %w", err)
	}

	return result, nil
}

// MetadataLimits holds configurable limits for metadata storage.
type MetadataLimits struct {
	MaxEntrySize         int // Maximum size in bytes for a single entry value
	MaxEntriesPerMailbox int // Maximum number of entries per mailbox
	MaxEntriesPerServer  int // Maximum number of server-level entries per account
	MaxTotalSize         int // Maximum total size in bytes for all metadata per account
}

// SetMetadata sets or removes server or mailbox metadata entries.
// If mailboxID is nil, sets server metadata.
// To remove an entry, set its value to nil.
// Returns ErrMetadataTooBig, ErrMetadataTooMany, or ErrMetadataQuotaExceeded if limits are exceeded.
func (db *Database) SetMetadata(ctx context.Context, tx pgx.Tx, accountID int64, mailboxID *int64, entries map[string]*[]byte, limits *MetadataLimits) error {
	if len(entries) == 0 {
		return nil
	}

	// If limits are provided and non-zero, enforce them
	if limits != nil && (limits.MaxEntrySize > 0 || limits.MaxEntriesPerMailbox > 0 || limits.MaxEntriesPerServer > 0 || limits.MaxTotalSize > 0) {
		// Check individual entry sizes (if limit is set)
		if limits.MaxEntrySize > 0 {
			for entryName, entryValue := range entries {
				if entryValue != nil && len(*entryValue) > limits.MaxEntrySize {
					return &MetadataError{
						Type:    MetadataErrMaxSize,
						Message: fmt.Sprintf("metadata entry %q exceeds max size of %d bytes", entryName, limits.MaxEntrySize),
					}
				}
			}
		}

		// Count existing entries (excluding ones we're about to delete)
		var currentCount int
		var currentTotalSize int64
		countQuery := `
			SELECT COUNT(*), COALESCE(SUM(LENGTH(entry_value)), 0)
			FROM metadata
			WHERE account_id = $1
			  AND mailbox_id IS NOT DISTINCT FROM $2
		`
		err := tx.QueryRow(ctx, countQuery, accountID, mailboxID).Scan(&currentCount, &currentTotalSize)
		if err != nil {
			return fmt.Errorf("failed to count existing metadata: %w", err)
		}

		// Calculate new counts (account for deletions and additions)
		newEntries := 0
		newTotalSize := int64(0)
		for _, entryValue := range entries {
			if entryValue != nil {
				newEntries++
				newTotalSize += int64(len(*entryValue))
			}
		}

		// Check entry count limit (if limits are set)
		if limits.MaxEntriesPerMailbox > 0 || limits.MaxEntriesPerServer > 0 {
			maxEntries := limits.MaxEntriesPerServer
			if mailboxID != nil && limits.MaxEntriesPerMailbox > 0 {
				maxEntries = limits.MaxEntriesPerMailbox
			}

			if maxEntries > 0 && currentCount+newEntries > maxEntries {
				return &MetadataError{
					Type:    MetadataErrTooMany,
					Message: fmt.Sprintf("too many metadata entries (limit: %d)", maxEntries),
				}
			}
		}

		// Check total size limit (per account, across all mailboxes)
		if limits.MaxTotalSize > 0 {
			var accountTotalSize int64
			sizeQuery := `
				SELECT COALESCE(SUM(LENGTH(entry_value)), 0)
				FROM metadata
				WHERE account_id = $1
			`
			err = tx.QueryRow(ctx, sizeQuery, accountID).Scan(&accountTotalSize)
			if err != nil {
				return fmt.Errorf("failed to calculate total metadata size: %w", err)
			}

			if int(accountTotalSize+newTotalSize) > limits.MaxTotalSize {
				return &MetadataError{
					Type:    MetadataErrQuotaExceeded,
					Message: fmt.Sprintf("metadata quota exceeded (limit: %d bytes)", limits.MaxTotalSize),
				}
			}
		}
	}

	for entryName, entryValue := range entries {
		if entryValue == nil {
			// Delete the entry
			_, err := tx.Exec(ctx, `
				DELETE FROM metadata
				WHERE account_id = $1
				  AND mailbox_id IS NOT DISTINCT FROM $2
				  AND entry_name = $3
			`, accountID, mailboxID, entryName)
			if err != nil {
				return fmt.Errorf("failed to delete metadata entry %q: %w", entryName, err)
			}
		} else {
			// Insert or update the entry
			_, err := tx.Exec(ctx, `
				INSERT INTO metadata (account_id, mailbox_id, entry_name, entry_value, updated_at)
				VALUES ($1, $2, $3, $4, NOW())
				ON CONFLICT (account_id, mailbox_id, entry_name)
				DO UPDATE SET
					entry_value = EXCLUDED.entry_value,
					updated_at = NOW()
			`, accountID, mailboxID, entryName, *entryValue)
			if err != nil {
				return fmt.Errorf("failed to set metadata entry %q: %w", entryName, err)
			}
		}
	}

	return nil
}

// DeleteMailboxMetadata removes all metadata entries for a mailbox.
// This should be called when a mailbox is deleted.
func (db *Database) DeleteMailboxMetadata(ctx context.Context, tx pgx.Tx, mailboxID int64) error {
	_, err := tx.Exec(ctx, `
		DELETE FROM metadata
		WHERE mailbox_id = $1
	`, mailboxID)
	if err != nil {
		return fmt.Errorf("failed to delete mailbox metadata: %w", err)
	}
	return nil
}

// DeleteAccountMetadata removes all metadata entries for an account.
// This should be called when an account is deleted (handled by CASCADE).
func (db *Database) DeleteAccountMetadata(ctx context.Context, tx pgx.Tx, accountID int64) error {
	_, err := tx.Exec(ctx, `
		DELETE FROM metadata
		WHERE account_id = $1
	`, accountID)
	if err != nil {
		return fmt.Errorf("failed to delete account metadata: %w", err)
	}
	return nil
}
