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
	var args []any

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
		args = []any{accountID, mailboxID, entryNames}

	case imap.GetMetadataDepthOne:
		// Match exact entries and their immediate children
		var conditions []string
		argIdx := 3
		args = []any{accountID, mailboxID}

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
		args = []any{accountID, mailboxID}

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

	for rows.Next() {
		var entryName string
		var entryValue []byte

		if err := rows.Scan(&entryName, &entryValue); err != nil {
			return nil, fmt.Errorf("failed to scan metadata row: %w", err)
		}

		// Check MAXSIZE limit if specified
		if options != nil && options.MaxSize != nil {
			entrySize := uint32(len(entryValue))
			if entrySize > *options.MaxSize {
				if entrySize > result.LongEntries {
					result.LongEntries = entrySize
				}
				continue
			}
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

		// Look up the CURRENT stored size of every entry named in this request
		// (0 if absent) so overwrites and deletes are not miscounted against the
		// limits. An overwrite of an existing entry is net-zero for the count and a
		// size delta; deleting an existing entry frees a slot and its size. The
		// previous code counted every non-nil request entry as a brand-new addition,
		// so overwriting an entry at the limit was wrongly rejected as TOOMANY.
		requestedNames := make([]string, 0, len(entries))
		for entryName := range entries {
			requestedNames = append(requestedNames, entryName)
		}
		existingSizes := make(map[string]int64, len(requestedNames))
		existingRows, err := tx.Query(ctx, `
			SELECT entry_name, COALESCE(LENGTH(entry_value), 0)
			FROM metadata
			WHERE account_id = $1
			  AND mailbox_id IS NOT DISTINCT FROM $2
			  AND entry_name = ANY($3)
		`, accountID, mailboxID, requestedNames)
		if err != nil {
			return fmt.Errorf("failed to look up existing metadata: %w", err)
		}
		for existingRows.Next() {
			var name string
			var size int64
			if err := existingRows.Scan(&name, &size); err != nil {
				existingRows.Close()
				return fmt.Errorf("failed to scan existing metadata: %w", err)
			}
			existingSizes[name] = size
		}
		existingRows.Close()
		if err := existingRows.Err(); err != nil {
			return fmt.Errorf("error iterating existing metadata: %w", err)
		}

		// Check entry count limit (if limits are set). Only genuinely new entries
		// add to the count; deleting an existing entry frees a slot.
		if limits.MaxEntriesPerMailbox > 0 || limits.MaxEntriesPerServer > 0 {
			maxEntries := limits.MaxEntriesPerServer
			if mailboxID != nil && limits.MaxEntriesPerMailbox > 0 {
				maxEntries = limits.MaxEntriesPerMailbox
			}

			if maxEntries > 0 {
				var currentCount int
				if err := tx.QueryRow(ctx, `
					SELECT COUNT(*)
					FROM metadata
					WHERE account_id = $1
					  AND mailbox_id IS NOT DISTINCT FROM $2
				`, accountID, mailboxID).Scan(&currentCount); err != nil {
					return fmt.Errorf("failed to count existing metadata: %w", err)
				}

				additions, deletions := 0, 0
				for entryName, entryValue := range entries {
					_, present := existingSizes[entryName]
					switch {
					case entryValue != nil && !present:
						additions++
					case entryValue == nil && present:
						deletions++
					}
				}

				if currentCount+additions-deletions > maxEntries {
					return &MetadataError{
						Type:    MetadataErrTooMany,
						Message: fmt.Sprintf("too many metadata entries (limit: %d)", maxEntries),
					}
				}
			}
		}

		// Check total size limit (per account, across all mailboxes). Add each new
		// value's size and subtract the old size of any entry being overwritten or
		// deleted in this request, so an overwrite only counts its net delta.
		if limits.MaxTotalSize > 0 {
			var accountTotalSize int64
			if err := tx.QueryRow(ctx, `
				SELECT COALESCE(SUM(LENGTH(entry_value)), 0)
				FROM metadata
				WHERE account_id = $1
			`, accountID).Scan(&accountTotalSize); err != nil {
				return fmt.Errorf("failed to calculate total metadata size: %w", err)
			}

			sizeDelta := int64(0)
			for entryName, entryValue := range entries {
				newSize := int64(0)
				if entryValue != nil {
					newSize = int64(len(*entryValue))
				}
				sizeDelta += newSize - existingSizes[entryName] // existingSizes[name] is 0 if absent
			}

			if accountTotalSize+sizeDelta > int64(limits.MaxTotalSize) {
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
		} else if mailboxID == nil {
			// Server-scope entry (mailbox_id IS NULL). NULLs are DISTINCT under
			// the base UNIQUE constraint, so target the partial unique index
			// metadata_unique_server_entry (account_id, entry_name) instead.
			_, err := tx.Exec(ctx, `
				INSERT INTO metadata (account_id, mailbox_id, entry_name, entry_value, updated_at)
				VALUES ($1, NULL, $2, $3, NOW())
				ON CONFLICT (account_id, entry_name) WHERE mailbox_id IS NULL
				DO UPDATE SET
					entry_value = EXCLUDED.entry_value,
					updated_at = NOW()
			`, accountID, entryName, *entryValue)
			if err != nil {
				return fmt.Errorf("failed to set server metadata entry %q: %w", entryName, err)
			}
		} else {
			// Mailbox-scope entry: mailbox_id IS NOT NULL, so the base
			// UNIQUE(account_id, mailbox_id, entry_name) constraint applies.
			_, err := tx.Exec(ctx, `
				INSERT INTO metadata (account_id, mailbox_id, entry_name, entry_value, updated_at)
				VALUES ($1, $2, $3, $4, NOW())
				ON CONFLICT (account_id, mailbox_id, entry_name)
				DO UPDATE SET
					entry_value = EXCLUDED.entry_value,
					updated_at = NOW()
			`, accountID, *mailboxID, entryName, *entryValue)
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
