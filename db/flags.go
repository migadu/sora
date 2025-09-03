package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
)

// The maximum allowed keyword (custom flag) length
const FlagsMaxKeywordLength = 100

// splitFlags separates a list of IMAP flags into system flags (starting with '\')
// and custom keyword flags.
func SplitFlags(flags []imap.Flag) (systemFlags []imap.Flag, customKeywords []string) {
	for _, f := range flags {
		flagStr := string(f)
		if strings.HasPrefix(flagStr, "\\") {
			systemFlags = append(systemFlags, f)
		} else if flagStr != "" { // Ensure not to add empty strings as keywords
			// Per RFC 3501: "A keyword is an atom that does not begin with "\".
			// Keywords MUST NOT contain control characters or non-ASCII characters.
			// We assume valid keywords are passed from the IMAP layer.
			if len(flagStr) > FlagsMaxKeywordLength {
				log.Printf("[DB] custom keyword '%s' exceeds maximum length of %d, skipping.", flagStr, FlagsMaxKeywordLength)
				continue // Skip this keyword
			}
			customKeywords = append(customKeywords, flagStr)
		}
	}
	// Sort the custom keywords to ensure a canonical order before making them unique.
	// This makes the output of Compact deterministic and the stored JSONB array more consistent.
	slices.Sort(customKeywords)
	// Compact removes adjacent duplicates, resulting in a sorted slice of unique keywords.
	customKeywords = slices.Compact(customKeywords)
	if len(customKeywords) == 0 {
		// json.Marshal encodes nil lists as null instead of an empty array,
		// avoid this by allocating a zero-length slice
		customKeywords = []string{}
	}
	return
}

// getAllFlagsForMessage retrieves all system and custom flags for a given message.
// This function must be called within the same transaction as any preceding update
// to ensure it reads the latest state.
func (db *Database) getAllFlagsForMessage(ctx context.Context, tx pgx.Tx, messageUID imap.UID, mailboxID int64) ([]imap.Flag, error) {
	var bitwiseFlags int
	var customFlagsJSON []byte
	err := tx.QueryRow(ctx, `
		SELECT flags, custom_flags FROM messages
		WHERE uid = $1 AND mailbox_id = $2 AND expunged_at IS NULL
	`, messageUID, mailboxID).Scan(&bitwiseFlags, &customFlagsJSON)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Message might have been expunged or doesn't exist.
			return nil, fmt.Errorf("message UID %d in mailbox %d not found: %w", messageUID, mailboxID, err)
		}
		return nil, fmt.Errorf("failed to get flags for message UID %d in mailbox %d: %w", messageUID, mailboxID, err)
	}

	allFlags := BitwiseToFlags(bitwiseFlags)
	var customKeywords []string
	if err := json.Unmarshal(customFlagsJSON, &customKeywords); err != nil {
		log.Printf("[DB] error unmarshalling custom_flags for UID %d (mailbox %d): %v. JSON: %s", messageUID, mailboxID, err, string(customFlagsJSON))
		return nil, fmt.Errorf("failed to unmarshal custom_flags for UID %d (mailbox %d): %w", messageUID, mailboxID, err)
	}
	for _, kw := range customKeywords {
		allFlags = append(allFlags, imap.Flag(kw))
	}
	return allFlags, nil
}

func (db *Database) SetMessageFlags(ctx context.Context, messageUID imap.UID, mailboxID int64, newFlags []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	tx, err := db.BeginTx(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to begin transaction for SetMessageFlags: %w", err)
	}
	defer tx.Rollback(ctx)
	// Ensure modSeq is initialized in case of early error returns before it's set.

	systemFlagsToSet, customKeywordsToSet := SplitFlags(newFlags)
	bitwiseSystemFlags := FlagsToBitwise(systemFlagsToSet)
	customKeywordsJSON, err := json.Marshal(customKeywordsToSet)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal custom keywords for SetMessageFlags: %w", err)
	}
	err = tx.QueryRow(ctx, `
		UPDATE messages
		SET flags = $1, custom_flags = $2, flags_changed_at = $3, updated_modseq = nextval('messages_modseq')
		WHERE uid = $4 AND mailbox_id = $5 AND expunged_at IS NULL
		RETURNING COALESCE(updated_modseq, created_modseq)
	`, bitwiseSystemFlags, customKeywordsJSON, time.Now(), messageUID, mailboxID).Scan(&modSeq)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to execute set message flags for UID %d in mailbox %d: %w", messageUID, mailboxID, err)
	}

	currentFlags, err := db.getAllFlagsForMessage(ctx, tx, messageUID, mailboxID)
	if err != nil {
		return nil, 0, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, 0, fmt.Errorf("failed to commit transaction for SetMessageFlags: %w", err)
	}
	return currentFlags, modSeq, nil
}

func (db *Database) AddMessageFlags(ctx context.Context, messageUID imap.UID, mailboxID int64, newFlags []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	tx, err := db.BeginTx(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to begin transaction for AddMessageFlags: %w", err)
	}
	defer tx.Rollback(ctx)

	systemFlagsToAdd, customKeywordsToAdd := SplitFlags(newFlags)
	var currentModSeq sql.NullInt64 // Use sql.NullInt64 to handle potential NULL from RETURNING if no rows updated

	if len(systemFlagsToAdd) > 0 {
		bitwiseSystemFlagsToAdd := FlagsToBitwise(systemFlagsToAdd)
		_, err = tx.Exec(ctx, `
			UPDATE messages
			SET flags = flags | $1, flags_changed_at = $2, updated_modseq = nextval('messages_modseq')
			WHERE uid = $3 AND mailbox_id = $4 AND expunged_at IS NULL
		`, bitwiseSystemFlagsToAdd, time.Now(), messageUID, mailboxID)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to add system flags for UID %d: %w", messageUID, err)
		} // modSeq will be updated by the custom flags part or a final fetch if only system flags changed
	}

	if len(customKeywordsToAdd) > 0 {
		_, err = tx.Exec(ctx, `
			UPDATE messages
			SET custom_flags = (
				SELECT COALESCE(jsonb_agg(DISTINCT flag_element ORDER BY flag_element), '[]'::jsonb) -- ORDER BY for deterministic output if needed
				FROM (
					SELECT jsonb_array_elements_text(custom_flags) AS flag_element FROM messages WHERE uid = $1 AND mailbox_id = $2 AND expunged_at IS NULL
					UNION ALL
					SELECT unnest($3::text[]) AS flag_element
				) AS combined_flags
			), flags_changed_at = $4, updated_modseq = nextval('messages_modseq')
			WHERE uid = $1 AND mailbox_id = $2 AND expunged_at IS NULL
		`, messageUID, mailboxID, customKeywordsToAdd, time.Now())
		if err != nil {
			return nil, 0, fmt.Errorf("failed to add custom keywords for UID %d: %w", messageUID, err)
		}
	}

	// Fetch the final modSeq after all potential updates
	err = tx.QueryRow(ctx, `SELECT COALESCE(updated_modseq, created_modseq) FROM messages WHERE uid = $1 AND mailbox_id = $2 AND expunged_at IS NULL`, messageUID, mailboxID).Scan(&currentModSeq)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to retrieve final modseq for UID %d: %w", messageUID, err)
	}
	if !currentModSeq.Valid { // Should not happen if message exists
		return nil, 0, fmt.Errorf("modseq not found for UID %d after update", messageUID)
	}
	modSeq = currentModSeq.Int64

	currentFlags, err := db.getAllFlagsForMessage(ctx, tx, messageUID, mailboxID)
	if err != nil {
		return nil, 0, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, 0, fmt.Errorf("failed to commit transaction for AddMessageFlags: %w", err)
	}
	return currentFlags, modSeq, nil
}

func (db *Database) RemoveMessageFlags(ctx context.Context, messageUID imap.UID, mailboxID int64, flagsToRemove []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	tx, err := db.BeginTx(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to begin transaction for RemoveMessageFlags: %w", err)
	}
	defer tx.Rollback(ctx)

	systemFlagsToRemove, customKeywordsToRemove := SplitFlags(flagsToRemove)
	var currentModSeq sql.NullInt64

	if len(systemFlagsToRemove) > 0 {
		bitwiseSystemFlagsToRemove := FlagsToBitwise(systemFlagsToRemove)
		negatedSystemFlags := ^bitwiseSystemFlagsToRemove // Bitwise NOT to clear these flags
		_, err = tx.Exec(ctx, `
			UPDATE messages
			SET flags = flags & $1, flags_changed_at = $2, updated_modseq = nextval('messages_modseq')
			WHERE uid = $3 AND mailbox_id = $4 AND expunged_at IS NULL
		`, negatedSystemFlags, time.Now(), messageUID, mailboxID)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to remove system flags for UID %d: %w", messageUID, err)
		} // modSeq will be updated by the custom flags part or a final fetch
	}

	if len(customKeywordsToRemove) > 0 {
		// The '-' operator removes all occurrences of elements from the right-hand array.
		_, err = tx.Exec(ctx, `
			UPDATE messages
			SET custom_flags = custom_flags - $3::text[],
			    flags_changed_at = $4, updated_modseq = nextval('messages_modseq')
			WHERE uid = $1 AND mailbox_id = $2 AND expunged_at IS NULL
		`, messageUID, mailboxID, customKeywordsToRemove, time.Now())
		if err != nil {
			return nil, 0, fmt.Errorf("failed to remove custom keywords for UID %d: %w", messageUID, err)
		}
	}

	// Fetch the final modSeq after all potential updates
	err = tx.QueryRow(ctx, `SELECT COALESCE(updated_modseq, created_modseq) FROM messages WHERE uid = $1 AND mailbox_id = $2 AND expunged_at IS NULL`, messageUID, mailboxID).Scan(&currentModSeq)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to retrieve final modseq for UID %d: %w", messageUID, err)
	}
	if !currentModSeq.Valid { // Should not happen if message exists
		return nil, 0, fmt.Errorf("modseq not found for UID %d after update", messageUID)
	}
	modSeq = currentModSeq.Int64

	currentFlags, err := db.getAllFlagsForMessage(ctx, tx, messageUID, mailboxID)
	if err != nil {
		return nil, 0, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, 0, fmt.Errorf("failed to commit transaction for RemoveMessageFlags: %w", err)
	}
	return currentFlags, modSeq, nil
}

// GetUniqueCustomFlagsForMailbox retrieves a list of unique custom flags
// (keywords) currently in use for messages within a specific mailbox.
// It excludes system flags (those starting with '\').
func (db *Database) GetUniqueCustomFlagsForMailbox(ctx context.Context, mailboxID int64) ([]string, error) {
	query := `
		SELECT DISTINCT flag
		FROM messages CROSS JOIN LATERAL jsonb_array_elements_text(custom_flags) AS elem(flag)
		WHERE mailbox_id = $1
		  AND expunged_at IS NULL
		  AND flag NOT LIKE '\%';
	`
	rows, err := db.GetReadPool().Query(ctx, query, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("failed to query unique custom flags for mailbox %d: %w", mailboxID, err)
	}
	defer rows.Close()

	var flags []string
	for rows.Next() {
		var flag string
		if err := rows.Scan(&flag); err != nil {
			return nil, fmt.Errorf("failed to scan custom flag for mailbox %d: %w", mailboxID, err)
		}
		flags = append(flags, flag)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating unique custom flags for mailbox %d: %w", mailboxID, err)
	}
	return flags, nil
}
