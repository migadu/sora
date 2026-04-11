package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
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
				log.Printf("Database: custom keyword '%s' exceeds maximum length of %d, skipping.", flagStr, FlagsMaxKeywordLength)
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
		SELECT ms.flags, ms.custom_flags FROM messages m
		JOIN message_state ms ON m.id = ms.message_id
		WHERE m.uid = $1 AND m.mailbox_id = $2 AND m.expunged_at IS NULL
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
		log.Printf("Database: error unmarshalling custom_flags for UID %d (mailbox %d): %v. JSON: %s", messageUID, mailboxID, err, string(customFlagsJSON))
		return nil, fmt.Errorf("failed to unmarshal custom_flags for UID %d (mailbox %d): %w", messageUID, mailboxID, err)
	}

	// Convert custom keywords to imap.Flag and sanitize to remove invalid values
	// that may have been stored before validation was added (e.g., NIL, NULL)
	for _, kw := range customKeywords {
		allFlags = append(allFlags, imap.Flag(kw))
	}
	allFlags = helpers.SanitizeFlags(allFlags)

	return allFlags, nil
}

func (db *Database) SetMessageFlags(ctx context.Context, tx pgx.Tx, messageUID imap.UID, mailboxID int64, newFlags []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	start := time.Now()
	defer func() {
		status := "success"
		if err != nil {
			status = "error"
		}
		metrics.DBQueryDuration.WithLabelValues("flags_set", "write").Observe(time.Since(start).Seconds())
		metrics.DBQueriesTotal.WithLabelValues("flags_set", status, "write").Inc()
	}()

	systemFlagsToSet, customKeywordsToSet := SplitFlags(newFlags)
	bitwiseSystemFlags := FlagsToBitwise(systemFlagsToSet)
	customKeywordsJSON, err := json.Marshal(customKeywordsToSet)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal custom keywords for SetMessageFlags: %w", err)
	}
	err = tx.QueryRow(ctx, `
		UPDATE message_state ms
		SET flags = $1, custom_flags = $2, flags_changed_at = $3, updated_modseq = nextval('messages_modseq')
		FROM messages m
		WHERE ms.message_id = m.id AND m.uid = $4 AND ms.mailbox_id = $5 AND m.expunged_at IS NULL
		RETURNING COALESCE(ms.updated_modseq, m.created_modseq)
	`, bitwiseSystemFlags, customKeywordsJSON, time.Now(), messageUID, mailboxID).Scan(&modSeq)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to execute set message flags for UID %d in mailbox %d: %w", messageUID, mailboxID, err)
	}

	currentFlags, err := db.getAllFlagsForMessage(ctx, tx, messageUID, mailboxID)
	if err != nil {
		return nil, 0, err
	}

	return currentFlags, modSeq, nil
}

func (db *Database) AddMessageFlags(ctx context.Context, tx pgx.Tx, messageUID imap.UID, mailboxID int64, newFlags []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	systemFlagsToAdd, customKeywordsToAdd := SplitFlags(newFlags)
	hasCustom := len(customKeywordsToAdd) > 0
	var finalModSeq int64
	var hasUpdate bool

	if len(systemFlagsToAdd) > 0 {
		bitwiseSystemFlagsToAdd := FlagsToBitwise(systemFlagsToAdd)
		if hasCustom {
			// Custom keywords update follows — skip modseq bump here to avoid double increment
			ct, execErr := tx.Exec(ctx, `
				UPDATE message_state ms
				SET flags = ms.flags | $1, flags_changed_at = $2
				FROM messages m
				WHERE ms.message_id = m.id AND m.uid = $3 AND ms.mailbox_id = $4 AND m.expunged_at IS NULL
			`, bitwiseSystemFlagsToAdd, time.Now(), messageUID, mailboxID)
			if execErr != nil {
				return nil, 0, fmt.Errorf("failed to add system flags for UID %d: %w", messageUID, execErr)
			}
			if ct.RowsAffected() == 0 {
				return nil, 0, fmt.Errorf("message UID %d in mailbox %d not found (may be expunged or moved)", messageUID, mailboxID)
			}
		} else {
			// Only system flags to update — bump modseq here
			err = tx.QueryRow(ctx, `
				UPDATE message_state ms
				SET flags = ms.flags | $1, flags_changed_at = $2, updated_modseq = nextval('messages_modseq')
				FROM messages m
				WHERE ms.message_id = m.id AND m.uid = $3 AND ms.mailbox_id = $4 AND m.expunged_at IS NULL
				RETURNING COALESCE(ms.updated_modseq, m.created_modseq)
			`, bitwiseSystemFlagsToAdd, time.Now(), messageUID, mailboxID).Scan(&finalModSeq)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, 0, fmt.Errorf("message UID %d in mailbox %d not found (may be expunged or moved)", messageUID, mailboxID)
				}
				return nil, 0, fmt.Errorf("failed to add system flags for UID %d: %w", messageUID, err)
			}
		}
		hasUpdate = true
	}

	if hasCustom {
		// This is always the last update — bump modseq here
		err = tx.QueryRow(ctx, `
			UPDATE message_state ms
			SET custom_flags = (
				SELECT COALESCE(jsonb_agg(DISTINCT flag_element ORDER BY flag_element), '[]'::jsonb) -- ORDER BY for deterministic output if needed
				FROM (
					SELECT jsonb_array_elements_text(ms2.custom_flags) AS flag_element FROM message_state ms2 WHERE ms2.message_id = ms.message_id
					UNION ALL
					SELECT unnest($3::text[]) AS flag_element
				) AS combined_flags
			), flags_changed_at = $4, updated_modseq = nextval('messages_modseq')
			FROM messages m
			WHERE ms.message_id = m.id AND m.uid = $1 AND ms.mailbox_id = $2 AND m.expunged_at IS NULL
			RETURNING COALESCE(ms.updated_modseq, m.created_modseq)
		`, messageUID, mailboxID, customKeywordsToAdd, time.Now()).Scan(&finalModSeq)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, 0, fmt.Errorf("message UID %d in mailbox %d not found (may be expunged or moved)", messageUID, mailboxID)
			}
			return nil, 0, fmt.Errorf("failed to add custom keywords for UID %d: %w", messageUID, err)
		}
		hasUpdate = true
	}

	if !hasUpdate {
		// Neither update ran - this shouldn't happen if newFlags is non-empty
		return nil, 0, fmt.Errorf("no flags to add for UID %d", messageUID)
	}

	currentFlags, err := db.getAllFlagsForMessage(ctx, tx, messageUID, mailboxID)
	if err != nil {
		return nil, 0, err
	}

	return currentFlags, finalModSeq, nil
}

func (db *Database) RemoveMessageFlags(ctx context.Context, tx pgx.Tx, messageUID imap.UID, mailboxID int64, flagsToRemove []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	systemFlagsToRemove, customKeywordsToRemove := SplitFlags(flagsToRemove)
	var finalModSeq int64
	var hasUpdate bool

	hasCustom := len(customKeywordsToRemove) > 0

	if len(systemFlagsToRemove) > 0 {
		bitwiseSystemFlagsToRemove := FlagsToBitwise(systemFlagsToRemove)
		negatedSystemFlags := ^bitwiseSystemFlagsToRemove // Bitwise NOT to clear these flags
		if hasCustom {
			// Custom keywords update follows — skip modseq bump here to avoid double increment
			ct, execErr := tx.Exec(ctx, `
				UPDATE message_state ms
				SET flags = ms.flags & $1, flags_changed_at = $2
				FROM messages m
				WHERE ms.message_id = m.id AND m.uid = $3 AND ms.mailbox_id = $4 AND m.expunged_at IS NULL
			`, negatedSystemFlags, time.Now(), messageUID, mailboxID)
			if execErr != nil {
				return nil, 0, fmt.Errorf("failed to remove system flags for UID %d: %w", messageUID, execErr)
			}
			if ct.RowsAffected() == 0 {
				return nil, 0, fmt.Errorf("message UID %d in mailbox %d not found (may be expunged or moved)", messageUID, mailboxID)
			}
		} else {
			// Only system flags to update — bump modseq here
			err = tx.QueryRow(ctx, `
				UPDATE message_state ms
				SET flags = ms.flags & $1, flags_changed_at = $2, updated_modseq = nextval('messages_modseq')
				FROM messages m
				WHERE ms.message_id = m.id AND m.uid = $3 AND ms.mailbox_id = $4 AND m.expunged_at IS NULL
				RETURNING COALESCE(ms.updated_modseq, m.created_modseq)
			`, negatedSystemFlags, time.Now(), messageUID, mailboxID).Scan(&finalModSeq)
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil, 0, fmt.Errorf("message UID %d in mailbox %d not found (may be expunged or moved)", messageUID, mailboxID)
				}
				return nil, 0, fmt.Errorf("failed to remove system flags for UID %d: %w", messageUID, err)
			}
		}
		hasUpdate = true
	}

	if hasCustom {
		// This is always the last update — bump modseq here
		err = tx.QueryRow(ctx, `
			UPDATE message_state ms
			SET custom_flags = ms.custom_flags - $3::text[],
			    flags_changed_at = $4, updated_modseq = nextval('messages_modseq')
			FROM messages m
			WHERE ms.message_id = m.id AND m.uid = $1 AND ms.mailbox_id = $2 AND m.expunged_at IS NULL
			RETURNING COALESCE(ms.updated_modseq, m.created_modseq)
		`, messageUID, mailboxID, customKeywordsToRemove, time.Now()).Scan(&finalModSeq)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, 0, fmt.Errorf("message UID %d in mailbox %d not found (may be expunged or moved)", messageUID, mailboxID)
			}
			return nil, 0, fmt.Errorf("failed to remove custom keywords for UID %d: %w", messageUID, err)
		}
		hasUpdate = true
	}

	if !hasUpdate {
		// Neither update ran - this shouldn't happen if flagsToRemove is non-empty
		return nil, 0, fmt.Errorf("no flags to remove for UID %d", messageUID)
	}

	currentFlags, err := db.getAllFlagsForMessage(ctx, tx, messageUID, mailboxID)
	if err != nil {
		return nil, 0, err
	}

	return currentFlags, finalModSeq, nil
}

// GetUniqueCustomFlagsForMailbox retrieves a list of unique custom flags
// (keywords) currently in use for messages within a specific mailbox.
// It excludes system flags (those starting with '\').
// Also sanitizes flags to remove invalid values (NIL, NULL, etc.) that may have been stored.
//
// OPTIMIZATION: Uses the custom_flags_cache column in mailbox_stats (maintained by trigger)
// instead of scanning all messages with JSONB LATERAL expansion.
// Falls back to the full scan query if the cache is not available.
func (db *Database) GetUniqueCustomFlagsForMailbox(ctx context.Context, mailboxID int64) ([]string, error) {
	// Try the cached version first (maintained by trigger in migration 009)
	var cachedFlagsJSON []byte
	err := db.GetReadPool().QueryRow(ctx, `
		SELECT custom_flags_cache FROM mailbox_stats WHERE mailbox_id = $1
	`, mailboxID).Scan(&cachedFlagsJSON)

	if err == nil && cachedFlagsJSON != nil {
		var cachedFlags []string
		if err := json.Unmarshal(cachedFlagsJSON, &cachedFlags); err == nil {
			// Sanitize and return cached flags
			var flags []imap.Flag
			for _, f := range cachedFlags {
				flags = append(flags, imap.Flag(f))
			}
			sanitizedFlags := helpers.SanitizeFlags(flags)
			result := make([]string, len(sanitizedFlags))
			for i, f := range sanitizedFlags {
				result[i] = string(f)
			}
			return result, nil
		}
		// If unmarshal fails, fall through to the full scan
		log.Printf("Database: failed to unmarshal custom_flags_cache for mailbox %d, falling back to full scan", mailboxID)
	}

	// Fallback: full scan query (used if cache column doesn't exist yet or cache is NULL)
	query := `
		SELECT DISTINCT flag
		FROM message_state ms CROSS JOIN LATERAL jsonb_array_elements_text(ms.custom_flags) AS elem(flag)
		JOIN messages m ON m.id = ms.message_id
		WHERE ms.mailbox_id = $1
		  AND m.expunged_at IS NULL
		  AND flag !~ '^\\';
	`
	rows, err := db.GetReadPool().Query(ctx, query, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("failed to query unique custom flags for mailbox %d: %w", mailboxID, err)
	}
	defer rows.Close()

	var flags []imap.Flag
	for rows.Next() {
		var flag string
		if err := rows.Scan(&flag); err != nil {
			return nil, fmt.Errorf("failed to scan custom flag for mailbox %d: %w", mailboxID, err)
		}
		flags = append(flags, imap.Flag(flag))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating unique custom flags for mailbox %d: %w", mailboxID, err)
	}

	// Sanitize to remove invalid flags (NIL, NULL, etc.) that may have been stored
	sanitizedFlags := helpers.SanitizeFlags(flags)

	// Convert back to []string for return
	result := make([]string, len(sanitizedFlags))
	for i, f := range sanitizedFlags {
		result[i] = string(f)
	}

	return result, nil
}
