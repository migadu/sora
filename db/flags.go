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

// foldKeyword returns the case-insensitive identity key for a keyword.
// Per RFC 9051 §2.3.2, keyword matching is case-insensitive, so two keywords
// that differ only in case (e.g. "WAREHOUSING" and "warehousing") are the same
// keyword and must never be stored or advertised as two distinct values.
func foldKeyword(kw string) string {
	return strings.ToLower(kw)
}

// dedupKeywordsByFold collapses case-variants of the same keyword to a single
// representative (the lexicographically smallest case, for determinism), so a
// mailbox never advertises e.g. both "WAREHOUSING" and "warehousing" in its
// FLAGS list (RFC 9051 §2.3.2). Order of the result is otherwise preserved.
// Post-migration the stored data holds a single case per keyword, so this is a
// no-op safety net that also covers cross-mailbox COPY/MOVE and any raced write.
func dedupKeywordsByFold(in []string) []string {
	if len(in) < 2 {
		return in
	}
	// First pass: choose the representative case per fold key.
	rep := make(map[string]string, len(in))
	for _, kw := range in {
		key := foldKeyword(kw)
		if cur, ok := rep[key]; !ok || kw < cur {
			rep[key] = kw
		}
	}
	// Second pass: emit each fold key once, in first-seen order.
	seen := make(map[string]struct{}, len(rep))
	out := make([]string, 0, len(rep))
	for _, kw := range in {
		key := foldKeyword(kw)
		if _, done := seen[key]; done {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, rep[key])
	}
	return out
}

// mailboxKeywordCanonicalMap returns a fold(keyword) -> canonical-case map of the
// keywords already known for a mailbox, read from the custom_flags_cache registry
// in mailbox_stats (maintained by the stats triggers). The read happens inside the
// caller's transaction so concurrent flag writes observe a consistent registry.
//
// A missing stats row, NULL/empty cache, or unmarshal error yields an empty map
// (treated as "no keywords known yet") rather than failing the flag write.
func (db *Database) mailboxKeywordCanonicalMap(ctx context.Context, tx pgx.Tx, mailboxID int64) (map[string]string, error) {
	var cacheJSON []byte
	var err error
	if tx != nil {
		err = tx.QueryRow(ctx, `SELECT custom_flags_cache FROM mailbox_stats WHERE mailbox_id = $1`, mailboxID).Scan(&cacheJSON)
	} else {
		err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `SELECT custom_flags_cache FROM mailbox_stats WHERE mailbox_id = $1`, mailboxID).Scan(&cacheJSON)
	}
	canonical := make(map[string]string)
	if errors.Is(err, pgx.ErrNoRows) {
		return canonical, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read custom_flags_cache for mailbox %d: %w", mailboxID, err)
	}
	if len(cacheJSON) == 0 {
		return canonical, nil
	}
	var existing []string
	if err := json.Unmarshal(cacheJSON, &existing); err != nil {
		// A malformed cache must not break flag writes; treat as an empty registry.
		log.Printf("Database: failed to unmarshal custom_flags_cache for mailbox %d: %v", mailboxID, err)
		return canonical, nil
	}
	for _, e := range existing {
		if e == "" || strings.HasPrefix(e, "\\") {
			continue
		}
		key := foldKeyword(e)
		// Legacy/raced caches may still hold >1 case for a keyword; pick a stable
		// representative (lexicographically smallest) so the result is deterministic.
		// Post-migration the cache holds a single case per keyword, so this is a no-op.
		if cur, ok := canonical[key]; !ok || e < cur {
			canonical[key] = e
		}
	}
	return canonical, nil
}

// canonicalizeKeywords folds each keyword onto the case already established for it
// in the mailbox, implementing case-insensitive keyword identity (RFC 9051 §2.3.2).
// The first case seen for a keyword in a mailbox is its canonical form; later
// references in any other case are mapped onto it. A keyword with no existing
// variant is returned unchanged and establishes the canonical case going forward.
//
// keywords must already be split out from system flags (no '\'-prefixed values).
// Returns a sorted, duplicate-free slice (matching SplitFlags' output contract):
// folding two input cases onto one canonical value can introduce duplicates.
//
// Callers should only invoke this when there is at least one custom keyword; an
// empty input returns immediately without touching the database.
func (db *Database) canonicalizeKeywords(ctx context.Context, tx pgx.Tx, mailboxID int64, keywords []string) ([]string, error) {
	if len(keywords) == 0 {
		return keywords, nil
	}

	canonical, err := db.mailboxKeywordCanonicalMap(ctx, tx, mailboxID)
	if err != nil {
		return nil, err
	}

	return foldKeywordsWithMap(canonical, keywords), nil
}

// foldKeywordsWithMap folds keywords onto the canonical case held in `canonical`
// (fold-key -> canonical-case). A keyword with no entry registers its own case as
// the canonical one (first-seen wins) by mutating the map, so the SAME map can be
// threaded across many messages — e.g. a single-mailbox import batch or a MOVE of
// several messages — to keep every message's keyword case consistent without a
// per-message database round-trip.
//
// keywords must already be split out from system flags (no '\'-prefixed values).
// Returns a sorted, duplicate-free slice (matching SplitFlags' output contract).
func foldKeywordsWithMap(canonical map[string]string, keywords []string) []string {
	if len(keywords) == 0 {
		return keywords
	}
	out := make([]string, 0, len(keywords))
	for _, kw := range keywords {
		key := foldKeyword(kw)
		if c, ok := canonical[key]; ok {
			out = append(out, c)
		} else {
			canonical[key] = kw
			out = append(out, kw)
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	return out
}

// resolveMessageID resolves a (mailbox_id, uid) pair to a message_id using
// the unique index on messages(mailbox_id, uid). This decouples flag updates
// from the messages table, enabling direct PK updates on message_state
// without cross-table UPDATE ... FROM joins that cause lock contention
// under high concurrency.
func (db *Database) resolveMessageID(ctx context.Context, tx pgx.Tx, messageUID imap.UID, mailboxID int64) (int64, error) {
	var messageID int64
	err := tx.QueryRow(ctx, `
		SELECT id FROM messages
		WHERE uid = $1 AND mailbox_id = $2 AND expunged_at IS NULL
	`, messageUID, mailboxID).Scan(&messageID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("message UID %d in mailbox %d not found (may be expunged or moved)", messageUID, mailboxID)
		}
		return 0, fmt.Errorf("failed to resolve message ID for UID %d in mailbox %d: %w", messageUID, mailboxID, err)
	}
	return messageID, nil
}

// getAllFlagsForMessage retrieves all system and custom flags for a given message.
// Uses a direct PK lookup on message_state for maximum performance.
// This function must be called within the same transaction as any preceding update
// to ensure it reads the latest state.
func (db *Database) getAllFlagsForMessage(ctx context.Context, tx pgx.Tx, messageID int64) ([]imap.Flag, error) {
	var bitwiseFlags int
	var customFlagsJSON []byte
	err := tx.QueryRow(ctx, `
		SELECT flags, custom_flags FROM message_state
		WHERE message_id = $1
	`, messageID).Scan(&bitwiseFlags, &customFlagsJSON)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("message_state for message %d not found: %w", messageID, err)
		}
		return nil, fmt.Errorf("failed to get flags for message %d: %w", messageID, err)
	}

	allFlags := BitwiseToFlags(bitwiseFlags)
	var customKeywords []string
	if err := json.Unmarshal(customFlagsJSON, &customKeywords); err != nil {
		log.Printf("Database: error unmarshalling custom_flags for message %d: %v. JSON: %s", messageID, err, string(customFlagsJSON))
		return nil, fmt.Errorf("failed to unmarshal custom_flags for message %d: %w", messageID, err)
	}

	// Convert custom keywords to imap.Flag and sanitize to remove invalid values
	// that may have been stored before validation was added (e.g., NIL, NULL)
	for _, kw := range customKeywords {
		allFlags = append(allFlags, imap.Flag(kw))
	}
	allFlags = helpers.SanitizeFlags(allFlags)

	return allFlags, nil
}

// MaxCustomKeywordsPerMessage bounds how many custom keywords (IMAP keywords) a
// single message may carry. It guards against unbounded keyword accumulation
// from a buggy or hostile client bloating message_state.custom_flags and the
// per-mailbox keyword registry. The same bound is enforced as a CHECK constraint
// on message_state as a backstop. Lenient paths (deliveries, imports) silently
// cap to this value to avoid bouncing; interactive paths (IMAP, API) reject
// over-limit requests cleanly rather than failing with a constraint violation.
// 50 is far above any realistic tagging scheme.
const MaxCustomKeywordsPerMessage = 50

// capCustomKeywords truncates kw to at most MaxCustomKeywordsPerMessage entries,
// preserving order so already-present keywords (placed first by the caller) win
// over overflow. Used only on the lenient INSERT paths — Sieve-set keywords on
// delivery (imap4flags, RFC 5232) and bulk import — where silently dropping
// surplus keywords is preferable to bouncing a delivery or aborting a migration.
// The interactive paths (IMAP STORE/APPEND, User API) instead reject with a LIMIT
// error — see DistinctKeywordCount. (LMTP itself carries no flags.)
func capCustomKeywords(kw []string) []string {
	if len(kw) > MaxCustomKeywordsPerMessage {
		return kw[:MaxCustomKeywordsPerMessage]
	}
	return kw
}

// DistinctKeywordCount returns the number of distinct custom keywords in flags,
// folding case per RFC 9051 §2.3.2 (so "Work" and "WORK" count once). System
// flags (\Seen, …) are not keywords and are ignored. Interactive callers use it
// to reject a STORE/APPEND that would exceed MaxCustomKeywordsPerMessage with a
// LIMIT error (RFC 5530) instead of silently dropping keywords.
func DistinctKeywordCount(flags []imap.Flag) int {
	_, keywords := SplitFlags(flags)
	if len(keywords) == 0 {
		return 0
	}
	seen := make(map[string]struct{}, len(keywords))
	for _, k := range keywords {
		seen[foldKeyword(k)] = struct{}{}
	}
	return len(seen)
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

	// Serialize unseen_count maintenance per mailbox (see lockMailboxStats) so the
	// flag-change trigger can't race a concurrent expunge/move trigger.
	if err = lockMailboxStats(ctx, tx, mailboxID); err != nil {
		return nil, 0, err
	}

	// Resolve message_id once, then use direct PK updates on message_state
	messageID, err := db.resolveMessageID(ctx, tx, messageUID, mailboxID)
	if err != nil {
		return nil, 0, err
	}

	systemFlagsToSet, customKeywordsToSet := SplitFlags(newFlags)
	bitwiseSystemFlags := FlagsToBitwise(systemFlagsToSet)
	// Fold keywords onto the case already used in this mailbox (RFC 9051 §2.3.2).
	customKeywordsToSet, err = db.canonicalizeKeywords(ctx, tx, mailboxID, customKeywordsToSet)
	if err != nil {
		return nil, 0, err
	}
	customKeywordsJSON, err := json.Marshal(customKeywordsToSet)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal custom keywords for SetMessageFlags: %w", err)
	}
	err = tx.QueryRow(ctx, `
		UPDATE message_state
		SET flags = $1, custom_flags = $2, flags_changed_at = $3, updated_modseq = nextval('messages_modseq')
		WHERE message_id = $4
		RETURNING updated_modseq
	`, bitwiseSystemFlags, customKeywordsJSON, time.Now(), messageID).Scan(&modSeq)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to execute set message flags for UID %d in mailbox %d: %w", messageUID, mailboxID, err)
	}

	currentFlags, err := db.getAllFlagsForMessage(ctx, tx, messageID)
	if err != nil {
		return nil, 0, err
	}

	return currentFlags, modSeq, nil
}

func (db *Database) AddMessageFlags(ctx context.Context, tx pgx.Tx, messageUID imap.UID, mailboxID int64, newFlags []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	// Serialize unseen_count maintenance per mailbox (see lockMailboxStats) so the
	// flag-change trigger can't race a concurrent expunge/move trigger.
	if err = lockMailboxStats(ctx, tx, mailboxID); err != nil {
		return nil, 0, err
	}

	// Resolve message_id once, then use direct PK updates on message_state
	messageID, err := db.resolveMessageID(ctx, tx, messageUID, mailboxID)
	if err != nil {
		return nil, 0, err
	}

	systemFlagsToAdd, customKeywordsToAdd := SplitFlags(newFlags)
	// Fold keywords onto the case already used in this mailbox (RFC 9051 §2.3.2)
	// so adding a different-case variant of an existing keyword is a no-op merge
	// rather than creating a duplicate.
	customKeywordsToAdd, err = db.canonicalizeKeywords(ctx, tx, mailboxID, customKeywordsToAdd)
	if err != nil {
		return nil, 0, err
	}
	hasCustom := len(customKeywordsToAdd) > 0
	var finalModSeq int64
	var hasUpdate bool

	if len(systemFlagsToAdd) > 0 {
		bitwiseSystemFlagsToAdd := FlagsToBitwise(systemFlagsToAdd)
		if hasCustom {
			// Custom keywords update follows — skip modseq bump here to avoid double increment
			ct, execErr := tx.Exec(ctx, `
				UPDATE message_state
				SET flags = flags | $1, flags_changed_at = $2
				WHERE message_id = $3
			`, bitwiseSystemFlagsToAdd, time.Now(), messageID)
			if execErr != nil {
				return nil, 0, fmt.Errorf("failed to add system flags for UID %d: %w", messageUID, execErr)
			}
			if ct.RowsAffected() == 0 {
				return nil, 0, fmt.Errorf("message UID %d in mailbox %d not found (may be expunged or moved)", messageUID, mailboxID)
			}
		} else {
			// Only system flags to update — bump modseq here
			err = tx.QueryRow(ctx, `
				UPDATE message_state
				SET flags = flags | $1, flags_changed_at = $2, updated_modseq = nextval('messages_modseq')
				WHERE message_id = $3
				RETURNING updated_modseq
			`, bitwiseSystemFlagsToAdd, time.Now(), messageID).Scan(&finalModSeq)
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
			UPDATE message_state
			SET custom_flags = (
				SELECT COALESCE(jsonb_agg(DISTINCT flag_element ORDER BY flag_element), '[]'::jsonb)
				FROM (
					SELECT jsonb_array_elements_text(message_state.custom_flags) AS flag_element
					UNION ALL
					SELECT unnest($2::text[]) AS flag_element
				) AS combined_flags
			), flags_changed_at = $3, updated_modseq = nextval('messages_modseq')
			WHERE message_id = $1
			RETURNING updated_modseq
		`, messageID, customKeywordsToAdd, time.Now()).Scan(&finalModSeq)
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

	currentFlags, err := db.getAllFlagsForMessage(ctx, tx, messageID)
	if err != nil {
		return nil, 0, err
	}

	return currentFlags, finalModSeq, nil
}

func (db *Database) RemoveMessageFlags(ctx context.Context, tx pgx.Tx, messageUID imap.UID, mailboxID int64, flagsToRemove []imap.Flag) (updatedFlags []imap.Flag, modSeq int64, err error) {
	// Serialize unseen_count maintenance per mailbox (see lockMailboxStats) so the
	// flag-change trigger can't race a concurrent expunge/move trigger.
	if err = lockMailboxStats(ctx, tx, mailboxID); err != nil {
		return nil, 0, err
	}

	// Resolve message_id once, then use direct PK updates on message_state
	messageID, err := db.resolveMessageID(ctx, tx, messageUID, mailboxID)
	if err != nil {
		return nil, 0, err
	}

	systemFlagsToRemove, customKeywordsToRemove := SplitFlags(flagsToRemove)
	// Fold the keywords to remove onto the case stored in this mailbox
	// (RFC 9051 §2.3.2) so removal is case-insensitive.
	customKeywordsToRemove, err = db.canonicalizeKeywords(ctx, tx, mailboxID, customKeywordsToRemove)
	if err != nil {
		return nil, 0, err
	}
	var finalModSeq int64
	var hasUpdate bool

	hasCustom := len(customKeywordsToRemove) > 0

	if len(systemFlagsToRemove) > 0 {
		bitwiseSystemFlagsToRemove := FlagsToBitwise(systemFlagsToRemove)
		negatedSystemFlags := ^bitwiseSystemFlagsToRemove // Bitwise NOT to clear these flags
		if hasCustom {
			// Custom keywords update follows — skip modseq bump here to avoid double increment
			ct, execErr := tx.Exec(ctx, `
				UPDATE message_state
				SET flags = flags & $1, flags_changed_at = $2
				WHERE message_id = $3
			`, negatedSystemFlags, time.Now(), messageID)
			if execErr != nil {
				return nil, 0, fmt.Errorf("failed to remove system flags for UID %d: %w", messageUID, execErr)
			}
			if ct.RowsAffected() == 0 {
				return nil, 0, fmt.Errorf("message UID %d in mailbox %d not found (may be expunged or moved)", messageUID, mailboxID)
			}
		} else {
			// Only system flags to update — bump modseq here
			err = tx.QueryRow(ctx, `
				UPDATE message_state
				SET flags = flags & $1, flags_changed_at = $2, updated_modseq = nextval('messages_modseq')
				WHERE message_id = $3
				RETURNING updated_modseq
			`, negatedSystemFlags, time.Now(), messageID).Scan(&finalModSeq)
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
			UPDATE message_state
			SET custom_flags = custom_flags - $2::text[],
			    flags_changed_at = $3, updated_modseq = nextval('messages_modseq')
			WHERE message_id = $1
			RETURNING updated_modseq
		`, messageID, customKeywordsToRemove, time.Now()).Scan(&finalModSeq)
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

	currentFlags, err := db.getAllFlagsForMessage(ctx, tx, messageID)
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

	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("failed to query custom_flags_cache for mailbox %d: %w", mailboxID, err)
	}

	if errors.Is(err, pgx.ErrNoRows) {
		return []string{}, nil
	}

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
			return dedupKeywordsByFold(result), nil
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

	return dedupKeywordsByFold(result), nil
}
