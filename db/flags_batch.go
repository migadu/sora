package db

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
)

type BatchFlagUpdateResult struct {
	UID                imap.UID
	Flags              []imap.Flag
	ModSeq             int64
	PreconditionFailed bool // current mod-sequence exceeded the optional UNCHANGEDSINCE bound
}

// filterConditionalFlagIDs runs after lockMailboxStats in the write transaction.
// Checking the server's earlier read snapshot is insufficient: another STORE may
// have committed between that read and this lock (RFC 7162 §3.1.3.1).
func filterConditionalFlagIDs(ctx context.Context, tx pgx.Tx, ids []int64, idToUID map[int64]imap.UID, unchangedSince []uint64) ([]int64, []BatchFlagUpdateResult, error) {
	if len(unchangedSince) == 0 || len(ids) == 0 {
		return ids, nil, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT m.id, GREATEST(m.created_modseq, COALESCE(ms.updated_modseq, 0))
		FROM messages m
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.id = ANY($1) AND m.expunged_at IS NULL
	`, ids)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var allowed []int64
	var failed []BatchFlagUpdateResult
	for rows.Next() {
		var id, modSeq int64
		if err := rows.Scan(&id, &modSeq); err != nil {
			return nil, nil, err
		}
		if uint64(modSeq) > unchangedSince[0] {
			failed = append(failed, BatchFlagUpdateResult{UID: idToUID[id], ModSeq: modSeq, PreconditionFailed: true})
		} else {
			allowed = append(allowed, id)
		}
	}
	return allowed, failed, rows.Err()
}

func (db *Database) resolveMessageIDsBatch(ctx context.Context, tx pgx.Tx, mailboxID int64, messageUIDs []imap.UID) (map[int64]imap.UID, []int64, error) {
	if len(messageUIDs) == 0 {
		return nil, nil, nil
	}
	uids := make([]int64, len(messageUIDs))
	for i, uid := range messageUIDs {
		uids[i] = int64(uid)
	}

	rows, err := tx.Query(ctx, `
		SELECT id, uid FROM messages
		WHERE mailbox_id = $1 AND uid = ANY($2) AND expunged_at IS NULL
	`, mailboxID, uids)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve message IDs batch in mailbox %d: %w", mailboxID, err)
	}
	defer rows.Close()

	idToUID := make(map[int64]imap.UID)
	var messageIDs []int64
	for rows.Next() {
		var id int64
		var uid int64
		if err := rows.Scan(&id, &uid); err != nil {
			return nil, nil, err
		}
		idToUID[id] = imap.UID(uid)
		messageIDs = append(messageIDs, id)
	}
	return idToUID, messageIDs, rows.Err()
}

func (db *Database) getAllFlagsForMessages(ctx context.Context, tx pgx.Tx, messageIDs []int64) (map[int64][]imap.Flag, error) {
	if len(messageIDs) == 0 {
		return nil, nil
	}

	rows, err := tx.Query(ctx, `
		SELECT message_id, flags, custom_flags FROM message_state
		WHERE message_id = ANY($1)
	`, messageIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get batch flags: %w", err)
	}
	defer rows.Close()

	results := make(map[int64][]imap.Flag)
	for rows.Next() {
		var msgID int64
		var bitwiseFlags int
		var customFlagsJSON []byte
		if err := rows.Scan(&msgID, &bitwiseFlags, &customFlagsJSON); err != nil {
			return nil, err
		}

		allFlags := BitwiseToFlags(bitwiseFlags)
		var customKeywords []string
		if err := json.Unmarshal(customFlagsJSON, &customKeywords); err != nil {
			log.Printf("Database: error unmarshalling custom_flags for message %d: %v", msgID, err)
			continue
		}

		for _, kw := range customKeywords {
			allFlags = append(allFlags, imap.Flag(kw))
		}
		allFlags = helpers.SanitizeFlags(allFlags)
		results[msgID] = allFlags
	}
	return results, rows.Err()
}

func (db *Database) SetMessageFlagsBatch(ctx context.Context, tx pgx.Tx, messageUIDs []imap.UID, mailboxID int64, newFlags []imap.Flag, unchangedSince ...uint64) ([]BatchFlagUpdateResult, error) {
	return db.setMessageFlagsBatch(ctx, tx, messageUIDs, mailboxID, newFlags, nil, unchangedSince...)
}

// SetMessageFlagsBatchWithRights applies the requested replacement only to flags
// the user may modify (RFC 4314 §4). Protected flags come from the current row in
// the locked UPDATE, never from the IMAP command's earlier read snapshot.
func (db *Database) SetMessageFlagsBatchWithRights(ctx context.Context, tx pgx.Tx, messageUIDs []imap.UID, mailboxID int64, newFlags []imap.Flag, rights string, unchangedSince ...uint64) ([]BatchFlagUpdateResult, error) {
	return db.setMessageFlagsBatch(ctx, tx, messageUIDs, mailboxID, newFlags, &rights, unchangedSince...)
}

func (db *Database) setMessageFlagsBatch(ctx context.Context, tx pgx.Tx, messageUIDs []imap.UID, mailboxID int64, newFlags []imap.Flag, rights *string, unchangedSince ...uint64) ([]BatchFlagUpdateResult, error) {
	start := time.Now()
	defer func() {
		metrics.DBQueryDuration.WithLabelValues("flags_set_batch", "write").Observe(time.Since(start).Seconds())
		metrics.DBQueriesTotal.WithLabelValues("flags_set_batch", "success", "write").Inc()
	}()

	// Serialize unseen_count maintenance per mailbox (see lockMailboxStats) so the
	// flag-change trigger can't race a concurrent expunge/move trigger.
	if err := lockMailboxStats(ctx, tx, mailboxID); err != nil {
		return nil, err
	}

	idToUID, messageIDs, err := db.resolveMessageIDsBatch(ctx, tx, mailboxID, messageUIDs)
	if err != nil || len(messageIDs) == 0 {
		return nil, err
	}
	messageIDs, failed, err := filterConditionalFlagIDs(ctx, tx, messageIDs, idToUID, unchangedSince)
	if err != nil || len(messageIDs) == 0 {
		return failed, err
	}

	preserveSystem := 0
	preserveCustom := false
	if rights != nil {
		if !strings.ContainsRune(*rights, 's') {
			preserveSystem |= FlagSeen
		}
		if !strings.ContainsRune(*rights, 't') {
			preserveSystem |= FlagDeleted
		}
		if !strings.ContainsRune(*rights, 'w') {
			preserveSystem |= ^(FlagSeen | FlagDeleted)
			preserveCustom = true
		} else if !helpers.HasFlag(newFlags, imap.FlagFlagged) {
			// Match STORE's unflagging policy without touching protected colors.
			newFlags = slices.DeleteFunc(slices.Clone(newFlags), helpers.IsFlagColorKeyword)
		}
	}
	newFlags = NormalizeAttachmentKeywordUpdate(newFlags, newFlags)
	if rights != nil && !preserveCustom && DistinctKeywordCount(newFlags) > MaxCustomKeywordsPerMessage {
		return nil, consts.ErrTooManyKeywords
	}
	systemFlagsToSet, customKeywordsToSet := SplitFlags(newFlags)
	bitwiseSystemFlags := FlagsToBitwise(systemFlagsToSet) &^ preserveSystem
	// Fold keywords onto the case already used in this mailbox (RFC 9051 §2.3.2).
	customKeywordsToSet, err = db.canonicalizeKeywords(ctx, tx, mailboxID, customKeywordsToSet)
	if err != nil {
		return nil, err
	}
	if customKeywordsToSet == nil {
		customKeywordsToSet = []string{}
	}
	customKeywordsJSON, err := json.Marshal(customKeywordsToSet)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal custom keywords for SetMessageFlagsBatch: %w", err)
	}

	rows, err := tx.Query(ctx, `
		UPDATE message_state
		SET flags = $1 | (flags & $5),
		    custom_flags = CASE WHEN $6 THEN custom_flags ELSE $2::jsonb END,
		    flags_changed_at = $3, updated_modseq = nextval('messages_modseq')
		WHERE message_id = ANY($4)
		  AND (flags != ($1 | (flags & $5))
		       OR custom_flags != CASE WHEN $6 THEN custom_flags ELSE $2::jsonb END)
		RETURNING message_id, updated_modseq
	`, bitwiseSystemFlags, customKeywordsJSON, time.Now(), messageIDs, preserveSystem, preserveCustom)
	if err != nil {
		return nil, fmt.Errorf("failed to execute batch set message flags in mailbox %d: %w", mailboxID, err)
	}
	defer rows.Close()

	updatedModSeqs := make(map[int64]int64)
	for rows.Next() {
		var id, modSeq int64
		if err := rows.Scan(&id, &modSeq); err != nil {
			return nil, err
		}
		updatedModSeqs[id] = modSeq
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(updatedModSeqs) == 0 {
		return failed, nil
	}

	currentFlagsMap, err := db.getAllFlagsForMessages(ctx, tx, messageIDs)
	if err != nil {
		return nil, err
	}

	results := failed
	for _, id := range messageIDs {
		if modSeq, ok := updatedModSeqs[id]; ok {
			results = append(results, BatchFlagUpdateResult{
				UID:    idToUID[id],
				Flags:  currentFlagsMap[id],
				ModSeq: modSeq,
			})
		}
	}

	return results, nil
}

func (db *Database) AddMessageFlagsBatch(ctx context.Context, tx pgx.Tx, messageUIDs []imap.UID, mailboxID int64, newFlags []imap.Flag, unchangedSince ...uint64) ([]BatchFlagUpdateResult, error) {
	start := time.Now()
	defer func() {
		metrics.DBQueryDuration.WithLabelValues("flags_add_batch", "write").Observe(time.Since(start).Seconds())
		metrics.DBQueriesTotal.WithLabelValues("flags_add_batch", "success", "write").Inc()
	}()

	// Serialize unseen_count maintenance per mailbox (see lockMailboxStats) so the
	// flag-change trigger can't race a concurrent expunge/move trigger.
	if err := lockMailboxStats(ctx, tx, mailboxID); err != nil {
		return nil, err
	}

	idToUID, messageIDs, err := db.resolveMessageIDsBatch(ctx, tx, mailboxID, messageUIDs)
	if err != nil || len(messageIDs) == 0 {
		return nil, err
	}
	messageIDs, failed, err := filterConditionalFlagIDs(ctx, tx, messageIDs, idToUID, unchangedSince)
	if err != nil || len(messageIDs) == 0 {
		return failed, err
	}

	attachmentRemovals := attachmentKeywordRemovals(newFlags)
	newFlags = NormalizeAttachmentKeywordUpdate(newFlags, newFlags)
	systemFlagsToAdd, customKeywordsToAdd := SplitFlags(newFlags)
	// Fold keywords onto the case already used in this mailbox (RFC 9051 §2.3.2)
	// so adding a different-case variant of an existing keyword is a no-op merge.
	customKeywordsToAdd, err = db.canonicalizeKeywords(ctx, tx, mailboxID, customKeywordsToAdd)
	if err != nil {
		return nil, err
	}
	if customKeywordsToAdd == nil {
		customKeywordsToAdd = []string{}
	}
	bitwiseSystemFlagsToAdd := FlagsToBitwise(systemFlagsToAdd)

	// Re-check the keyword cap under the mailbox lock: the caller's check ran on
	// an earlier snapshot, and a concurrent writer may have filled a message since.
	// The count mirrors the custom_flags expression of the UPDATE below.
	if len(customKeywordsToAdd) > 0 {
		var overLimit bool
		err = tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM message_state
				WHERE message_id = ANY($1)
				  AND (
					SELECT count(DISTINCT flag_element)
					FROM (
						SELECT jsonb_array_elements_text(message_state.custom_flags) AS flag_element
						UNION ALL
						SELECT unnest($2::text[]) AS flag_element
					) AS combined_flags
					WHERE NOT (lower(flag_element) = ANY($3::text[]))
				  ) > $4
			)
		`, messageIDs, customKeywordsToAdd, attachmentRemovals, MaxCustomKeywordsPerMessage).Scan(&overLimit)
		if err != nil {
			return nil, fmt.Errorf("failed to check keyword limit in mailbox %d: %w", mailboxID, err)
		}
		if overLimit {
			return nil, consts.ErrTooManyKeywords
		}
	}

	rows, err := tx.Query(ctx, `
		UPDATE message_state
		SET flags = flags | $1,
		    custom_flags = (
				SELECT COALESCE(jsonb_agg(DISTINCT flag_element ORDER BY flag_element), '[]'::jsonb)
				FROM (
					SELECT jsonb_array_elements_text(message_state.custom_flags) AS flag_element
					UNION ALL
					SELECT unnest($2::text[]) AS flag_element
				) AS combined_flags
				WHERE NOT (lower(flag_element) = ANY($5::text[]))
			),
		    flags_changed_at = $3,
		    updated_modseq = nextval('messages_modseq')
		WHERE message_id = ANY($4)
		  AND ( (flags & $1) != $1 OR NOT (custom_flags @> to_jsonb($2::text[]))
		        OR (cardinality($5::text[]) > 0 AND EXISTS (
		              SELECT 1 FROM jsonb_array_elements_text(custom_flags) AS old_keyword
		              WHERE lower(old_keyword) = ANY($5::text[]))) )
		RETURNING message_id, updated_modseq
	`, bitwiseSystemFlagsToAdd, customKeywordsToAdd, time.Now(), messageIDs, attachmentRemovals)
	if err != nil {
		return nil, fmt.Errorf("failed to execute batch add message flags in mailbox %d: %w", mailboxID, err)
	}
	defer rows.Close()

	updatedModSeqs := make(map[int64]int64)
	for rows.Next() {
		var id, modSeq int64
		if err := rows.Scan(&id, &modSeq); err != nil {
			return nil, err
		}
		updatedModSeqs[id] = modSeq
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(updatedModSeqs) == 0 {
		return failed, nil
	}

	currentFlagsMap, err := db.getAllFlagsForMessages(ctx, tx, messageIDs)
	if err != nil {
		return nil, err
	}

	results := failed
	for _, id := range messageIDs {
		if modSeq, ok := updatedModSeqs[id]; ok {
			results = append(results, BatchFlagUpdateResult{
				UID:    idToUID[id],
				Flags:  currentFlagsMap[id],
				ModSeq: modSeq,
			})
		}
	}

	return results, nil
}

func (db *Database) RemoveMessageFlagsBatch(ctx context.Context, tx pgx.Tx, messageUIDs []imap.UID, mailboxID int64, flagsToRemove []imap.Flag, unchangedSince ...uint64) ([]BatchFlagUpdateResult, error) {
	start := time.Now()
	defer func() {
		metrics.DBQueryDuration.WithLabelValues("flags_del_batch", "write").Observe(time.Since(start).Seconds())
		metrics.DBQueriesTotal.WithLabelValues("flags_del_batch", "success", "write").Inc()
	}()

	// Serialize unseen_count maintenance per mailbox (see lockMailboxStats) so the
	// flag-change trigger can't race a concurrent expunge/move trigger.
	if err := lockMailboxStats(ctx, tx, mailboxID); err != nil {
		return nil, err
	}

	idToUID, messageIDs, err := db.resolveMessageIDsBatch(ctx, tx, mailboxID, messageUIDs)
	if err != nil || len(messageIDs) == 0 {
		return nil, err
	}
	messageIDs, failed, err := filterConditionalFlagIDs(ctx, tx, messageIDs, idToUID, unchangedSince)
	if err != nil || len(messageIDs) == 0 {
		return failed, err
	}

	systemFlagsToRemove, customKeywordsToRemove := SplitFlags(flagsToRemove)
	// Fold the keywords to remove onto the case stored in this mailbox
	// (RFC 9051 §2.3.2) so removal is case-insensitive.
	customKeywordsToRemove, err = db.canonicalizeKeywords(ctx, tx, mailboxID, customKeywordsToRemove)
	if err != nil {
		return nil, err
	}
	if customKeywordsToRemove == nil {
		customKeywordsToRemove = []string{}
	}
	bitwiseSystemFlagsToRemove := FlagsToBitwise(systemFlagsToRemove)
	negatedSystemFlags := ^bitwiseSystemFlagsToRemove

	rows, err := tx.Query(ctx, `
		UPDATE message_state
		SET flags = flags & $1,
		    custom_flags = custom_flags - $2::text[],
		    flags_changed_at = $3,
		    updated_modseq = nextval('messages_modseq')
		WHERE message_id = ANY($4)
		  AND ( (flags & $5) > 0 OR custom_flags ?| $2::text[] )
		RETURNING message_id, updated_modseq
	`, negatedSystemFlags, customKeywordsToRemove, time.Now(), messageIDs, bitwiseSystemFlagsToRemove)
	if err != nil {
		return nil, fmt.Errorf("failed to execute batch remove message flags in mailbox %d: %w", mailboxID, err)
	}
	defer rows.Close()

	updatedModSeqs := make(map[int64]int64)
	for rows.Next() {
		var id, modSeq int64
		if err := rows.Scan(&id, &modSeq); err != nil {
			return nil, err
		}
		updatedModSeqs[id] = modSeq
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(updatedModSeqs) == 0 {
		return failed, nil
	}

	currentFlagsMap, err := db.getAllFlagsForMessages(ctx, tx, messageIDs)
	if err != nil {
		return nil, err
	}

	results := failed
	for _, id := range messageIDs {
		if modSeq, ok := updatedModSeqs[id]; ok {
			results = append(results, BatchFlagUpdateResult{
				UID:    idToUID[id],
				Flags:  currentFlagsMap[id],
				ModSeq: modSeq,
			})
		}
	}

	return results, nil
}
