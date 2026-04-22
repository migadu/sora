package db

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
)

type BatchFlagUpdateResult struct {
	UID    imap.UID
	Flags  []imap.Flag
	ModSeq int64
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

func (db *Database) SetMessageFlagsBatch(ctx context.Context, tx pgx.Tx, messageUIDs []imap.UID, mailboxID int64, newFlags []imap.Flag) ([]BatchFlagUpdateResult, error) {
	start := time.Now()
	defer func() {
		metrics.DBQueryDuration.WithLabelValues("flags_set_batch", "write").Observe(time.Since(start).Seconds())
		metrics.DBQueriesTotal.WithLabelValues("flags_set_batch", "success", "write").Inc()
	}()

	idToUID, messageIDs, err := db.resolveMessageIDsBatch(ctx, tx, mailboxID, messageUIDs)
	if err != nil || len(messageIDs) == 0 {
		return nil, err
	}

	systemFlagsToSet, customKeywordsToSet := SplitFlags(newFlags)
	bitwiseSystemFlags := FlagsToBitwise(systemFlagsToSet)
	if customKeywordsToSet == nil {
		customKeywordsToSet = []string{}
	}
	customKeywordsJSON, err := json.Marshal(customKeywordsToSet)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal custom keywords for SetMessageFlagsBatch: %w", err)
	}

	rows, err := tx.Query(ctx, `
		UPDATE message_state
		SET flags = $1, custom_flags = $2::jsonb, flags_changed_at = $3, updated_modseq = nextval('messages_modseq')
		WHERE message_id = ANY($4)
		  AND (flags != $1 OR custom_flags != $2::jsonb)
		RETURNING message_id, updated_modseq
	`, bitwiseSystemFlags, customKeywordsJSON, time.Now(), messageIDs)
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
		return []BatchFlagUpdateResult{}, nil
	}

	currentFlagsMap, err := db.getAllFlagsForMessages(ctx, tx, messageIDs)
	if err != nil {
		return nil, err
	}

	var results []BatchFlagUpdateResult
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

func (db *Database) AddMessageFlagsBatch(ctx context.Context, tx pgx.Tx, messageUIDs []imap.UID, mailboxID int64, newFlags []imap.Flag) ([]BatchFlagUpdateResult, error) {
	start := time.Now()
	defer func() {
		metrics.DBQueryDuration.WithLabelValues("flags_add_batch", "write").Observe(time.Since(start).Seconds())
		metrics.DBQueriesTotal.WithLabelValues("flags_add_batch", "success", "write").Inc()
	}()

	idToUID, messageIDs, err := db.resolveMessageIDsBatch(ctx, tx, mailboxID, messageUIDs)
	if err != nil || len(messageIDs) == 0 {
		return nil, err
	}

	systemFlagsToAdd, customKeywordsToAdd := SplitFlags(newFlags)
	if customKeywordsToAdd == nil {
		customKeywordsToAdd = []string{}
	}
	bitwiseSystemFlagsToAdd := FlagsToBitwise(systemFlagsToAdd)

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
			),
		    flags_changed_at = $3,
		    updated_modseq = nextval('messages_modseq')
		WHERE message_id = ANY($4)
		  AND ( (flags & $1) != $1 OR NOT (custom_flags @> to_jsonb($2::text[])) )
		RETURNING message_id, updated_modseq
	`, bitwiseSystemFlagsToAdd, customKeywordsToAdd, time.Now(), messageIDs)
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
		return []BatchFlagUpdateResult{}, nil
	}

	currentFlagsMap, err := db.getAllFlagsForMessages(ctx, tx, messageIDs)
	if err != nil {
		return nil, err
	}

	var results []BatchFlagUpdateResult
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

func (db *Database) RemoveMessageFlagsBatch(ctx context.Context, tx pgx.Tx, messageUIDs []imap.UID, mailboxID int64, flagsToRemove []imap.Flag) ([]BatchFlagUpdateResult, error) {
	start := time.Now()
	defer func() {
		metrics.DBQueryDuration.WithLabelValues("flags_del_batch", "write").Observe(time.Since(start).Seconds())
		metrics.DBQueriesTotal.WithLabelValues("flags_del_batch", "success", "write").Inc()
	}()

	idToUID, messageIDs, err := db.resolveMessageIDsBatch(ctx, tx, mailboxID, messageUIDs)
	if err != nil || len(messageIDs) == 0 {
		return nil, err
	}

	systemFlagsToRemove, customKeywordsToRemove := SplitFlags(flagsToRemove)
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
		return []BatchFlagUpdateResult{}, nil
	}

	currentFlagsMap, err := db.getAllFlagsForMessages(ctx, tx, messageIDs)
	if err != nil {
		return nil, err
	}

	var results []BatchFlagUpdateResult
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
