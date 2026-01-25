package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"database/sql"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
)

type MessageUpdate struct {
	UID             imap.UID
	SeqNum          uint32
	BitwiseFlags    int // Matches the 'flags' column type in messages table (INTEGER)
	IsExpunge       bool
	CustomFlags     []string
	EffectiveModSeq uint64 // The modseq that triggered this update
}

type MailboxPoll struct {
	Updates     []MessageUpdate
	NumMessages uint32
	ModSeq      uint64
}

func (db *Database) PollMailbox(ctx context.Context, mailboxID int64, sinceModSeq uint64) (*MailboxPoll, error) {
	tx, err := db.GetReadPool().BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// OPTIMIZATION: Early exit if modseq hasn't changed
	// This avoids expensive window functions when mailbox is idle
	var currentModSeq uint64
	var messageCount int
	err = tx.QueryRow(ctx, `
		SELECT
			COALESCE(ms.highest_modseq, 0) AS highest_modseq,
			COALESCE(ms.message_count, 0) AS message_count
		FROM mailboxes mb
		LEFT JOIN mailbox_stats ms ON mb.id = ms.mailbox_id
		WHERE mb.id = $1
	`, mailboxID).Scan(&currentModSeq, &messageCount)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Mailbox was deleted while session was active
			return nil, ErrMailboxNotFound
		}
		return nil, fmt.Errorf("failed to get mailbox stats: %w", err)
	}

	// If modseq hasn't changed, return early with no updates
	if currentModSeq <= sinceModSeq {
		return &MailboxPoll{
			Updates:     []MessageUpdate{},
			NumMessages: uint32(messageCount),
			ModSeq:      currentModSeq,
		}, nil
	}

	// OPTIMIZATION: Use message_sequences table instead of ROW_NUMBER()
	// The message_sequences table is already maintained by triggers and cached
	rows, err := tx.Query(ctx, `
		SELECT * FROM (
			WITH
			  global_stats AS (
				SELECT
					COALESCE(ms.message_count, 0) AS total_messages,
					COALESCE(ms.highest_modseq, 0) AS highest_mailbox_modseq
				FROM mailboxes mb
				LEFT JOIN mailbox_stats ms ON mb.id = ms.mailbox_id
				WHERE mb.id = $1
			  ),
			  current_mailbox_state AS (
			    SELECT
			        m.uid,
			        -- Use the cached sequence numbers from message_sequences table
			        -- For expunged messages, we need to calculate their pre-expunge sequence number
			        CASE
			            WHEN m.expunged_modseq IS NOT NULL THEN
			                -- For expunged messages, count all messages with lower or equal UIDs
			                -- This gives us the sequence number BEFORE the expunge
			                (SELECT COUNT(*) FROM messages m2
			                 WHERE m2.mailbox_id = m.mailbox_id
			                   AND m2.uid <= m.uid
			                   AND (m2.expunged_modseq IS NULL OR m2.expunged_modseq > $2))
			            ELSE
			                -- For non-expunged messages, use the cached sequence number
			                COALESCE(ms.seqnum, 0)
			        END AS seq_num,
			        m.flags,
			        m.custom_flags,
			        m.created_modseq,
			        COALESCE(m.updated_modseq, 0) AS updated_modseq_val,
			        m.expunged_modseq
			    FROM messages m
			    LEFT JOIN message_sequences ms ON m.mailbox_id = ms.mailbox_id AND m.uid = ms.uid
			    WHERE m.mailbox_id = $1
			      AND (m.expunged_modseq IS NULL OR m.expunged_modseq > $2)
			      AND (m.created_modseq > $2 OR COALESCE(m.updated_modseq, 0) > $2 OR COALESCE(m.expunged_modseq, 0) > $2)
			  ),
			  changed_messages AS (
			    SELECT
			        cms.uid,
			        cms.seq_num,
			        cms.flags,
			        cms.custom_flags,
			        cms.expunged_modseq,
			        GREATEST(cms.created_modseq, cms.updated_modseq_val, COALESCE(cms.expunged_modseq, 0)) AS effective_modseq,
			        true AS is_message_update
			    FROM current_mailbox_state cms
			  )
			SELECT
			    cm.uid,
			    cm.seq_num,
			    cm.flags,
			    cm.custom_flags,
			    cm.expunged_modseq,
			    cm.effective_modseq,
			    cm.is_message_update,
			    gs.total_messages,
			    gs.highest_mailbox_modseq AS current_modseq
			FROM changed_messages cm, global_stats gs
			UNION ALL
			SELECT
			    NULL AS uid,
			    NULL AS seq_num,
			    NULL AS flags,
			    NULL AS custom_flags,
			    NULL AS expunged_modseq,
			    NULL AS effective_modseq,
			    false AS is_message_update,
			    gs.total_messages,
			    gs.highest_mailbox_modseq AS current_modseq
			FROM global_stats gs
			WHERE NOT EXISTS (SELECT 1 FROM changed_messages)
		) AS combined_results
		ORDER BY
		    is_message_update DESC,
		    (expunged_modseq IS NOT NULL) DESC,
		    CASE WHEN expunged_modseq IS NOT NULL THEN -seq_num ELSE seq_num END ASC
	`, mailboxID, sinceModSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to query combined mailbox poll: %w", err)
	}
	defer rows.Close()

	var updates []MessageUpdate
	var pollData MailboxPoll
	firstRowProcessed := false

	for rows.Next() {
		var (
			uidScannable             sql.NullInt32 // imap.UID is uint32
			seqNumScannable          sql.NullInt32 // uint32
			bitwiseFlagsScannable    sql.NullInt32 // INTEGER in DB
			expungedModSeqPtr        *int64
			customFlagsJSON          []byte
			effectiveModSeqScannable sql.NullInt64
			isMessageUpdate          bool
			rowTotalMessages         uint32
			rowCurrentModSeq         uint64
		)

		err := rows.Scan(
			&uidScannable,
			&seqNumScannable,
			&bitwiseFlagsScannable,
			&customFlagsJSON,
			&expungedModSeqPtr,
			&effectiveModSeqScannable,
			&isMessageUpdate,
			&rowTotalMessages,
			&rowCurrentModSeq,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan combined poll data: %w", err)
		}

		if !firstRowProcessed {
			pollData.NumMessages = rowTotalMessages
			pollData.ModSeq = rowCurrentModSeq
			firstRowProcessed = true
		}

		if isMessageUpdate {
			if !uidScannable.Valid || !seqNumScannable.Valid || !bitwiseFlagsScannable.Valid || !effectiveModSeqScannable.Valid {
				return nil, fmt.Errorf("unexpected NULL value in message update row: uid_valid=%v, seq_valid=%v, flags_valid=%v, effective_modseq_valid=%v", uidScannable.Valid, seqNumScannable.Valid, bitwiseFlagsScannable.Valid, effectiveModSeqScannable.Valid)
			}
			var customFlags []string
			if customFlagsJSON != nil { // Will be []byte("[]") if empty, or []byte("null")
				if err := json.Unmarshal(customFlagsJSON, &customFlags); err != nil {
					return nil, fmt.Errorf("failed to unmarshal custom_flags in poll: %w, json: %s", err, string(customFlagsJSON))
				}
			}
			if !effectiveModSeqScannable.Valid { // Should always be valid if isMessageUpdate is true
				return nil, fmt.Errorf("unexpected NULL effective_modseq in message update row for UID %d", uidScannable.Int32)
			}
			updates = append(updates, MessageUpdate{
				UID:             imap.UID(uidScannable.Int32),
				SeqNum:          uint32(seqNumScannable.Int32),
				BitwiseFlags:    int(bitwiseFlagsScannable.Int32),
				IsExpunge:       expungedModSeqPtr != nil,
				CustomFlags:     customFlags,
				EffectiveModSeq: uint64(effectiveModSeqScannable.Int64),
			})
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating through combined poll results: %w", err)
	}

	pollData.Updates = updates
	return &pollData, nil
}
