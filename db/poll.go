package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

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
	// OPTIMIZATION: Early exit if modseq hasn't changed
	// This avoids expensive window functions when mailbox is idle
	var currentModSeq uint64
	var messageCount int
	err := db.GetReadPool().QueryRow(ctx, `
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

	// Phase 1: Fetch Raw Changes
	// Instead of a massive CTE pipeline, we directly pull exactly the messages that changed.
	rows, err := db.GetReadPool().Query(ctx, `
		SELECT uid, expunged_at, flags, custom_flags, created, updated, expunged FROM (
			SELECT m.uid, m.expunged_at, ms.flags, ms.custom_flags, m.created_modseq as created, ms.updated_modseq as updated, m.expunged_modseq as expunged
			FROM messages m LEFT JOIN message_state ms ON ms.message_id = m.id
			WHERE m.mailbox_id = $1 AND m.created_modseq > $2
			UNION
			SELECT m.uid, m.expunged_at, ms.flags, ms.custom_flags, m.created_modseq, ms.updated_modseq, m.expunged_modseq
			FROM messages m LEFT JOIN message_state ms ON ms.message_id = m.id
			WHERE m.mailbox_id = $1 AND m.expunged_modseq > $2
			UNION
			SELECT m.uid, m.expunged_at, ms.flags, ms.custom_flags, m.created_modseq, ms.updated_modseq, m.expunged_modseq
			FROM message_state ms JOIN messages m ON ms.message_id = m.id
			WHERE ms.mailbox_id = $1 AND ms.updated_modseq > $2
		) sub
	`, mailboxID, sinceModSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch raw changes: %w", err)
	}
	defer rows.Close()

	var rawUpdates []MessageUpdate
	for rows.Next() {
		var uid uint32
		var expungedAt sql.NullTime
		var flags sql.NullInt32
		var customFlagsJSON []byte
		var created sql.NullInt64
		var updated sql.NullInt64
		var expunged sql.NullInt64

		if err := rows.Scan(&uid, &expungedAt, &flags, &customFlagsJSON, &created, &updated, &expunged); err != nil {
			return nil, fmt.Errorf("failed to scan raw change: %w", err)
		}

		var customFlags []string
		if customFlagsJSON != nil {
			if err := json.Unmarshal(customFlagsJSON, &customFlags); err != nil {
				return nil, fmt.Errorf("failed to unmarshal custom_flags in poll: %w", err)
			}
		}

		effective := uint64(0)
		if created.Valid && uint64(created.Int64) > effective {
			effective = uint64(created.Int64)
		}
		if updated.Valid && uint64(updated.Int64) > effective {
			effective = uint64(updated.Int64)
		}
		if expunged.Valid && uint64(expunged.Int64) > effective {
			effective = uint64(expunged.Int64)
		}

		bitwise := 0
		if flags.Valid {
			bitwise = int(flags.Int32)
		}

		rawUpdates = append(rawUpdates, MessageUpdate{
			UID:             imap.UID(uid),
			BitwiseFlags:    bitwise,
			IsExpunge:       expungedAt.Valid,
			CustomFlags:     customFlags,
			EffectiveModSeq: effective,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating raw changes: %w", err)
	}

	pollData := MailboxPoll{
		Updates:     []MessageUpdate{},
		NumMessages: uint32(messageCount),
		ModSeq:      currentModSeq,
	}

	if len(rawUpdates) == 0 {
		return &pollData, nil
	}

	// Phase 2: Dynamic Sequence Hydration
	uids := make([]uint32, len(rawUpdates))
	for i, u := range rawUpdates {
		uids[i] = uint32(u.UID)
	}

	seqMap := make(map[uint32]uint32)

	if sinceModSeq > 0 && len(rawUpdates) <= 1000 {
		// SPARSE PATH: Evaluate correlation strictly for the requested UIDs
		seqRows, err := db.GetReadPool().Query(ctx, `
			SELECT m.uid,
			  (SELECT COUNT(*) FROM messages m2 WHERE m2.mailbox_id = $1 AND m2.uid <= m.uid AND m2.expunged_at IS NULL) as active_seq,
			  (SELECT COUNT(*) FROM messages m2 WHERE m2.mailbox_id = $1 AND m2.uid <= m.uid AND m2.expunged_modseq > $2) as exp_offset
			FROM messages m
			WHERE m.mailbox_id = $1 AND m.uid = ANY($3)
		`, mailboxID, sinceModSeq, uids)
		if err != nil {
			return nil, fmt.Errorf("failed to map sparse sequence numbers: %w", err)
		}
		defer seqRows.Close()

		for seqRows.Next() {
			var uid, active, offset uint32
			if err := seqRows.Scan(&uid, &active, &offset); err != nil {
				return nil, fmt.Errorf("failed to scan sparse sequence: %w", err)
			}
			seqMap[uid] = active + offset
		}
		if err := seqRows.Err(); err != nil {
			return nil, fmt.Errorf("error in sparse hydration: %w", err)
		}
	} else {
		// DENSE PATH: Stream the entire active block sequentially without memory CTEs
		seqRows, err := db.GetReadPool().Query(ctx, `
			SELECT uid, expunged_at
			FROM messages
			WHERE mailbox_id = $1 AND (expunged_at IS NULL OR expunged_modseq > $2)
			ORDER BY uid ASC
		`, mailboxID, sinceModSeq)
		if err != nil {
			return nil, fmt.Errorf("failed to query dense sequences: %w", err)
		}
		defer seqRows.Close()

		activeCount := uint32(0)
		expungedOffset := uint32(0)

		for seqRows.Next() {
			var uid uint32
			var exp sql.NullTime
			if err := seqRows.Scan(&uid, &exp); err != nil {
				return nil, fmt.Errorf("failed to scan dense sequence row: %w", err)
			}
			if !exp.Valid {
				activeCount++
			} else {
				expungedOffset++
			}
			seqMap[uid] = activeCount + expungedOffset
		}
		if err := seqRows.Err(); err != nil {
			return nil, fmt.Errorf("error iterating dense sequences: %w", err)
		}
	}

	for i := range rawUpdates {
		rawUpdates[i].SeqNum = seqMap[uint32(rawUpdates[i].UID)]
	}

	// Sort correctly for correct IMAP processing:
	// Expunged processed top-down, flags processed bottom-up.
	sort.Slice(rawUpdates, func(i, j int) bool {
		a := rawUpdates[i]
		b := rawUpdates[j]
		if a.IsExpunge != b.IsExpunge {
			return a.IsExpunge
		}
		if a.IsExpunge {
			return a.SeqNum > b.SeqNum
		}
		return a.SeqNum < b.SeqNum
	})

	pollData.Updates = rawUpdates
	return &pollData, nil
}
