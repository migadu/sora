package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"database/sql"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
)

type MessageUpdate struct {
	UID             imap.UID
	SeqNum          uint32
	BitwiseFlags    int // Matches the 'flags' column type in messages table (INTEGER)
	IsExpunge       bool
	IsNew           bool // Created after sinceModSeq, independently of any later flag changes
	FlagsAreInitial bool // Known to still have the state installed at creation; NULL legacy versions are unknown
	CustomFlags     []string
	EffectiveModSeq uint64 // The modseq that triggered this update
}

type MailboxPoll struct {
	Updates     []MessageUpdate
	NumMessages uint32
	ModSeq      uint64
	HighestUID  imap.UID // mailboxes.highest_uid, read no later than NumMessages was counted
	// PhantomModSeq is the highest modseq of a message created and expunged since
	// sinceModSeq, which Updates leaves out: the client was never told it existed. A
	// cursor advanced past the changes in Updates must also pass it, or the message
	// would sit in the client's view as of the cursor (created at or before it,
	// expunged after it) and the next poll would report its expunge at the sequence
	// number of the message that follows it.
	PhantomModSeq uint64
}

// pollMailboxStateQuery is the single statement a poll that finds nothing changed
// issues. It must stay a single-row read: Poll runs after every IMAP command and every
// 15 seconds per IDLE session, so anything here that scales with the mailbox turns an
// idle fleet into O(sessions x mailbox_size) continuous load.
const pollMailboxStateQuery = `
	SELECT
		COALESCE(ms.highest_modseq, 0) AS highest_modseq,
		ms.message_count,
		mb.highest_uid
	FROM mailboxes mb
	LEFT JOIN mailbox_stats ms ON mb.id = ms.mailbox_id
	WHERE mb.id = $1
`

// pollMailboxActiveCountQuery counts the messages a client can see, for a poll with
// nothing to report that found no mailbox_stats row to take the count from.
const pollMailboxActiveCountQuery = `SELECT COUNT(*)::int FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL`

// pollMailboxSnapshotQuery is the first statement of a poll that has changes to report,
// so it fixes the snapshot the rest of the poll reads: the mailbox state again, as of that
// snapshot, and the live message count.
const pollMailboxSnapshotQuery = `
	SELECT
		COALESCE(ms.highest_modseq, 0) AS highest_modseq,
		mb.highest_uid,
		(SELECT COUNT(*)::int FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL) AS message_count
	FROM mailboxes mb
	LEFT JOIN mailbox_stats ms ON mb.id = ms.mailbox_id
	WHERE mb.id = $1
`

// PollMailbox reports what changed in a mailbox since sinceModSeq, numbered for a client
// whose view stands at it.
//
// A poll that has changes to report reads them in one REPEATABLE READ snapshot, so that the
// count, the changes and their sequence numbers describe the same mailbox. Otherwise a write
// committing between two of those statements makes them disagree: a message delivered after
// the count is reported as new at a sequence number past the EXISTS the count gives (a
// client numbers new messages from EXISTS, RFC 9051 §2.3.1.2), an expunge after the count is
// reported while the count still holds the message, and a delivery before the numbering
// shifts the numbers counted back from the total. A write that commits after the snapshot
// is left to the next poll: the cursor only passes changes the snapshot holds.
func (db *Database) PollMailbox(ctx context.Context, mailboxID int64, sinceModSeq uint64) (*MailboxPoll, error) {
	// OPTIMIZATION: Early exit if modseq hasn't changed
	// This avoids expensive window functions when mailbox is idle
	var currentModSeq uint64
	var cachedMessageCount sql.NullInt32
	var uidNext uint32
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, pollMailboxStateQuery, mailboxID).Scan(&currentModSeq, &cachedMessageCount, &uidNext)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Mailbox was deleted while session was active
			return nil, ErrMailboxNotFound
		}
		return nil, fmt.Errorf("failed to get mailbox stats: %w", err)
	}

	// If modseq hasn't changed, return early with no updates. Such a poll takes the cached
	// counter: mailbox_stats.message_count is written by the same trigger statement that
	// advances highest_modseq, so while the modseq stands still that counter stands still
	// too, and it is the very value SELECT seeded the session's message count from
	// (GetMailboxSummary). A missing stats row is the state the cache is known to get
	// wrong, so it falls back to counting.
	if currentModSeq <= sinceModSeq {
		messageCount := int(cachedMessageCount.Int32)
		if !cachedMessageCount.Valid {
			if err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, pollMailboxActiveCountQuery, mailboxID).Scan(&messageCount); err != nil {
				return nil, fmt.Errorf("failed to count active messages: %w", err)
			}
		}
		return &MailboxPoll{
			Updates:     []MessageUpdate{},
			NumMessages: uint32(messageCount),
			ModSeq:      currentModSeq,
			HighestUID:  imap.UID(uidNext),
		}, nil
	}

	// Everything from here on reads one snapshot (see above). REPEATABLE READ takes it at
	// the first statement, which re-reads the state the early exit was decided on, so the
	// modseq, the highest UID and the count all describe the mailbox the changes come from.
	tx, err := db.GetReadPoolWithContext(ctx).BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("failed to begin poll snapshot: %w", err)
	}
	defer tx.Rollback(context.Background())

	var messageCount int
	if err := tx.QueryRow(ctx, pollMailboxSnapshotQuery, mailboxID).Scan(&currentModSeq, &uidNext, &messageCount); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrMailboxNotFound
		}
		return nil, fmt.Errorf("failed to count active messages: %w", err)
	}

	// Phase 1: Fetch Raw Changes
	// Instead of a massive CTE pipeline, we directly pull exactly the messages that changed.
	rows, err := tx.Query(ctx, `
		SELECT uid, expunged_at, flags, custom_flags, created, updated, expunged, initial FROM (
			SELECT m.uid, m.expunged_at, ms.flags, ms.custom_flags, m.created_modseq as created, ms.updated_modseq as updated, m.expunged_modseq as expunged, ms.initial_modseq as initial
			FROM messages m LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
			-- New messages: created since the client's last sync and still active. The expunged_at IS NULL
			-- guard drops create+expunge-in-window phantoms (created since, already gone) which the client
			-- never saw -- reporting them would desync the client's sequence numbers.
			WHERE m.mailbox_id = $1 AND m.created_modseq > $2 AND m.expunged_at IS NULL
			UNION
			SELECT m.uid, m.expunged_at, ms.flags, ms.custom_flags, m.created_modseq, ms.updated_modseq, m.expunged_modseq, ms.initial_modseq
			FROM messages m LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
			-- Only report expunges for messages the client already knew about (created at or before its
			-- last-seen modseq). A message created AND expunged within this poll window was never sent to
			-- the client (no EXISTS), so emitting an EXPUNGE for it would shift the client's sequence
			-- numbers against a message it never saw -> tracker desync (Outlook stops showing new mail).
			WHERE m.mailbox_id = $1 AND m.expunged_modseq > $2 AND m.created_modseq <= $2
			UNION
			SELECT m.uid, m.expunged_at, ms.flags, ms.custom_flags, m.created_modseq, ms.updated_modseq, m.expunged_modseq, ms.initial_modseq
			FROM message_state ms JOIN messages m ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
			-- Flag updates only for active messages; an expunge is reported by the branch above.
			WHERE ms.mailbox_id = $1 AND ms.updated_modseq > $2 AND m.expunged_at IS NULL
			UNION
			SELECT m.uid, m.expunged_at, ms.flags, ms.custom_flags, m.created_modseq, ms.updated_modseq, m.expunged_modseq, ms.initial_modseq
			FROM messages m LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
			-- The create+expunge-in-window phantoms themselves: never reported, read only so the
			-- cursor can pass them (MailboxPoll.PhantomModSeq).
			WHERE m.mailbox_id = $1 AND m.created_modseq > $2 AND m.expunged_at IS NOT NULL
		) sub
	`, mailboxID, sinceModSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch raw changes: %w", err)
	}
	defer rows.Close()

	var rawUpdates []MessageUpdate
	var phantomModSeq uint64
	for rows.Next() {
		var uid uint32
		var expungedAt sql.NullTime
		var flags sql.NullInt32
		var customFlagsJSON []byte
		var created sql.NullInt64
		var updated sql.NullInt64
		var expunged sql.NullInt64
		var initial sql.NullInt64

		if err := rows.Scan(&uid, &expungedAt, &flags, &customFlagsJSON, &created, &updated, &expunged, &initial); err != nil {
			return nil, fmt.Errorf("failed to scan raw change: %w", err)
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

		// A phantom (the last branch above) is never reported; only its modseq counts.
		if expungedAt.Valid && created.Valid && uint64(created.Int64) > sinceModSeq {
			phantomModSeq = max(phantomModSeq, effective)
			continue
		}

		var customFlags []string
		if customFlagsJSON != nil {
			if err := json.Unmarshal(customFlagsJSON, &customFlags); err != nil {
				return nil, fmt.Errorf("failed to unmarshal custom_flags in poll: %w", err)
			}
		}

		bitwise := 0
		if flags.Valid {
			bitwise = int(flags.Int32)
		}

		rawUpdates = append(rawUpdates, MessageUpdate{
			UID:             imap.UID(uid),
			BitwiseFlags:    bitwise,
			IsExpunge:       expungedAt.Valid,
			IsNew:           !expungedAt.Valid && created.Valid && uint64(created.Int64) > sinceModSeq,
			FlagsAreInitial: initial.Valid && updated.Valid && initial.Int64 == updated.Int64,
			CustomFlags:     customFlags,
			EffectiveModSeq: effective,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating raw changes: %w", err)
	}

	pollData := MailboxPoll{
		Updates:       []MessageUpdate{},
		NumMessages:   uint32(messageCount),
		ModSeq:        currentModSeq,
		HighestUID:    imap.UID(uidNext),
		PhantomModSeq: phantomModSeq,
	}

	if len(rawUpdates) == 0 {
		return &pollData, nil
	}

	// Phase 2: Dynamic Sequence Hydration
	// Using Bidirectional Sequence Counting: If the requested UID is in the second half of the mailbox,
	// we count BACKWARDS from the total active message count instead of FORWARDS from zero.
	// This reduces O(N) index scans down to O(1) for recent updates.
	// For dense updates, we fall back to a single sequential stream to avoid O(K*N) Postgres load.

	if len(rawUpdates) <= 50 {
		// The totals the backward counts subtract from are computed ONCE per poll: the
		// live active count is already in hand (messageCount above), and the client's
		// pre-poll total is one query. They used to be re-evaluated inside every queued
		// statement — a full-mailbox COUNT(*) per updated message, so a STORE over 50
		// recent messages in a 100k mailbox cost every session's next poll ~50 index
		// scans. Every statement reads the poll's one snapshot, so the hoisted totals are
		// exactly what each statement would have counted itself.
		var clientTotal int
		clientTotalKnown := false
		batch := &pgx.Batch{}
		for _, u := range rawUpdates {
			if !u.IsExpunge {
				if uint32(u.UID) > (uidNext / 2) {
					// Count backwards: TotalActive - COUNT(Active > Target)
					batch.Queue(`
						SELECT $3::int - COUNT(*)::int FROM messages
						WHERE mailbox_id = $1 AND expunged_at IS NULL AND uid > $2
					`, mailboxID, u.UID, messageCount)
				} else {
					// Count forwards: COUNT(Active <= Target)
					batch.Queue(`
						SELECT COUNT(*)::int FROM messages 
						WHERE mailbox_id = $1 AND expunged_at IS NULL AND uid <= $2
					`, mailboxID, u.UID)
				}
			} else {
				if uint32(u.UID) > (uidNext / 2) {
					// Expunged backward count. The expunge sequence number must be the message's
					// position in the CLIENT's pre-poll view: messages it already knew
					// (created_modseq <= sinceModSeq) that it has not yet been told are gone
					// (expunged_at IS NULL OR expunged_modseq > sinceModSeq). Restricting every term to
					// created_modseq <= sinceModSeq keeps messages added in this same poll (and
					// create+expunge-in-window phantoms) out of the count.
					// ClientTotal = ClientKnownActive + ClientKnownExpungedSince
					// SeqNum = ClientTotal - COUNT(ClientView AND uid > Target)
					if !clientTotalKnown {
						if err := tx.QueryRow(ctx, `
							SELECT COUNT(*)::int FROM messages
							WHERE mailbox_id = $1 AND created_modseq <= $2
							  AND (expunged_at IS NULL OR expunged_modseq > $2)
						`, mailboxID, sinceModSeq).Scan(&clientTotal); err != nil {
							return nil, fmt.Errorf("failed to count the client's pre-poll view: %w", err)
						}
						clientTotalKnown = true
					}
					batch.Queue(`
						SELECT $4::int - COUNT(*)::int
						FROM messages
						WHERE mailbox_id = $1 AND created_modseq <= $2 AND (expunged_at IS NULL OR expunged_modseq > $2) AND uid > $3
					`, mailboxID, sinceModSeq, u.UID, clientTotal)
				} else {
					// Expunged forward count: client-view messages (created at/before sinceModSeq,
					// not yet acked as expunged) with uid <= target.
					batch.Queue(`
						SELECT COUNT(*)::int FROM messages
						WHERE mailbox_id = $1 AND created_modseq <= $2 AND (expunged_at IS NULL OR expunged_modseq > $2) AND uid <= $3
					`, mailboxID, sinceModSeq, u.UID)
				}
			}
		}

		br := tx.SendBatch(ctx, batch)
		for i := range rawUpdates {
			var seq uint32
			if err := br.QueryRow().Scan(&seq); err != nil {
				_ = br.Close()
				return nil, fmt.Errorf("failed to count sparse sequence: %w", err)
			}
			rawUpdates[i].SeqNum = seq
		}
		if err := br.Close(); err != nil {
			return nil, fmt.Errorf("failed to close sparse sequence batch: %w", err)
		}
	} else {
		// Dense stream
		interestedUIDs := make(map[uint32]bool, len(rawUpdates))
		for _, u := range rawUpdates {
			interestedUIDs[uint32(u.UID)] = true
		}
		seqMap := make(map[uint32]uint32, len(rawUpdates))

		// OPTIMIZATION: Using expunged_at IS NULL matches the active partial covering index.
		seqRows, err := tx.Query(ctx, `
			SELECT uid, expunged_modseq
			FROM messages
			WHERE mailbox_id = $1 AND (expunged_at IS NULL OR (expunged_modseq > $2 AND created_modseq <= $2))
			ORDER BY uid ASC
		`, mailboxID, sinceModSeq)
		if err != nil {
			return nil, fmt.Errorf("failed to query sequences: %w", err)
		}
		defer seqRows.Close()

		activeCount := uint32(0)
		expungedOffset := uint32(0)

		for seqRows.Next() {
			var uid uint32
			var exp sql.NullInt64
			if err := seqRows.Scan(&uid, &exp); err != nil {
				return nil, fmt.Errorf("failed to scan sequence row: %w", err)
			}
			if !exp.Valid {
				activeCount++
			} else {
				expungedOffset++
			}

			if interestedUIDs[uid] {
				if !exp.Valid {
					seqMap[uid] = activeCount
				} else {
					seqMap[uid] = activeCount + expungedOffset
				}
				if len(seqMap) == len(interestedUIDs) {
					break // Early exit: all modified messages mapped
				}
			}
		}
		if err := seqRows.Err(); err != nil {
			return nil, fmt.Errorf("error iterating sequences: %w", err)
		}

		for i := range rawUpdates {
			rawUpdates[i].SeqNum = seqMap[uint32(rawUpdates[i].UID)]
		}
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
