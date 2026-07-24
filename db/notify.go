package db

import (
	"context"
	"fmt"
)

// MailboxStatsRow is one per-mailbox statistics row used by the IMAP NOTIFY
// (RFC 5465) fan-in poll: everything needed to build an unsolicited STATUS
// response without touching the messages table.
type MailboxStatsRow struct {
	MailboxID     int64
	HighestModSeq uint64
	MessageCount  uint32
	UnseenCount   uint32
	HighestUID    uint32 // UIDNEXT = HighestUID + 1
}

// PollMailboxStats returns the statistics of every given mailbox whose
// highest_modseq advanced past sinceModSeq. It is the account-level change
// detector for NOTIFY watches: one cheap indexed query per poll tick instead
// of a per-mailbox PollMailbox. Mailboxes without changes (or without any
// messages yet, i.e. no mailbox_stats row) are not returned.
//
// The modseq values come from the global messages_modseq sequence, so they
// are comparable across all mailboxes of the account and the caller can keep
// a single monotonic cursor. Reads honor the session's master-DB pinning via
// GetReadPoolWithContext; a lagged replica delays change detection but never
// loses it (the cursor only advances to what was actually observed).
func (db *Database) PollMailboxStats(ctx context.Context, mailboxIDs []int64, sinceModSeq uint64) ([]MailboxStatsRow, error) {
	if len(mailboxIDs) == 0 {
		return nil, nil
	}

	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT ms.mailbox_id, ms.highest_modseq, ms.message_count, ms.unseen_count, mb.highest_uid
		FROM mailbox_stats ms
		JOIN mailboxes mb ON mb.id = ms.mailbox_id
		WHERE ms.mailbox_id = ANY($1) AND ms.highest_modseq > $2 AND mb.deleted_at IS NULL
	`, mailboxIDs, int64(sinceModSeq))
	if err != nil {
		return nil, fmt.Errorf("failed to poll mailbox stats: %w", err)
	}
	defer rows.Close()

	return scanMailboxStatsRows(rows)
}

// GetMailboxesStats returns the statistics of all given mailboxes, including
// mailboxes that have never had a message (no mailbox_stats row yet). It is
// used to bootstrap a NOTIFY watch: initializing the change cursor and
// producing the initial STATUS responses of NOTIFY SET STATUS (RFC 5465
// section 3.1), which are due for every matching mailbox, empty or not.
func (db *Database) GetMailboxesStats(ctx context.Context, mailboxIDs []int64) ([]MailboxStatsRow, error) {
	if len(mailboxIDs) == 0 {
		return nil, nil
	}

	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT mb.id, COALESCE(ms.highest_modseq, 0), COALESCE(ms.message_count, 0), COALESCE(ms.unseen_count, 0), mb.highest_uid
		FROM mailboxes mb
		LEFT JOIN mailbox_stats ms ON ms.mailbox_id = mb.id
		WHERE mb.id = ANY($1) AND mb.deleted_at IS NULL
	`, mailboxIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get mailbox stats: %w", err)
	}
	defer rows.Close()

	return scanMailboxStatsRows(rows)
}

func scanMailboxStatsRows(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]MailboxStatsRow, error) {
	var result []MailboxStatsRow
	for rows.Next() {
		var (
			mailboxID     int64
			highestModSeq int64
			messageCount  int64
			unseenCount   int64
			highestUID    int64
		)
		if err := rows.Scan(&mailboxID, &highestModSeq, &messageCount, &unseenCount, &highestUID); err != nil {
			return nil, fmt.Errorf("failed to scan mailbox stats row: %w", err)
		}
		result = append(result, MailboxStatsRow{
			MailboxID:     mailboxID,
			HighestModSeq: uint64(highestModSeq),
			MessageCount:  uint32(messageCount),
			UnseenCount:   uint32(unseenCount),
			HighestUID:    uint32(highestUID),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating mailbox stats rows: %w", err)
	}
	return result, nil
}
