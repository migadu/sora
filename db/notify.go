package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// NotifyMailbox is the minimal per-mailbox view the NOTIFY (RFC 5465) watch
// pump needs each tick: identity, name, UIDVALIDITY, subscription state and
// the owning account (to distinguish owned mailboxes from ACL-shared ones for
// the read-right check). It deliberately omits has_children/path/special_use,
// so the snapshot query avoids GetMailboxes' per-row has_children lookup —
// the dominant cost for accounts with many mailboxes, run on every tick of
// every watching session.
type NotifyMailbox struct {
	ID          int64
	Name        string
	UIDValidity uint32
	Subscribed  bool
	OwnerID     int64
}

// GetMailboxNotifySnapshot returns the accessible mailboxes of the account for
// the NOTIFY watch pump. Its access-control CTE mirrors GetMailboxes (owned +
// ACL-shared with the 'l' right + domain "anyone"), but the projection is
// trimmed to what the pump needs.
func (db *Database) GetMailboxNotifySnapshot(ctx context.Context, accountID int64) ([]NotifyMailbox, error) {
	ownerDomain, err := db.GetAccountDomain(ctx, accountID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to retrieve account domain: %w", err)
	}

	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		WITH accessible_mailboxes AS (
			SELECT id, name, uid_validity, account_id
			FROM mailboxes
			WHERE account_id = $1 AND deleted_at IS NULL
			UNION
			SELECT m.id, m.name, m.uid_validity, m.account_id
			FROM mailboxes m
			INNER JOIN mailbox_acls acl ON m.id = acl.mailbox_id
			WHERE m.is_shared = TRUE AND acl.account_id = $1
			  AND position('l' IN acl.rights) > 0 AND m.deleted_at IS NULL
			UNION
			SELECT m.id, m.name, m.uid_validity, m.account_id
			FROM mailboxes m
			INNER JOIN mailbox_acls anyone_acl ON m.id = anyone_acl.mailbox_id
			WHERE m.is_shared = TRUE AND m.owner_domain = $2
			  AND anyone_acl.identifier = 'anyone'
			  AND position('l' IN anyone_acl.rights) > 0 AND m.deleted_at IS NULL
		)
		SELECT m.id, m.name, m.uid_validity, m.account_id,
		       (subs.mailbox_name IS NOT NULL) AS subscribed
		FROM accessible_mailboxes m
		LEFT JOIN subscriptions subs ON subs.account_id = $1 AND LOWER(subs.mailbox_name) = LOWER(m.name)
	`, accountID, ownerDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to query notify snapshot: %w", err)
	}
	defer rows.Close()

	var result []NotifyMailbox
	for rows.Next() {
		var (
			m           NotifyMailbox
			uidValidity int64
		)
		if err := rows.Scan(&m.ID, &m.Name, &uidValidity, &m.OwnerID, &m.Subscribed); err != nil {
			return nil, fmt.Errorf("failed to scan notify snapshot row: %w", err)
		}
		m.UIDValidity = uint32(uidValidity)
		result = append(result, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating notify snapshot rows: %w", err)
	}
	return result, nil
}

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
