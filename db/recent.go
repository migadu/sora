package db

import (
	"context"
	"fmt"

	"github.com/emersion/go-imap/v2"
)

// CountMessagesGreaterThanUID counts messages in a given mailbox
// that have a UID greater than minUID and are not expunged.
func (d *Database) CountMessagesGreaterThanUID(ctx context.Context, mailboxID int64, minUID imap.UID) (uint32, error) {
	var count uint32
	query := `SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND uid > $2 AND expunged_at IS NULL`
	err := d.Pool.QueryRow(ctx, query, mailboxID, minUID).Scan(&count)
	if err != nil {
		// It's important to log the actual error for debugging.
		d.Pool.QueryRow(ctx, query, mailboxID, minUID).Scan(&count) // Example, adapt logging
		return 0, fmt.Errorf("CountMessagesGreaterThanUID: failed for mailbox %d, minUID %d: %w", mailboxID, minUID, err)
	}
	return count, nil
}
