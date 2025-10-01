package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DeletedMessage represents a deleted message with its original location
type DeletedMessage struct {
	ID           int64
	UID          int64
	ContentHash  string
	MailboxPath  string
	MailboxID    *int64 // nil if mailbox was deleted
	Subject      string
	MessageID    string
	InternalDate time.Time
	ExpungedAt   time.Time
	Size         int
}

// ListDeletedMessagesParams defines the search criteria for deleted messages
type ListDeletedMessagesParams struct {
	Email       string
	MailboxPath *string
	Since       *time.Time
	Until       *time.Time
	Limit       int
}

// ListDeletedMessages returns messages that have been deleted (expunged)
// matching the given criteria
func (d *Database) ListDeletedMessages(ctx context.Context, params ListDeletedMessagesParams) ([]DeletedMessage, error) {
	// First, get the account ID from the email
	var accountID int64
	err := d.GetReadPool().QueryRow(ctx, `
		SELECT a.id
		FROM accounts a
		JOIN credentials c ON a.id = c.account_id
		WHERE LOWER(c.address) = LOWER($1::text) AND a.deleted_at IS NULL
		LIMIT 1
	`, params.Email).Scan(&accountID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("account not found: %s", params.Email)
		}
		return nil, fmt.Errorf("failed to get account ID for %q: %w", params.Email, err)
	}

	// Build the query with optional filters
	query := `
		SELECT
			m.id,
			m.uid,
			m.content_hash,
			m.mailbox_path,
			m.mailbox_id,
			m.subject,
			m.message_id,
			m.internal_date,
			m.expunged_at,
			m.size
		FROM messages m
		WHERE m.account_id = $1
		  AND m.expunged_at IS NOT NULL
	`

	args := []interface{}{accountID}
	argPos := 2

	if params.MailboxPath != nil {
		query += fmt.Sprintf(" AND m.mailbox_path = $%d", argPos)
		args = append(args, *params.MailboxPath)
		argPos++
	}

	if params.Since != nil {
		query += fmt.Sprintf(" AND m.expunged_at >= $%d", argPos)
		args = append(args, *params.Since)
		argPos++
	}

	if params.Until != nil {
		query += fmt.Sprintf(" AND m.expunged_at <= $%d", argPos)
		args = append(args, *params.Until)
		argPos++
	}

	query += " ORDER BY m.expunged_at DESC"

	if params.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argPos)
		args = append(args, params.Limit)
	}

	rows, err := d.GetReadPool().Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list deleted messages: %w", err)
	}
	defer rows.Close()

	var messages []DeletedMessage
	for rows.Next() {
		var msg DeletedMessage
		err := rows.Scan(
			&msg.ID,
			&msg.UID,
			&msg.ContentHash,
			&msg.MailboxPath,
			&msg.MailboxID,
			&msg.Subject,
			&msg.MessageID,
			&msg.InternalDate,
			&msg.ExpungedAt,
			&msg.Size,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan deleted message: %w", err)
		}
		messages = append(messages, msg)
	}

	return messages, rows.Err()
}

// RestoreMessagesParams defines the criteria for restoring messages
type RestoreMessagesParams struct {
	Email       string
	MessageIDs  []int64    // Specific message IDs to restore
	MailboxPath *string    // Restore all messages from this mailbox
	Since       *time.Time // Restore messages deleted since this time
	Until       *time.Time // Restore messages deleted until this time
}

// RestoreMessages restores deleted messages back to their original mailboxes
// It recreates mailboxes if they no longer exist
func (d *Database) RestoreMessages(ctx context.Context, tx pgx.Tx, params RestoreMessagesParams) (int64, error) {
	// First, get the account ID from the email
	var accountID int64
	err := tx.QueryRow(ctx, `
		SELECT a.id
		FROM accounts a
		JOIN credentials c ON a.id = c.account_id
		WHERE LOWER(c.address) = LOWER($1) AND a.deleted_at IS NULL
		LIMIT 1
	`, params.Email).Scan(&accountID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return 0, fmt.Errorf("account not found: %s", params.Email)
		}
		return 0, fmt.Errorf("failed to get account ID: %w", err)
	}

	// Build query to select messages to restore
	query := `
		SELECT id, mailbox_path, mailbox_id
		FROM messages
		WHERE account_id = $1
		  AND expunged_at IS NOT NULL
	`

	args := []interface{}{accountID}
	argPos := 2

	if len(params.MessageIDs) > 0 {
		query += fmt.Sprintf(" AND id = ANY($%d::bigint[])", argPos)
		args = append(args, params.MessageIDs)
		argPos++
	} else {
		// If no specific message IDs, use other filters
		if params.MailboxPath != nil {
			query += fmt.Sprintf(" AND mailbox_path = $%d", argPos)
			args = append(args, *params.MailboxPath)
			argPos++
		}

		if params.Since != nil {
			query += fmt.Sprintf(" AND expunged_at >= $%d", argPos)
			args = append(args, *params.Since)
			argPos++
		}

		if params.Until != nil {
			query += fmt.Sprintf(" AND expunged_at <= $%d", argPos)
			args = append(args, *params.Until)
			argPos++
		}
	}

	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to query messages for restoration: %w", err)
	}
	defer rows.Close()

	// Collect messages and their target mailboxes
	type msgToRestore struct {
		id          int64
		mailboxPath string
		mailboxID   *int64
	}

	var messagesToRestore []msgToRestore
	mailboxPaths := make(map[string]bool)

	for rows.Next() {
		var msg msgToRestore
		err := rows.Scan(&msg.id, &msg.mailboxPath, &msg.mailboxID)
		if err != nil {
			return 0, fmt.Errorf("failed to scan message for restoration: %w", err)
		}
		messagesToRestore = append(messagesToRestore, msg)
		mailboxPaths[msg.mailboxPath] = true
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("error iterating messages for restoration: %w", err)
	}

	if len(messagesToRestore) == 0 {
		return 0, nil
	}

	// Ensure all required mailboxes exist, create them if they don't
	mailboxIDMap := make(map[string]int64)
	for mailboxPath := range mailboxPaths {
		var mailboxID int64
		err := tx.QueryRow(ctx, `
			SELECT id FROM mailboxes
			WHERE account_id = $1 AND name = $2
		`, accountID, mailboxPath).Scan(&mailboxID)

		if err == pgx.ErrNoRows {
			// Mailbox doesn't exist, create it
			err = tx.QueryRow(ctx, `
				INSERT INTO mailboxes (account_id, name, uid_validity, created_at, updated_at)
				VALUES ($1, $2, extract(epoch from now())::bigint, now(), now())
				RETURNING id
			`, accountID, mailboxPath).Scan(&mailboxID)
			if err != nil {
				return 0, fmt.Errorf("failed to create mailbox %s: %w", mailboxPath, err)
			}
		} else if err != nil {
			return 0, fmt.Errorf("failed to check mailbox %s: %w", mailboxPath, err)
		}

		mailboxIDMap[mailboxPath] = mailboxID
	}

	// Restore messages by clearing expunged_at and updating mailbox_id
	var restoredCount int64
	for _, msg := range messagesToRestore {
		targetMailboxID := mailboxIDMap[msg.mailboxPath]

		// Get next UID for the mailbox
		var nextUID int64
		err := tx.QueryRow(ctx, `
			UPDATE mailboxes
			SET highest_uid = highest_uid + 1
			WHERE id = $1
			RETURNING highest_uid
		`, targetMailboxID).Scan(&nextUID)
		if err != nil {
			return 0, fmt.Errorf("failed to get next UID for mailbox: %w", err)
		}

		// Restore the message
		result, err := tx.Exec(ctx, `
			UPDATE messages
			SET expunged_at = NULL,
			    expunged_modseq = NULL,
			    mailbox_id = $2,
			    uid = $3,
			    updated_at = now(),
			    updated_modseq = nextval('messages_modseq')
			WHERE id = $1
		`, msg.id, targetMailboxID, nextUID)
		if err != nil {
			return 0, fmt.Errorf("failed to restore message %d: %w", msg.id, err)
		}

		restoredCount += result.RowsAffected()
	}

	return restoredCount, nil
}
