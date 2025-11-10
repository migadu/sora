package db

import (
	"context"
	"fmt"
	"log"
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
			return nil, fmt.Errorf("%w: %s", ErrAccountNotFound, params.Email)
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

	args := []any{accountID}
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
			return 0, fmt.Errorf("%w: %s", ErrAccountNotFound, params.Email)
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

	args := []any{accountID}
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

	// Collect all message IDs being restored to exclude them from duplicate checks
	restoringMessageIDs := make([]int64, len(messagesToRestore))
	for i, msg := range messagesToRestore {
		restoringMessageIDs[i] = msg.id
	}

	// Restore messages by clearing expunged_at and updating mailbox_id
	var restoredCount int64
	var skippedCount int64
	for _, msg := range messagesToRestore {
		targetMailboxID := mailboxIDMap[msg.mailboxPath]

		// Get the message_id for this message
		var messageIDToRestore string
		err := tx.QueryRow(ctx, `SELECT message_id FROM messages WHERE id = $1`, msg.id).Scan(&messageIDToRestore)
		if err != nil {
			return 0, fmt.Errorf("failed to get message_id for message %d: %w", msg.id, err)
		}

		// Check if a non-expunged message with the same message_id already exists in the TARGET mailbox
		// EXCLUDING other messages in this restoration batch (to allow restoring multiple copies)
		// If so, skip restoration to avoid duplicate active copies in the same mailbox
		// Note: It's valid to have the same message_id in different mailboxes (e.g., INBOX + Sent)
		var existingCount int
		err = tx.QueryRow(ctx, `
			SELECT COUNT(*)
			FROM messages
			WHERE account_id = $1
			  AND mailbox_id = $2
			  AND expunged_at IS NULL
			  AND message_id = $3
			  AND id != ALL($4)
		`, accountID, targetMailboxID, messageIDToRestore, restoringMessageIDs).Scan(&existingCount)

		if err != nil {
			return 0, fmt.Errorf("failed to check for existing message in target mailbox: %w", err)
		}

		if existingCount > 0 {
			// A non-expunged copy already exists in the target mailbox, skip restoration
			log.Printf("Database: skipping message restoration: message already exists in target mailbox '%s'", msg.mailboxPath)
			skippedCount++
			continue
		}

		// Delete any expunged messages with the same message_id in the target mailbox
		// This prevents unique constraint violations when restoring
		// (e.g., when a message was moved from INBOX to Trash, the old INBOX row is expunged,
		// and the Trash row might also be expunged later, leaving expunged tombstones in both mailboxes)
		deleteResult, err := tx.Exec(ctx, `
			DELETE FROM messages
			WHERE account_id = $1
			  AND mailbox_id = $2
			  AND message_id = $3
			  AND id != $4
		`, accountID, targetMailboxID, messageIDToRestore, msg.id)
		if err != nil {
			return 0, fmt.Errorf("failed to delete conflicting messages: %w", err)
		}
		if deleteResult.RowsAffected() > 0 {
			log.Printf("Database: deleted %d conflicting message(s) with message_id='%s' from mailbox '%s' before restoration",
				deleteResult.RowsAffected(), messageIDToRestore, msg.mailboxPath)
		}

		// Get next UID for the mailbox
		var nextUID int64
		err = tx.QueryRow(ctx, `
			UPDATE mailboxes
			SET highest_uid = highest_uid + 1
			WHERE id = $1
			RETURNING highest_uid
		`, targetMailboxID).Scan(&nextUID)
		if err != nil {
			return 0, fmt.Errorf("failed to get next UID for mailbox: %w", err)
		}

		// Restore the message and clear the \Deleted flag
		// FlagDeleted = 8 (bit 3), so we use bitwise AND with NOT 8 to clear it
		result, err := tx.Exec(ctx, `
			UPDATE messages
			SET expunged_at = NULL,
			    expunged_modseq = NULL,
			    mailbox_id = $2,
			    uid = $3,
			    flags = flags & ~8,
			    flags_changed_at = now(),
			    updated_at = now(),
			    updated_modseq = nextval('messages_modseq')
			WHERE id = $1
		`, msg.id, targetMailboxID, nextUID)
		if err != nil {
			return 0, fmt.Errorf("failed to restore message %d: %w", msg.id, err)
		}

		restoredCount += result.RowsAffected()
	}

	if skippedCount > 0 {
		log.Printf("Database: skipped restoring %d messages that already exist in target mailboxes", skippedCount)
	}

	return restoredCount, nil
}
