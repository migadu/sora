package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
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
	accountID, err := restoreAccountID(ctx, d.GetReadPool(), params.Email)
	if err != nil {
		return nil, err
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

// rowQuerier is the subset of pgx.Tx / *pgxpool.Pool used by the restore helpers so
// the same account lookup and candidate query can run inside a transaction or on the
// read pool.
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// restoreAccountID resolves the live account behind an address for restore operations.
func restoreAccountID(ctx context.Context, q rowQuerier, email string) (int64, error) {
	var accountID int64
	err := q.QueryRow(ctx, `
		SELECT a.id
		FROM accounts a
		JOIN credentials c ON a.id = c.account_id
		WHERE LOWER(c.address) = LOWER($1::text) AND a.deleted_at IS NULL
		LIMIT 1
	`, email).Scan(&accountID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return 0, fmt.Errorf("%w: %s", ErrAccountNotFound, email)
		}
		return 0, fmt.Errorf("failed to get account ID: %w", err)
	}
	return accountID, nil
}

// restoreCandidatesQuery builds the SELECT that identifies the expunged rows matching
// params (the same predicate for listing and for restoring). Rows are ordered by
// (mailbox_path, internal_date, id) so restored messages receive new UIDs in arrival
// order per mailbox — deterministic regardless of physical row order or batching.
func restoreCandidatesQuery(accountID int64, params RestoreMessagesParams, columns string) (string, []any) {
	query := `
		SELECT ` + columns + `
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

	query += " ORDER BY mailbox_path, internal_date, id"
	return query, args
}

// GetRestorableMessageIDs returns the ids of the expunged messages that RestoreMessages
// would act on for params, in restore order. Callers use it to split a large restore
// into bounded transactions (see ResilientDatabase.RestoreMessagesWithRetry): the ids
// are then passed back through RestoreMessagesParams.MessageIDs chunk by chunk.
func (d *Database) GetRestorableMessageIDs(ctx context.Context, params RestoreMessagesParams) ([]int64, error) {
	pool := d.GetReadPoolWithContext(ctx)
	accountID, err := restoreAccountID(ctx, pool, params.Email)
	if err != nil {
		return nil, err
	}

	query, args := restoreCandidatesQuery(accountID, params, "id")
	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages for restoration: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan message for restoration: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating messages for restoration: %w", err)
	}
	return ids, nil
}

// RestoreMessages restores deleted messages back to their original mailboxes
// It recreates mailboxes if they no longer exist.
//
// Every candidate is handled with a fixed number of statements inside the caller's
// transaction, so the caller must bound the batch (see RestoreMessagesWithRetry, which
// resolves the ids first and restores them in chunks, each in its own transaction).
// A candidate that has meanwhile been restored or purged is skipped, not an error, so
// a restore can always be re-run to pick up whatever is still expunged.
func (d *Database) RestoreMessages(ctx context.Context, tx pgx.Tx, params RestoreMessagesParams) (int64, error) {
	accountID, err := restoreAccountID(ctx, tx, params.Email)
	if err != nil {
		return 0, err
	}

	query, args := restoreCandidatesQuery(accountID, params, "id, mailbox_path, mailbox_id, message_id")
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
		messageID   string
	}

	var messagesToRestore []msgToRestore
	mailboxPaths := make(map[string]bool)

	for rows.Next() {
		var msg msgToRestore
		var mailboxPath *string
		err := rows.Scan(&msg.id, &mailboxPath, &msg.mailboxID, &msg.messageID)
		if err != nil {
			return 0, fmt.Errorf("failed to scan message for restoration: %w", err)
		}
		if mailboxPath == nil {
			// mailbox_path is what routes a tombstone back to its mailbox; without it there
			// is no sane target. Fail loudly (naming the row) rather than guess.
			return 0, fmt.Errorf("message %d has no recorded mailbox path and cannot be restored", msg.id)
		}
		msg.mailboxPath = *mailboxPath
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
			WHERE account_id = $1 AND LOWER(name) = LOWER($2) AND deleted_at IS NULL
		`, accountID, mailboxPath).Scan(&mailboxID)

		if err == pgx.ErrNoRows {
			// Mailbox was deleted along with its messages; recreate it. Re-seed the
			// RFC 6154 special-use attribute for a canonical top-level default name
			// (consistent with CreateDefaultMailboxes / migration 000045), but ONLY
			// if the attribute is not already held by another live mailbox — so a
			// restore never violates the (account_id, special_use) unique index nor
			// duplicates special-use. ON CONFLICT tolerates a concurrent recreate of
			// the same name; the id is then re-fetched below.
			err = tx.QueryRow(ctx, `
				INSERT INTO mailboxes (account_id, name, uid_validity, created_at, updated_at, path, special_use)
				SELECT $1, $2, extract(epoch from now())::bigint, now(), now(), '',
					CASE WHEN canon.su IS NOT NULL
					          AND NOT EXISTS (SELECT 1 FROM mailboxes m2
					                          WHERE m2.account_id = $1 AND m2.special_use = canon.su AND m2.deleted_at IS NULL)
					     THEN canon.su END
				FROM (SELECT CASE LOWER($2)
					WHEN 'sent'    THEN '\Sent'
					WHEN 'drafts'  THEN '\Drafts'
					WHEN 'archive' THEN '\Archive'
					WHEN 'junk'    THEN '\Junk'
					WHEN 'trash'   THEN '\Trash'
				END AS su) canon
				ON CONFLICT (account_id, LOWER(name)) WHERE deleted_at IS NULL DO NOTHING
				RETURNING id
			`, accountID, mailboxPath).Scan(&mailboxID)
			if err == pgx.ErrNoRows {
				// Concurrent recreate won the race; fetch the existing row's id.
				err = tx.QueryRow(ctx, `
					SELECT id FROM mailboxes WHERE account_id = $1 AND LOWER(name) = LOWER($2) AND deleted_at IS NULL
				`, accountID, mailboxPath).Scan(&mailboxID)
			}
			if err != nil {
				return 0, fmt.Errorf("failed to create mailbox %s: %w", mailboxPath, err)
			}

			// Update the path now that we have the mailbox ID
			// This prevents the mailbox from being left with an empty path
			computedPath := helpers.GetMailboxPath("", mailboxID) // Root-level mailbox
			_, err = tx.Exec(ctx, `
				UPDATE mailboxes SET path = $1 WHERE id = $2
			`, computedPath, mailboxID)
			if err != nil {
				return 0, fmt.Errorf("failed to update path for mailbox %s: %w", mailboxPath, err)
			}
		} else if err != nil {
			return 0, fmt.Errorf("failed to check mailbox %s: %w", mailboxPath, err)
		}

		mailboxIDMap[mailboxPath] = mailboxID
	}

	// Restore messages by clearing expunged_at and updating mailbox_id
	var restoredCount int64
	var skippedCount int64
	for _, msg := range messagesToRestore {
		targetMailboxID := mailboxIDMap[msg.mailboxPath]

		// Re-check the row under this transaction, and look for a live copy of the same
		// Message-ID in the TARGET mailbox. It is valid to have the same Message-ID in
		// different mailboxes (e.g. INBOX + Sent), but restoring never produces a second
		// live copy inside one mailbox — including a copy restored earlier in this run or
		// in a previous chunk. The row itself may have vanished since the candidate list was
		// built (already restored by a concurrent run, or purged by the cleaner); that is a
		// skip, not an error, so a restore is always safe to re-run.
		var restorable bool
		var existingCount int
		err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM messages WHERE id = $1 AND expunged_at IS NOT NULL),
			       (SELECT COUNT(*) FROM messages
			         WHERE account_id = $2 AND mailbox_id = $3 AND message_id = $4 AND expunged_at IS NULL)
		`, msg.id, accountID, targetMailboxID, msg.messageID).Scan(&restorable, &existingCount)
		if err != nil {
			return 0, fmt.Errorf("failed to check restore preconditions for message %d: %w", msg.id, err)
		}

		if !restorable {
			logger.Info("Database: skipping message restoration: message no longer expunged or already removed", "id", msg.id, "mailbox_path", msg.mailboxPath)
			skippedCount++
			continue
		}

		if existingCount > 0 {
			// A non-expunged copy already exists in the target mailbox, skip restoration
			logger.Info("Database: skipping message restoration: message already exists in target mailbox", "id", msg.id, "mailbox_path", msg.mailboxPath)
			skippedCount++
			continue
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
		_, err = tx.Exec(ctx, `
			UPDATE message_state
			SET mailbox_id = $2,
			    flags = flags & ~8,
			    flags_changed_at = now(),
			    updated_modseq = nextval('messages_modseq')
			WHERE message_id = $1
		`, msg.id, targetMailboxID)
		if err != nil {
			return 0, fmt.Errorf("failed to restore message_state for message %d: %w", msg.id, err)
		}

		result, err := tx.Exec(ctx, `
			UPDATE messages
			SET expunged_at = NULL,
			    expunged_modseq = NULL,
			    mailbox_id = $2,
			    uid = $3,
			    updated_at = now()
			WHERE id = $1 AND expunged_at IS NOT NULL
		`, msg.id, targetMailboxID, nextUID)
		if err != nil {
			return 0, fmt.Errorf("failed to restore message %d: %w", msg.id, err)
		}

		restoredCount += result.RowsAffected()
	}

	if skippedCount > 0 {
		logger.Info("Database: skipped restoring messages that already exist in target mailboxes or are no longer expunged", "count", skippedCount)
	}

	return restoredCount, nil
}
