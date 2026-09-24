package db

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
)

// DeletedMessage represents a deleted message with its original location
type DeletedMessage struct {
	ID           int64
	UID          int64
	ContentHash  string
	MailboxPath  string // effective mailbox name: the live mailbox's current name, or the stored string for an orphan
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

// effectiveMailboxName is the SQL expression for "where this expunged message lived".
//
// While the mailbox still exists, its CURRENT name is the truth, so a rename does not
// have to rewrite messages.mailbox_path for every message it owns (that rewrite was a
// non-HOT update of every row, propagating into all 30 indexes on messages — seconds of
// work and gigabytes of WAL for a large mailbox, all while holding the mailboxes row
// lock that every delivery needs).
//
// The denormalized string is the fallback for orphans only: messages.mailbox_id is
// ON DELETE SET NULL, so once a mailbox is hard-deleted the string is the sole surviving
// record of where its messages were. DeleteMailbox stamps it (for live AND already-expunged
// rows) immediately before deleting the mailbox rows, which is the moment it starts to matter.
//
// The join deliberately does not filter on mb.deleted_at: a soft-deleted mailbox still
// names where the message lived, and its rows are hard-deleted (and stamped) by the purge.
const effectiveMailboxName = `COALESCE(mb.name, m.mailbox_path)`

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
			COALESCE(` + effectiveMailboxName + `, ''),
			m.mailbox_id,
			m.subject,
			m.message_id,
			m.internal_date,
			m.expunged_at,
			m.size
		FROM messages m
		LEFT JOIN mailboxes mb ON mb.id = m.mailbox_id
		WHERE m.account_id = $1
		  AND m.expunged_at IS NOT NULL
	`

	args := []any{accountID}
	argPos := 2

	if params.MailboxPath != nil {
		// Match the mailbox the row belongs to NOW, and case-insensitively: mailbox names
		// are case-insensitively unique (migration 000041) and the restore path resolves
		// them with LOWER(), so a byte-exact filter here only ever hid rows.
		query += fmt.Sprintf(" AND LOWER(%s) = LOWER($%d)", effectiveMailboxName, argPos)
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

// rowsQuerier is the multi-row counterpart of rowQuerier.
type rowsQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
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

// restoreFilters returns the FROM/WHERE shared by every restore query for params, and
// its arguments. Columns and aliases follow effectiveMailboxName (m, mb).
func restoreFilters(accountID int64, params RestoreMessagesParams) (string, []any) {
	query := `
		FROM messages m
		LEFT JOIN mailboxes mb ON mb.id = m.mailbox_id
		WHERE m.account_id = $1
		  AND m.expunged_at IS NOT NULL
	`
	args := []any{accountID}
	argPos := 2

	if len(params.MessageIDs) > 0 {
		query += fmt.Sprintf(" AND m.id = ANY($%d::bigint[])", argPos)
		args = append(args, params.MessageIDs)
		argPos++
	} else {
		// If no specific message IDs, use other filters
		if params.MailboxPath != nil {
			// Effective name, case-insensitively — see ListDeletedMessages.
			query += fmt.Sprintf(" AND LOWER(%s) = LOWER($%d)", effectiveMailboxName, argPos)
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
	}
	return query, args
}

// restoreCandidatesQuery builds the SELECT that identifies the expunged rows matching
// params (the same predicate for listing and for restoring). Rows are ordered by
// (effective mailbox name, internal_date, id) so restored messages receive new UIDs in
// arrival order per mailbox — deterministic regardless of physical row order or batching.
// Callers pass columns qualified with the m/mb aliases (see effectiveMailboxName).
//
// A criteria-based restore (mailbox / since / until) leaves out rows that can be routed
// nowhere — no live mailbox and no recorded mailbox_path — just as it skips candidates
// that were already restored or purged. Left in, such a row sorted last (NULL), took the
// final chunk down with it, and kept every real message in that chunk unrestorable on
// every re-run. See warnUnroutableCandidates. When the admin names the ids explicitly,
// the row stays in and RestoreMessages fails loudly on it.
func restoreCandidatesQuery(accountID int64, params RestoreMessagesParams, columns string) (string, []any) {
	filters, args := restoreFilters(accountID, params)
	query := `SELECT ` + columns + filters
	if len(params.MessageIDs) == 0 {
		query += " AND " + effectiveMailboxName + " IS NOT NULL"
	}
	query += " ORDER BY " + effectiveMailboxName + ", m.internal_date, m.id"
	return query, args
}

// maxUnroutableIDsLogged caps how many skipped ids one warning names.
const maxUnroutableIDsLogged = 50

// warnUnroutableCandidates logs, at WARN and by id, the rows a criteria-based restore
// matched but left out because they can be routed nowhere, so an operator can find them
// (they are listed with an empty mailbox) and decide what to do. No-op for id restores.
func warnUnroutableCandidates(ctx context.Context, q rowsQuerier, accountID int64, params RestoreMessagesParams) error {
	if len(params.MessageIDs) > 0 {
		return nil
	}
	filters, args := restoreFilters(accountID, params)
	rows, err := q.Query(ctx, `SELECT m.id`+filters+" AND "+effectiveMailboxName+" IS NULL ORDER BY m.id", args...)
	if err != nil {
		return fmt.Errorf("failed to query unroutable restore candidates: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return fmt.Errorf("failed to collect unroutable restore candidates: %w", err)
	}
	if len(ids) == 0 {
		return nil
	}
	named := ids
	if len(named) > maxUnroutableIDsLogged {
		named = named[:maxUnroutableIDsLogged]
	}
	logger.Warn("Database: restore skipped messages with no mailbox and no recorded mailbox path; name them with explicit ids to see the error",
		"account_id", accountID, "count", len(ids), "message_ids", named)
	return nil
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

	if err := warnUnroutableCandidates(ctx, pool, accountID, params); err != nil {
		return nil, err
	}

	query, args := restoreCandidatesQuery(accountID, params, "m.id")
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

	if err := warnUnroutableCandidates(ctx, tx, accountID, params); err != nil {
		return 0, err
	}

	query, args := restoreCandidatesQuery(accountID, params,
		"m.id, "+effectiveMailboxName+", m.message_id, m.content_hash")
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to query messages for restoration: %w", err)
	}
	defer rows.Close()

	// Collect messages and their target mailboxes
	type msgToRestore struct {
		id          int64
		mailboxName string // effective name: live mailbox's current name, else the stored string
		messageID   string
		contentHash string // for the per-object lock shared with the cleaner
	}

	var messagesToRestore []msgToRestore
	mailboxNames := make(map[string]bool)

	for rows.Next() {
		var msg msgToRestore
		var mailboxName *string
		err := rows.Scan(&msg.id, &mailboxName, &msg.messageID, &msg.contentHash)
		if err != nil {
			return 0, fmt.Errorf("failed to scan message for restoration: %w", err)
		}
		if mailboxName == nil {
			// The row has no mailbox (hard-deleted, mailbox_id nulled by the FK) AND no
			// recorded mailbox_path, so there is no sane target. Fail loudly (naming the
			// row) rather than guess.
			return 0, fmt.Errorf("message %d has no mailbox and no recorded mailbox path and cannot be restored", msg.id)
		}
		msg.mailboxName = *mailboxName
		messagesToRestore = append(messagesToRestore, msg)
		mailboxNames[msg.mailboxName] = true
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("error iterating messages for restoration: %w", err)
	}

	if len(messagesToRestore) == 0 {
		return 0, nil
	}

	// Ensure all required mailboxes exist, recreating any that were deleted. Shallow
	// names first, so a run's work is deterministic (map iteration is random);
	// restoreMailbox recreates missing ancestors itself, so correctness does not depend
	// on this order.
	names := make([]string, 0, len(mailboxNames))
	for name := range mailboxNames {
		names = append(names, name)
	}
	delim := string(consts.MailboxDelimiter)
	sort.Slice(names, func(i, j int) bool {
		di, dj := strings.Count(names[i], delim), strings.Count(names[j], delim)
		if di != dj {
			return di < dj
		}
		return names[i] < names[j]
	})

	mailboxIDMap := make(map[string]int64)
	for _, mailboxName := range names {
		mailboxID, _, err := restoreMailbox(ctx, tx, accountID, mailboxName, false)
		if err != nil {
			return 0, err
		}
		mailboxIDMap[mailboxName] = mailboxID
	}

	// Restore messages by clearing expunged_at and updating mailbox_id
	var restoredCount int64
	var skippedCount int64
	for _, msg := range messagesToRestore {
		targetMailboxID := mailboxIDMap[msg.mailboxName]

		// Re-check the row under this transaction, and look for a live copy of the same
		// Message-ID in the TARGET mailbox. It is valid to have the same Message-ID in
		// different mailboxes (e.g. INBOX + Sent), but restoring never produces a second
		// live copy inside one mailbox — including a copy restored earlier in this run or
		// in a previous chunk. The row itself may have vanished since the candidate list was
		// built (already restored by a concurrent run, or purged by the cleaner); that is a
		// skip, not an error, so a restore is always safe to re-run.
		// Hold the object's lock while the row comes back to life: the cleaner takes
		// the same lock (session try-lock) around "confirm orphan → delete object",
		// so a restore can no longer slip between its check and its delete and leave a
		// live row whose object is gone.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", GetS3ObjectLockID(accountID, msg.contentHash)); err != nil {
			return 0, fmt.Errorf("failed to lock object for message %d: %w", msg.id, err)
		}

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
			logger.Info("Database: skipping message restoration: message no longer expunged or already removed", "id", msg.id, "mailbox", msg.mailboxName)
			skippedCount++
			continue
		}

		if existingCount > 0 {
			// A non-expunged copy already exists in the target mailbox, skip restoration
			logger.Info("Database: skipping message restoration: message already exists in target mailbox", "id", msg.id, "mailbox", msg.mailboxName)
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

		// Restore the message's state and clear the \Deleted flag (FlagDeleted = 8,
		// bit 3). An upsert, not an UPDATE: the row is missing for any message whose
		// mailbox was purged by an older build (the FK cascade deleted it), and a bare
		// UPDATE then matched nothing and reported success — leaving a live message with
		// no state row, on which every later STORE silently did nothing. With nothing
		// left to recover, such a message comes back unread and keyword-less.
		_, err = tx.Exec(ctx, `
			INSERT INTO message_state (message_id, mailbox_id, flags, custom_flags, flags_changed_at, updated_modseq)
			VALUES ($1, $2, 0, '[]'::jsonb, now(), nextval('messages_modseq'))
			ON CONFLICT (message_id) DO UPDATE
			SET mailbox_id = EXCLUDED.mailbox_id,
			    flags = message_state.flags & ~8,
			    flags_changed_at = EXCLUDED.flags_changed_at,
			    updated_modseq = EXCLUDED.updated_modseq
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

	// Recompute unseen_count for every touched target mailbox. The database trigger on
	// messages joins on ms.mailbox_id = o.mailbox_id, which cannot match for an orphan
	// (o.mailbox_id IS NULL) or cross-mailbox restore, treating every restored message
	// as an unseen arrival and drifting unseen_count up by 1 per \Seen message.
	for _, targetMailboxID := range mailboxIDMap {
		if _, err := d.RecomputeMailboxUnseen(ctx, tx, targetMailboxID); err != nil {
			return 0, fmt.Errorf("failed to recompute unseen count for mailbox %d: %w", targetMailboxID, err)
		}
	}

	return restoredCount, nil
}

// restoreMailbox returns the id and path of the live mailbox called name, recreating it
// if it was deleted — linked under its parent, which is itself recreated first if it is
// gone too. A recreated "Parent/Child" used to land at the root: the name still showed
// the hierarchy in LIST, but the tree is path-based, so the parent lost \HasChildren,
// RENAME of the parent stopped carrying the child, and a later DELETE of the parent
// succeeded and stranded it.
//
// asParent takes FOR KEY SHARE on an existing mailbox that is about to receive a
// recreated child — the same lock createMailbox takes — so the parent cannot be
// soft-deleted underneath the child (see SoftDeleteMailbox).
func restoreMailbox(ctx context.Context, tx pgx.Tx, accountID int64, name string, asParent bool) (int64, string, error) {
	lookup := `SELECT id, path FROM mailboxes WHERE account_id = $1 AND LOWER(name) = LOWER($2) AND deleted_at IS NULL`
	if asParent {
		lookup += ` FOR KEY SHARE`
	}
	var mailboxID int64
	var path string
	err := tx.QueryRow(ctx, lookup, accountID, name).Scan(&mailboxID, &path)
	if err == nil {
		return mailboxID, path, nil
	}
	if err != pgx.ErrNoRows {
		return 0, "", fmt.Errorf("failed to check mailbox %s: %w", name, err)
	}

	// Gone: recreate its parent first, so this one can be linked under it.
	var parentPath string
	if i := strings.LastIndex(name, string(consts.MailboxDelimiter)); i > 0 {
		if _, parentPath, err = restoreMailbox(ctx, tx, accountID, name[:i], true); err != nil {
			return 0, "", err
		}
	}

	// Re-seed the RFC 6154 special-use attribute for a canonical top-level default name
	// (consistent with CreateDefaultMailboxes / migration 000045), but ONLY if the
	// attribute is not already held by another live mailbox — so a restore never
	// violates the (account_id, special_use) unique index nor duplicates special-use.
	// ON CONFLICT tolerates a concurrent recreate of the same name; its row is then
	// re-read below.
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
	`, accountID, name).Scan(&mailboxID)
	if err == pgx.ErrNoRows {
		// Concurrent recreate won the race; use its row as it is.
		err = tx.QueryRow(ctx, lookup, accountID, name).Scan(&mailboxID, &path)
		if err != nil {
			return 0, "", fmt.Errorf("failed to create mailbox %s: %w", name, err)
		}
		return mailboxID, path, nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("failed to create mailbox %s: %w", name, err)
	}

	// The path needs the id, so it is set once the row exists.
	path = helpers.GetMailboxPath(parentPath, mailboxID)
	if _, err := tx.Exec(ctx, `UPDATE mailboxes SET path = $1 WHERE id = $2`, path, mailboxID); err != nil {
		return 0, "", fmt.Errorf("failed to update path for mailbox %s: %w", name, err)
	}
	return mailboxID, path, nil
}
