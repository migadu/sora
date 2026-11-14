package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	imap "github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
)

// DBMessage represents a simplified message structure for API responses
type DBMessage struct {
	ID           int64     `json:"id"`
	UID          int64     `json:"uid"`
	MailboxID    int64     `json:"mailbox_id"`
	MailboxPath  string    `json:"mailbox_path"`
	Subject      string    `json:"subject"`
	From         string    `json:"from"`
	To           []string  `json:"to"`
	Cc           []string  `json:"cc,omitempty"`
	Bcc          []string  `json:"bcc,omitempty"`
	Date         time.Time `json:"date"`
	InternalDate time.Time `json:"internal_date"`
	Size         int       `json:"size"`
	Flags        []string  `json:"flags"`
	CustomFlags  []string  `json:"custom_flags,omitempty"`
	MessageID    string    `json:"message_id"`
	InReplyTo    string    `json:"in_reply_to,omitempty"`
	References   string    `json:"references,omitempty"`
	Recipients   []string  `json:"recipients,omitempty"`
	ContentHash  string    `json:"content_hash"`
	S3Domain     string    `json:"-"`
	AccountID    int64     `json:"-"` // owner of the row (the pending-upload key, with ContentHash)
	Uploaded     bool      `json:"-"` // body is in S3 under S3Domain/S3Localpart/ContentHash
	S3Localpart  string    `json:"-"`

	// HasAttachments mirrors the RFC 9979 §4 keywords: true for $hasattachment,
	// false for $hasnoattachment, nil (omitted) for mail stored before Sora set
	// them. RFC 9979 asks JMAP's hasAttachment to "reflect the same information
	// as this keyword"; this API follows the same rule.
	HasAttachments *bool `json:"has_attachments,omitempty"`
}

// setRecipients fills From, To, Cc and Bcc from recipients_json. It is stored as a
// list of helpers.Recipient ({type, email, name}; db/append.go), the list IMAP FETCH
// ENVELOPE reads too (db/fetch.go); list, search and get-by-ID all decode it here so
// their recipient fields cannot drift apart.
func (msg *DBMessage) setRecipients(recipientsJSON []byte) {
	if len(recipientsJSON) == 0 {
		return
	}
	var recipients []helpers.Recipient
	if err := json.Unmarshal(recipientsJSON, &recipients); err != nil {
		logger.Warn("Database: failed to decode recipients JSON", "message_id", msg.ID, "err", err)
		return
	}
	for _, r := range recipients {
		switch r.AddressType {
		case "from":
			if msg.From == "" {
				msg.From = r.EmailAddress
			}
		case "to":
			msg.To = append(msg.To, r.EmailAddress)
		case "cc":
			msg.Cc = append(msg.Cc, r.EmailAddress)
		case "bcc":
			msg.Bcc = append(msg.Bcc, r.EmailAddress)
		}
	}
}

// GetAccountIDByEmail retrieves account ID from email address
func (db *Database) GetAccountIDByEmail(ctx context.Context, email string) (int64, error) {
	return db.GetAccountIDByAddress(ctx, email)
}

// GetMailboxesForUser retrieves all mailboxes for an account
func (db *Database) GetMailboxesForUser(ctx context.Context, accountID int64, subscribed bool) ([]*DBMailbox, error) {
	return db.GetMailboxes(ctx, accountID, subscribed)
}

// canReadMailbox reports whether accountID may read the contents of mailbox.
// CheckMailboxPermission returns true for the owner, so personal mailboxes always
// pass; for a shared mailbox owned by another account it requires the 'r' (read)
// ACL right. This mirrors the IMAP SELECT gate (server/imap/select.go) so the User
// API cannot expose a mailbox's messages to a user who only holds 'l' (lookup).
func (db *Database) canReadMailbox(ctx context.Context, mailbox *DBMailbox, accountID int64) (bool, error) {
	if mailbox.AccountID == accountID {
		return true, nil
	}
	return db.CheckMailboxPermission(ctx, mailbox.ID, accountID, ACLRightRead)
}

// GetMessageCountForMailbox retrieves total message count
func (db *Database) GetMessageCountForMailbox(ctx context.Context, accountID int64, mailboxPath string) (int, error) {
	mailbox, err := db.GetMailboxByName(ctx, accountID, mailboxPath)
	if err != nil {
		return 0, err
	}
	// Hide counts for shared mailboxes the user can see ('l') but not read ('r').
	if ok, err := db.canReadMailbox(ctx, mailbox, accountID); err != nil {
		return 0, err
	} else if !ok {
		return 0, nil
	}

	var count int
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT COUNT(*)
		FROM messages 
		WHERE mailbox_id = $1 AND expunged_at IS NULL
	`, mailbox.ID).Scan(&count)

	if err != nil {
		return 0, fmt.Errorf("failed to get message count: %w", err)
	}

	return count, nil
}

// GetUnseenCountForMailbox retrieves unseen message count
func (db *Database) GetUnseenCountForMailbox(ctx context.Context, accountID int64, mailboxPath string) (int, error) {
	mailbox, err := db.GetMailboxByName(ctx, accountID, mailboxPath)
	if err != nil {
		return 0, err
	}
	// Hide counts for shared mailboxes the user can see ('l') but not read ('r').
	if ok, err := db.canReadMailbox(ctx, mailbox, accountID); err != nil {
		return 0, err
	} else if !ok {
		return 0, nil
	}

	var count int
	query := fmt.Sprintf(`
		SELECT COUNT(*) 
		FROM messages m
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.mailbox_id = $1 AND m.expunged_at IS NULL AND (ms.flags & %d) = 0
	`, FlagSeen)
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, query, mailbox.ID).Scan(&count)

	if err != nil {
		return 0, fmt.Errorf("failed to get unseen count: %w", err)
	}

	return count, nil
}

// GetMessagesForMailbox retrieves messages with pagination
func (db *Database) GetMessagesForMailbox(ctx context.Context, accountID int64, mailboxPath string, limit, offset int, unseenOnly bool) ([]*DBMessage, error) {
	mailbox, err := db.GetMailboxByName(ctx, accountID, mailboxPath)
	if err != nil {
		return nil, err
	}
	// Require the 'r' (read) right for shared mailboxes; 'l' (lookup) alone must not
	// expose message contents. Treat a denial as not-found to avoid leaking existence.
	if ok, err := db.canReadMailbox(ctx, mailbox, accountID); err != nil {
		return nil, err
	} else if !ok {
		return nil, consts.ErrMailboxNotFound
	}

	query := `
		SELECT
			m.id, m.uid, m.mailbox_id, COALESCE(m.subject, ''), m.sent_date, m.internal_date,
			m.size, COALESCE(ms.flags, 0), ms.custom_flags, m.message_id, COALESCE(m.in_reply_to, ''),
			m.recipients_json, m.content_hash, m.s3_domain, m.s3_localpart,
			mb.name as mailbox_path
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.mailbox_id = $1 AND m.expunged_at IS NULL
	`

	args := []any{mailbox.ID}
	argPos := 2

	if unseenOnly {
		query += fmt.Sprintf(" AND (ms.flags & %d) = 0", FlagSeen)
	}

	query += " ORDER BY m.internal_date DESC"

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argPos)
		args = append(args, limit)
		argPos++
	}

	if offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argPos)
		args = append(args, offset)
	}

	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %w", err)
	}
	defer rows.Close()

	var messages []*DBMessage
	for rows.Next() {
		msg := &DBMessage{}
		var customFlagsJSON []byte
		var recipientsJSON []byte
		var flagsBitmask int

		err := rows.Scan(
			&msg.ID, &msg.UID, &msg.MailboxID, &msg.Subject, &msg.Date,
			&msg.InternalDate, &msg.Size, &flagsBitmask, &customFlagsJSON,
			&msg.MessageID, &msg.InReplyTo, &recipientsJSON, &msg.ContentHash,
			&msg.S3Domain, &msg.S3Localpart, &msg.MailboxPath,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}

		// Parse custom flags
		if len(customFlagsJSON) > 0 {
			if err := json.Unmarshal(customFlagsJSON, &msg.CustomFlags); err != nil {
				log.Printf("Database: failed to unmarshal custom flags: %v", err)
				msg.CustomFlags = []string{}
			}
		}

		msg.setRecipients(recipientsJSON)

		// Convert bitwise flags to string array
		msg.Flags = bitwiseFlagsToStrings(flagsBitmask)
		msg.HasAttachments = hasAttachmentsFromKeywords(msg.CustomFlags)
		messages = append(messages, msg)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating messages: %w", err)
	}

	return messages, nil
}

// UserAPISearchLimit caps the messages a User API search returns. The query reads one
// row past it so the caller can tell a result clipped at the cap from a complete one.
const UserAPISearchLimit = 100

// SearchMessagesInMailbox performs full-text search. It returns at most
// UserAPISearchLimit messages, newest first, and whether more matches were left out.
func (db *Database) SearchMessagesInMailbox(ctx context.Context, accountID int64, mailboxPath string, query string) ([]*DBMessage, bool, error) {
	mailbox, err := db.GetMailboxByName(ctx, accountID, mailboxPath)
	if err != nil {
		return nil, false, err
	}
	// Require the 'r' (read) right for shared mailboxes; 'l' (lookup) alone must not
	// expose message contents. Treat a denial as not-found to avoid leaking existence.
	if ok, err := db.canReadMailbox(ctx, mailbox, accountID); err != nil {
		return nil, false, err
	} else if !ok {
		return nil, false, consts.ErrMailboxNotFound
	}

	searchQuery := `
		SELECT
			m.id, m.uid, m.mailbox_id, COALESCE(m.subject, ''), m.sent_date, m.internal_date,
			m.size, COALESCE(ms.flags, 0), ms.custom_flags, m.message_id, COALESCE(m.in_reply_to, ''),
			m.recipients_json, m.content_hash, m.s3_domain, m.s3_localpart,
			mb.name as mailbox_path
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		-- Account-scoped in the JOIN ON clause, never in WHERE: this is a LEFT JOIN whose
		-- FTS predicate sits inside an OR with header substring predicates, so a WHERE-side
		-- account qual would drop every message that has no FTS row (bodies over 64KB are
		-- never staged, empty bodies are skipped, retention prunes old rows) even when its
		-- subject or sender matched.
		LEFT JOIN messages_fts_v2 mf
		       ON mf.content_hash = m.content_hash AND mf.account_id = $4
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.mailbox_id = $1 AND m.expunged_at IS NULL
		-- Header matching is strpos(), never LIKE: see substringCond in search.go.
		AND (
			__HEADER_COND__
			-- 'simple' matches how the vector was built (db/fts.go). Without it this used
			-- default_text_search_config, so on a stemming configuration a search for
			-- "running" looked up the lexeme "run" and never matched.
			-- The IS NOT NULL is required for the PARTIAL composite GIN to be usable.
			OR (mf.text_body_tsv IS NOT NULL AND mf.text_body_tsv @@ plainto_tsquery('simple', $3))
		)
		ORDER BY m.internal_date DESC
		LIMIT $5
	`

	searchQuery = strings.Replace(searchQuery, "__HEADER_COND__", headerSubstringCond("m.", "$2"), 1)
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, searchQuery, mailbox.ID, strings.ToLower(query), query, mailbox.AccountID, UserAPISearchLimit+1)
	if err != nil {
		return nil, false, fmt.Errorf("failed to search messages: %w", err)
	}
	defer rows.Close()

	var messages []*DBMessage
	for rows.Next() {
		msg := &DBMessage{}
		var customFlagsJSON []byte
		var recipientsJSON []byte
		var flagsBitmask int

		err := rows.Scan(
			&msg.ID, &msg.UID, &msg.MailboxID, &msg.Subject, &msg.Date,
			&msg.InternalDate, &msg.Size, &flagsBitmask, &customFlagsJSON,
			&msg.MessageID, &msg.InReplyTo, &recipientsJSON, &msg.ContentHash,
			&msg.S3Domain, &msg.S3Localpart, &msg.MailboxPath,
		)
		if err != nil {
			return nil, false, fmt.Errorf("failed to scan message: %w", err)
		}

		// Parse custom flags
		if len(customFlagsJSON) > 0 {
			json.Unmarshal(customFlagsJSON, &msg.CustomFlags)
		}

		msg.setRecipients(recipientsJSON)

		msg.Flags = bitwiseFlagsToStrings(flagsBitmask)
		msg.HasAttachments = hasAttachmentsFromKeywords(msg.CustomFlags)
		messages = append(messages, msg)
	}

	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	// The extra row only says that the cap was hit; it is never returned.
	truncated := len(messages) > UserAPISearchLimit
	if truncated {
		messages = messages[:UserAPISearchLimit]
	}
	return messages, truncated, nil
}

// MessageS3Info represents minimal message info needed for S3 verification
type MessageS3Info struct {
	ID          int64
	ContentHash string
	S3Domain    string
	S3Localpart string
	S3Key       string
	Uploaded    bool // false while the body waits for the uploader: no object is expected yet
}

// MessageHashInfo represents message info for content hash verification
type MessageHashInfo struct {
	ID          int64
	UID         int64
	MailboxPath string
	Subject     string
	Uploaded    bool
	ContentHash string
	Expunged    bool // true if the message is soft-deleted (expunged_at IS NOT NULL), pending cleanup
}

// GetAllMessagesForUserVerification retrieves S3 info for all non-expunged messages for a user
func (db *Database) GetAllMessagesForUserVerification(ctx context.Context, accountID int64) ([]MessageS3Info, error) {
	query := `
		SELECT id, content_hash, s3_domain, s3_localpart, uploaded
		FROM messages
		WHERE account_id = $1 AND expunged_at IS NULL
		ORDER BY id
	`

	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages for verification: %w", err)
	}
	defer rows.Close()

	var messages []MessageS3Info
	for rows.Next() {
		var msg MessageS3Info
		err := rows.Scan(&msg.ID, &msg.ContentHash, &msg.S3Domain, &msg.S3Localpart, &msg.Uploaded)
		if err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}
		// Construct S3 key
		msg.S3Key = fmt.Sprintf("%s/%s/%s", msg.S3Domain, msg.S3Localpart, msg.ContentHash)
		messages = append(messages, msg)
	}

	return messages, rows.Err()
}

// GetMessagesByContentHash retrieves all messages with a specific content hash for an
// account, INCLUDING expunged (soft-deleted) messages. Each result carries an Expunged
// flag so callers (e.g. content-hash verification) can distinguish a live reference from
// one that is merely pending two-phase cleanup, rather than misreporting it as an orphan.
func (db *Database) GetMessagesByContentHash(ctx context.Context, accountID int64, contentHash string) ([]MessageHashInfo, error) {
	query := `
		SELECT m.id, m.uid, mb.name as mailbox_path, m.subject, m.uploaded, m.content_hash, (m.expunged_at IS NOT NULL) AS expunged
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE m.account_id = $1 AND m.content_hash = $2
		ORDER BY m.id
	`

	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, query, accountID, contentHash)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages by content hash: %w", err)
	}
	defer rows.Close()

	var messages []MessageHashInfo
	for rows.Next() {
		var msg MessageHashInfo
		err := rows.Scan(&msg.ID, &msg.UID, &msg.MailboxPath, &msg.Subject, &msg.Uploaded, &msg.ContentHash, &msg.Expunged)
		if err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}
		messages = append(messages, msg)
	}

	return messages, rows.Err()
}

// MarkMessagesAsNotUploaded marks messages as not uploaded by their S3 keys
func (db *Database) MarkMessagesAsNotUploaded(ctx context.Context, s3Keys []string) (int64, error) {
	if len(s3Keys) == 0 {
		return 0, nil
	}

	// Extract content hashes from S3 keys (format: domain/localpart/hash)
	// We'll match on content_hash, s3_domain, and s3_localpart
	query := `
		UPDATE messages
		SET uploaded = FALSE
		WHERE (s3_domain, s3_localpart, content_hash) IN (
			SELECT
				split_part(unnest($1::text[]), '/', 1),
				split_part(unnest($1::text[]), '/', 2),
				split_part(unnest($1::text[]), '/', 3)
		)
		AND expunged_at IS NULL
	`

	result, err := db.GetWritePool().Exec(ctx, query, s3Keys)
	if err != nil {
		return 0, fmt.Errorf("failed to mark messages as not uploaded: %w", err)
	}

	return result.RowsAffected(), nil
}

// GetMessageByID retrieves a single message
func (db *Database) GetMessageByID(ctx context.Context, accountID int64, messageID int64) (*DBMessage, error) {
	query := `
		SELECT 
			m.id, m.uid, m.mailbox_id, COALESCE(m.subject, ''), m.sent_date, m.internal_date,
			m.size, COALESCE(ms.flags, 0), ms.custom_flags, m.message_id, COALESCE(m.in_reply_to, ''), COALESCE(m."references", ''),
			m.recipients_json, m.content_hash, ms.flags_changed_at, m.s3_domain, m.s3_localpart,
			mb.name as mailbox_path, m.account_id, m.uploaded
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.id = $1 AND m.expunged_at IS NULL AND mb.deleted_at IS NULL
		-- A shared mailbox's messages belong to its owner. Anyone else reads them with the
		-- "r" right on the mailbox, as SELECT requires (RFC 4314 section 4), the same gate
		-- as the message list; without it the message is not found.
		AND (m.account_id = $2 OR has_mailbox_right(m.mailbox_id, $2, 'r'))
	`

	msg := &DBMessage{}
	var customFlagsJSON []byte
	var recipientsJSON []byte
	var flagsChangedAt any
	var flagsBitmask int

	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, query, messageID, accountID).Scan(
		&msg.ID, &msg.UID, &msg.MailboxID, &msg.Subject, &msg.Date,
		&msg.InternalDate, &msg.Size, &flagsBitmask, &customFlagsJSON,
		&msg.MessageID, &msg.InReplyTo, &msg.References, &recipientsJSON, &msg.ContentHash,
		&flagsChangedAt, &msg.S3Domain, &msg.S3Localpart, &msg.MailboxPath,
		&msg.AccountID, &msg.Uploaded,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, consts.ErrDBNotFound
		}
		return nil, fmt.Errorf("failed to get message: %w", err)
	}

	// Parse custom flags
	if len(customFlagsJSON) > 0 {
		json.Unmarshal(customFlagsJSON, &msg.CustomFlags)
	}

	msg.setRecipients(recipientsJSON)

	msg.Flags = bitwiseFlagsToStrings(flagsBitmask)
	msg.HasAttachments = hasAttachmentsFromKeywords(msg.CustomFlags)
	return msg, nil
}

// UpdateMessageFlags updates message flags
func (db *Database) UpdateMessageFlags(ctx context.Context, accountID int64, messageID int64, addFlags, removeFlags []string) error {
	tx, err := db.GetWritePool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(context.Background())

	// Resolve the mailbox before locking it. Read flags only after that lock,
	// so a concurrent STORE cannot make this update overwrite a stale snapshot.
	//
	// The message's account is its mailbox's owner, for a shared mailbox not the
	// caller. Anyone else reaches it only with the "r" right, as SELECT requires, and
	// changes a flag only with its right (RFC 4314 section 4): "s" for \Seen, "t" for
	// \Deleted, "w" for every other flag and keyword. The owner holds them all.
	var mailboxID, ownerID int64
	var maySeen, mayDelete, mayWrite bool
	err = tx.QueryRow(ctx, `
		SELECT m.mailbox_id, m.account_id,
		       m.account_id = $2 OR has_mailbox_right(m.mailbox_id, $2, 's'),
		       m.account_id = $2 OR has_mailbox_right(m.mailbox_id, $2, 't'),
		       m.account_id = $2 OR has_mailbox_right(m.mailbox_id, $2, 'w')
		FROM messages m
		WHERE m.id = $1 AND m.expunged_at IS NULL
		  AND (m.account_id = $2 OR has_mailbox_right(m.mailbox_id, $2, 'r'))
	`, messageID, accountID).Scan(&mailboxID, &ownerID, &maySeen, &mayDelete, &mayWrite)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return consts.ErrDBNotFound
		}
		return fmt.Errorf("failed to get current flags: %w", err)
	}

	// Like STORE, apply the flags the caller may change and leave the others alone;
	// refuse only when that is none of them.
	mayChange := func(flag string) bool {
		switch {
		case strings.EqualFold(flag, `\Seen`):
			return maySeen
		case strings.EqualFold(flag, `\Deleted`):
			return mayDelete
		}
		return mayWrite
	}
	requested := len(addFlags) + len(removeFlags)
	addFlags = slices.DeleteFunc(slices.Clone(addFlags), func(f string) bool { return !mayChange(f) })
	removeFlags = slices.DeleteFunc(slices.Clone(removeFlags), func(f string) bool { return !mayChange(f) })
	if requested > 0 && len(addFlags)+len(removeFlags) == 0 {
		return consts.ErrNotPermitted
	}

	// Serialize unseen_count maintenance for this mailbox (see lockMailboxStats)
	// before mutating flags. Without this, a User API flag change racing an IMAP/POP3
	// EXPUNGE on the same message double-counts the "no longer unseen" event and
	// drifts unseen_count negative — the same bug the IMAP paths already guard against.
	if err = lockMailboxStats(ctx, tx, mailboxID); err != nil {
		return err
	}

	var currentFlags int
	var currentCustomFlags []byte
	err = tx.QueryRow(ctx, `
		SELECT ms.flags, ms.custom_flags
		FROM messages m
		JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.id = $1 AND m.account_id = $2 AND m.expunged_at IS NULL
	`, messageID, ownerID).Scan(&currentFlags, &currentCustomFlags)
	if errors.Is(err, pgx.ErrNoRows) {
		return consts.ErrDBNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to get current flags: %w", err)
	}

	var customFlags []string
	if len(currentCustomFlags) > 0 {
		json.Unmarshal(currentCustomFlags, &customFlags)
	}
	storedCustomFlags := slices.Clone(customFlags)

	// Keyword identity is case-insensitive (RFC 9051 §2.3.2): fold incoming
	// keywords onto the case already established for this mailbox so adds/removes
	// match existing keywords regardless of case and never create a second variant.
	canonical, err := db.mailboxKeywordCanonicalMap(ctx, tx, mailboxID)
	if err != nil {
		return err
	}

	// Apply flag changes
	newFlags := currentFlags
	for _, flag := range addFlags {
		if strings.HasPrefix(flag, "\\") {
			newFlags |= stringFlagToBitwise(flag)
			continue
		}
		// This path builds custom_flags directly instead of going through
		// SplitFlags, so it needs its own guard: a keyword that is not an IMAP
		// atom cannot be encoded in a FLAGS response and would wedge SELECT of
		// this mailbox for every IMAP client (see helpers.IsValidFlagName). The
		// User API rejects these at the HTTP layer with 400; refuse them here
		// too rather than relying on the caller having checked.
		if !helpers.IsValidFlagName(imap.Flag(flag)) {
			return consts.ErrInvalidFlag
		}
		canon, ok := canonical[foldKeyword(flag)]
		if !ok {
			// First case seen for this keyword in the mailbox becomes canonical.
			canon = flag
			canonical[foldKeyword(flag)] = flag
		}
		// Compare against the message's own keywords case-insensitively: the
		// mailbox registry (custom_flags_cache) may not list them.
		if !slices.ContainsFunc(customFlags, func(cf string) bool { return foldKeyword(cf) == foldKeyword(canon) }) {
			customFlags = append(customFlags, canon)
		}
	}

	for _, flag := range removeFlags {
		if strings.HasPrefix(flag, "\\") {
			newFlags &^= stringFlagToBitwise(flag)
			continue
		}
		customFlags = slices.DeleteFunc(customFlags, func(cf string) bool { return foldKeyword(cf) == foldKeyword(flag) })
	}

	// RFC 9979 §4: one explicitly added attachment keyword replaces its
	// opposite; an explicitly conflicting pair clears both. Apply this before
	// the cap check so replacing a keyword does not consume another slot.
	// Removals run after additions, so cancelled additions must not replace a
	// surviving opposite keyword. Keep validating the original addFlags above.
	removed := make(map[string]struct{}, len(removeFlags))
	for _, flag := range removeFlags {
		removed[foldKeyword(flag)] = struct{}{}
	}
	effectiveAdded := make([]imap.Flag, 0, len(addFlags))
	for _, flag := range addFlags {
		if _, cancelled := removed[foldKeyword(flag)]; !cancelled {
			effectiveAdded = append(effectiveAdded, imap.Flag(flag))
		}
	}
	normalizedCustom := NormalizeAttachmentKeywordUpdate(helpers.StringsToFlags(customFlags), effectiveAdded)
	// Apply the User API's color policy to the final state, after additions and
	// removals: color keywords are meaningful only with \Flagged (RFC 9979
	// §§3.1–3.2). This also handles adding a color while removing \Flagged.
	if newFlags&FlagFlagged == 0 {
		normalizedCustom = slices.DeleteFunc(normalizedCustom, helpers.IsFlagColorKeyword)
	}
	customFlags = make([]string, len(normalizedCustom))
	for i, flag := range normalizedCustom {
		customFlags[i] = string(flag)
	}
	if !mayWrite {
		// No keyword changes without "w", not even the ones the attachment and
		// color rules above derive from \Seen or \Deleted changes.
		customFlags = storedCustomFlags
	}

	// Reject rather than silently drop if the result would exceed what a single
	// message may hold (see MaxCustomKeywordsPerMessage). customFlags is already
	// case-folded and deduplicated by the add loop above, so its length is the
	// distinct keyword count. The API surfaces this as HTTP 422.
	if len(customFlags) > MaxCustomKeywordsPerMessage {
		return consts.ErrTooManyKeywords
	}

	customFlagsJSON, _ := json.Marshal(customFlags)

	// Update flags
	_, err = tx.Exec(ctx, `
		UPDATE message_state ms
		SET flags = $1, custom_flags = $2, flags_changed_at = now(), updated_modseq = nextval('messages_modseq')
		FROM messages m
		WHERE ms.message_id = m.id AND m.id = $3 AND m.account_id = $4
	`, newFlags, customFlagsJSON, messageID, ownerID)

	if err != nil {
		return fmt.Errorf("failed to update flags: %w", err)
	}

	return tx.Commit(ctx)
}

// CreateMailboxForUser creates a new mailbox
func (db *Database) CreateMailboxForUser(ctx context.Context, accountID int64, mailboxPath string) error {
	tx, err := db.GetWritePool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(context.Background())

	// RFC 3501 §6.3.3: trim trailing hierarchy delimiters so "Folder/Sub/" creates
	// "Folder/Sub" rather than storing a trailing separator.
	delim := string(consts.MailboxDelimiter)
	mailboxPath = strings.TrimRight(mailboxPath, delim)
	if mailboxPath == "" {
		return consts.ErrMailboxInvalidName
	}

	// Link the mailbox under its parent, creating any missing ancestor first, as IMAP
	// CREATE and GetOrCreateMailboxByName do. Creating it with no parent (as this did)
	// put "Parent/Child" at the root: the parent never reported \HasChildren, the child
	// did not follow the parent's RENAME, and the delete gate could not see it.
	parts := strings.Split(mailboxPath, delim)
	var parentID *int64
	for i := 1; i < len(parts); i++ {
		ancestor := strings.Join(parts[:i], delim)
		var id int64
		err := tx.QueryRow(ctx, `
			SELECT id FROM mailboxes WHERE account_id = $1 AND LOWER(name) = LOWER($2) AND deleted_at IS NULL
		`, accountID, ancestor).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			if err := db.CreateMailbox(ctx, tx, accountID, ancestor, parentID); err != nil &&
				!errors.Is(err, consts.ErrDBUniqueViolation) && !errors.Is(err, consts.ErrMailboxAlreadyExists) {
				return fmt.Errorf("failed to create parent mailbox '%s': %w", ancestor, err)
			}
			err = tx.QueryRow(ctx, `
				SELECT id FROM mailboxes WHERE account_id = $1 AND LOWER(name) = LOWER($2) AND deleted_at IS NULL
			`, accountID, ancestor).Scan(&id)
		}
		if err != nil {
			return fmt.Errorf("failed to resolve parent mailbox '%s': %w", ancestor, err)
		}
		parentID = &id
	}

	err = db.CreateMailbox(ctx, tx, accountID, mailboxPath, parentID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// DeleteMailboxForUser deletes a mailbox
func (db *Database) DeleteMailboxForUser(ctx context.Context, accountID int64, mailboxPath string) error {
	// Prevent deletion of INBOX
	if strings.EqualFold(mailboxPath, "INBOX") {
		return errors.New("cannot delete INBOX")
	}

	mailbox, err := db.GetMailboxByName(ctx, accountID, mailboxPath)
	if err != nil {
		return err
	}

	tx, err := db.GetWritePool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(context.Background())

	// Two-phase deletion, as the IMAP DELETE path does: stamp deleted_at (one row) and
	// leave the per-message expunge to the cleaner. Hard-deleting inline made this request
	// proportional to the mailbox's size — 16s for 100k messages, 32s for 200k, measured —
	// while holding the mailbox row lock every delivery into it needs.
	err = db.SoftDeleteMailbox(ctx, tx, mailbox.ID, accountID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// SubscribeToMailbox marks mailbox as subscribed
func (db *Database) SubscribeToMailbox(ctx context.Context, accountID int64, mailboxPath string) error {
	mailbox, err := db.GetMailboxByName(ctx, accountID, mailboxPath)
	if err != nil {
		return err
	}

	tx, err := db.GetWritePool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(context.Background())

	err = db.SetMailboxSubscribed(ctx, tx, mailbox.ID, accountID, true)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// UnsubscribeFromMailbox marks mailbox as unsubscribed
func (db *Database) UnsubscribeFromMailbox(ctx context.Context, accountID int64, mailboxPath string) error {
	mailbox, err := db.GetMailboxByName(ctx, accountID, mailboxPath)
	if err != nil {
		return err
	}

	tx, err := db.GetWritePool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(context.Background())

	err = db.SetMailboxSubscribed(ctx, tx, mailbox.ID, accountID, false)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// Helper functions

func bitwiseFlagsToStrings(flags any) []string {
	var bitwiseFlags int

	switch v := flags.(type) {
	case int:
		bitwiseFlags = v
	case int64:
		bitwiseFlags = int(v)
	default:
		return []string{}
	}

	var result []string
	if bitwiseFlags&FlagSeen != 0 {
		result = append(result, "\\Seen")
	}
	if bitwiseFlags&FlagAnswered != 0 {
		result = append(result, "\\Answered")
	}
	if bitwiseFlags&FlagFlagged != 0 {
		result = append(result, "\\Flagged")
	}
	if bitwiseFlags&FlagDeleted != 0 {
		result = append(result, "\\Deleted")
	}
	if bitwiseFlags&FlagDraft != 0 {
		result = append(result, "\\Draft")
	}
	// The FlagRecent bit is skipped for the reason BitwiseToFlags gives: \Recent
	// is a session flag, and a set bit is stale data from before IMAP stopped
	// writing it.
	return result
}

// stringFlagToBitwise maps a system flag the User API may set or clear to its
// bit. \Recent maps to nothing, so this path can never write the FlagRecent bit
// (RFC 3501 §2.3.2: no client can change \Recent).
func stringFlagToBitwise(flag string) int {
	switch strings.ToLower(flag) {
	case "\\seen":
		return FlagSeen
	case "\\answered":
		return FlagAnswered
	case "\\flagged":
		return FlagFlagged
	case "\\deleted":
		return FlagDeleted
	case "\\draft":
		return FlagDraft
	default:
		return 0
	}
}
