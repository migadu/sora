package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
)

// DBMessage represents a simplified message structure for API responses
type DBMessage struct {
	ID           int64    `json:"id"`
	UID          int64    `json:"uid"`
	MailboxID    int64    `json:"mailbox_id"`
	MailboxPath  string   `json:"mailbox_path"`
	Subject      string   `json:"subject"`
	From         string   `json:"from"`
	To           []string `json:"to"`
	Cc           []string `json:"cc,omitempty"`
	Bcc          []string `json:"bcc,omitempty"`
	Date         string   `json:"date"`
	InternalDate string   `json:"internal_date"`
	Size         int      `json:"size"`
	Flags        []string `json:"flags"`
	CustomFlags  []string `json:"custom_flags,omitempty"`
	MessageID    string   `json:"message_id"`
	InReplyTo    string   `json:"in_reply_to,omitempty"`
	ContentHash  string   `json:"content_hash"`
	S3Domain     string   `json:"-"`
	S3Localpart  string   `json:"-"`
}

// RecipientInfo represents email recipient information
type RecipientInfo struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address"`
}

// GetAccountIDByEmail retrieves account ID from email address
func (db *Database) GetAccountIDByEmail(ctx context.Context, email string) (int64, error) {
	return db.GetAccountIDByAddress(ctx, email)
}

// GetMailboxesForUser retrieves all mailboxes for an account
func (db *Database) GetMailboxesForUser(ctx context.Context, accountID int64, subscribed bool) ([]*DBMailbox, error) {
	return db.GetMailboxes(ctx, accountID, subscribed)
}

// GetMessageCountForMailbox retrieves total message count
func (db *Database) GetMessageCountForMailbox(ctx context.Context, accountID int64, mailboxPath string) (int, error) {
	mailbox, err := db.GetMailboxByName(ctx, accountID, mailboxPath)
	if err != nil {
		return 0, err
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

	var count int
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT COUNT(*) 
		FROM messages 
		WHERE mailbox_id = $1 AND expunged_at IS NULL AND (flags & $2) = 0
	`, mailbox.ID, FlagSeen).Scan(&count)

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

	query := `
		SELECT 
			m.id, m.uid, m.mailbox_id, m.subject, m.sent_date, m.internal_date,
			m.size, m.flags, m.custom_flags, m.message_id, m.in_reply_to,
			m.recipients_json, m.content_hash, m.s3_domain, m.s3_localpart,
			mb.name as mailbox_path
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE m.mailbox_id = $1 AND m.expunged_at IS NULL
	`

	args := []any{mailbox.ID}
	argPos := 2

	if unseenOnly {
		query += fmt.Sprintf(" AND (m.flags & $%d) = 0", argPos)
		args = append(args, FlagSeen)
		argPos++
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

		err := rows.Scan(
			&msg.ID, &msg.UID, &msg.MailboxID, &msg.Subject, &msg.Date,
			&msg.InternalDate, &msg.Size, &msg.Flags, &customFlagsJSON,
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

		// Parse recipients
		if len(recipientsJSON) > 0 {
			var recipients map[string][]RecipientInfo
			if err := json.Unmarshal(recipientsJSON, &recipients); err != nil {
				log.Printf("Database: failed to unmarshal recipients: %v", err)
			} else {
				if from, ok := recipients["from"]; ok && len(from) > 0 {
					msg.From = from[0].Address
				}
				if to, ok := recipients["to"]; ok {
					for _, r := range to {
						msg.To = append(msg.To, r.Address)
					}
				}
				if cc, ok := recipients["cc"]; ok {
					for _, r := range cc {
						msg.Cc = append(msg.Cc, r.Address)
					}
				}
				if bcc, ok := recipients["bcc"]; ok {
					for _, r := range bcc {
						msg.Bcc = append(msg.Bcc, r.Address)
					}
				}
			}
		}

		// Convert bitwise flags to string array
		msg.Flags = bitwiseFlagsToStrings(msg.Flags)
		messages = append(messages, msg)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating messages: %w", err)
	}

	return messages, nil
}

// SearchMessagesInMailbox performs full-text search
func (db *Database) SearchMessagesInMailbox(ctx context.Context, accountID int64, mailboxPath string, query string) ([]*DBMessage, error) {
	mailbox, err := db.GetMailboxByName(ctx, accountID, mailboxPath)
	if err != nil {
		return nil, err
	}

	searchQuery := `
		SELECT 
			m.id, m.uid, m.mailbox_id, m.subject, m.sent_date, m.internal_date,
			m.size, m.flags, m.custom_flags, m.message_id, m.in_reply_to,
			m.recipients_json, m.content_hash, m.s3_domain, m.s3_localpart,
			mb.name as mailbox_path
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		LEFT JOIN message_contents mc ON m.content_hash = mc.content_hash
		WHERE m.mailbox_id = $1 AND m.expunged_at IS NULL
		AND (
			LOWER(m.subject) LIKE LOWER($2)
			OR mc.text_body_tsv @@ plainto_tsquery($3)
			OR mc.headers_tsv @@ plainto_tsquery($3)
		)
		ORDER BY m.internal_date DESC
		LIMIT 100
	`

	searchPattern := "%" + query + "%"
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, searchQuery, mailbox.ID, searchPattern, query)
	if err != nil {
		return nil, fmt.Errorf("failed to search messages: %w", err)
	}
	defer rows.Close()

	var messages []*DBMessage
	for rows.Next() {
		msg := &DBMessage{}
		var customFlagsJSON []byte
		var recipientsJSON []byte

		err := rows.Scan(
			&msg.ID, &msg.UID, &msg.MailboxID, &msg.Subject, &msg.Date,
			&msg.InternalDate, &msg.Size, &msg.Flags, &customFlagsJSON,
			&msg.MessageID, &msg.InReplyTo, &recipientsJSON, &msg.ContentHash,
			&msg.S3Domain, &msg.S3Localpart, &msg.MailboxPath,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}

		// Parse custom flags
		if len(customFlagsJSON) > 0 {
			json.Unmarshal(customFlagsJSON, &msg.CustomFlags)
		}

		// Parse recipients
		if len(recipientsJSON) > 0 {
			var recipients map[string][]RecipientInfo
			if err := json.Unmarshal(recipientsJSON, &recipients); err == nil {
				if from, ok := recipients["from"]; ok && len(from) > 0 {
					msg.From = from[0].Address
				}
				if to, ok := recipients["to"]; ok {
					for _, r := range to {
						msg.To = append(msg.To, r.Address)
					}
				}
			}
		}

		msg.Flags = bitwiseFlagsToStrings(msg.Flags)
		messages = append(messages, msg)
	}

	return messages, rows.Err()
}

// MessageS3Info represents minimal message info needed for S3 verification
type MessageS3Info struct {
	ID          int64
	ContentHash string
	S3Domain    string
	S3Localpart string
	S3Key       string
}

// MessageHashInfo represents message info for content hash verification
type MessageHashInfo struct {
	ID          int64
	UID         int64
	MailboxPath string
	Subject     string
	Uploaded    bool
	ContentHash string
}

// GetAllMessagesForUserVerification retrieves S3 info for all non-expunged messages for a user
func (db *Database) GetAllMessagesForUserVerification(ctx context.Context, accountID int64) ([]MessageS3Info, error) {
	query := `
		SELECT id, content_hash, s3_domain, s3_localpart
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
		err := rows.Scan(&msg.ID, &msg.ContentHash, &msg.S3Domain, &msg.S3Localpart)
		if err != nil {
			return nil, fmt.Errorf("failed to scan message: %w", err)
		}
		// Construct S3 key
		msg.S3Key = fmt.Sprintf("%s/%s/%s", msg.S3Domain, msg.S3Localpart, msg.ContentHash)
		messages = append(messages, msg)
	}

	return messages, rows.Err()
}

// GetMessagesByContentHash retrieves all messages with a specific content hash for an account
func (db *Database) GetMessagesByContentHash(ctx context.Context, accountID int64, contentHash string) ([]MessageHashInfo, error) {
	query := `
		SELECT m.id, m.uid, mb.name as mailbox_path, m.subject, m.uploaded, m.content_hash
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE m.account_id = $1 AND m.content_hash = $2 AND m.expunged_at IS NULL
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
		err := rows.Scan(&msg.ID, &msg.UID, &msg.MailboxPath, &msg.Subject, &msg.Uploaded, &msg.ContentHash)
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
			m.id, m.uid, m.mailbox_id, m.subject, m.sent_date, m.internal_date,
			m.size, m.flags, m.custom_flags, m.message_id, m.in_reply_to,
			m.recipients_json, m.content_hash, m.s3_domain, m.s3_localpart,
			mb.name as mailbox_path
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE m.id = $1 AND m.account_id = $2 AND m.expunged_at IS NULL
	`

	msg := &DBMessage{}
	var customFlagsJSON []byte
	var recipientsJSON []byte

	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, query, messageID, accountID).Scan(
		&msg.ID, &msg.UID, &msg.MailboxID, &msg.Subject, &msg.Date,
		&msg.InternalDate, &msg.Size, &msg.Flags, &customFlagsJSON,
		&msg.MessageID, &msg.InReplyTo, &recipientsJSON, &msg.ContentHash,
		&msg.S3Domain, &msg.S3Localpart, &msg.MailboxPath,
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

	// Parse recipients
	if len(recipientsJSON) > 0 {
		var recipients map[string][]RecipientInfo
		if err := json.Unmarshal(recipientsJSON, &recipients); err == nil {
			if from, ok := recipients["from"]; ok && len(from) > 0 {
				msg.From = from[0].Address
			}
			if to, ok := recipients["to"]; ok {
				for _, r := range to {
					msg.To = append(msg.To, r.Address)
				}
			}
			if cc, ok := recipients["cc"]; ok {
				for _, r := range cc {
					msg.Cc = append(msg.Cc, r.Address)
				}
			}
		}
	}

	msg.Flags = bitwiseFlagsToStrings(msg.Flags)
	return msg, nil
}

// UpdateMessageFlags updates message flags
func (db *Database) UpdateMessageFlags(ctx context.Context, accountID int64, messageID int64, addFlags, removeFlags []string) error {
	tx, err := db.GetWritePool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Get current flags
	var currentFlags int
	var currentCustomFlags []byte
	err = tx.QueryRow(ctx, `
		SELECT flags, custom_flags 
		FROM messages 
		WHERE id = $1 AND account_id = $2 AND expunged_at IS NULL
	`, messageID, accountID).Scan(&currentFlags, &currentCustomFlags)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return consts.ErrDBNotFound
		}
		return fmt.Errorf("failed to get current flags: %w", err)
	}

	var customFlags []string
	if len(currentCustomFlags) > 0 {
		json.Unmarshal(currentCustomFlags, &customFlags)
	}

	// Apply flag changes
	newFlags := currentFlags
	for _, flag := range addFlags {
		if strings.HasPrefix(flag, "\\") {
			newFlags |= stringFlagToBitwise(flag)
		} else {
			if !contains(customFlags, flag) {
				customFlags = append(customFlags, flag)
			}
		}
	}

	for _, flag := range removeFlags {
		if strings.HasPrefix(flag, "\\") {
			newFlags &^= stringFlagToBitwise(flag)
		} else {
			customFlags = removeString(customFlags, flag)
		}
	}

	customFlagsJSON, _ := json.Marshal(customFlags)

	// Update flags
	_, err = tx.Exec(ctx, `
		UPDATE messages 
		SET flags = $1, custom_flags = $2, updated_at = now()
		WHERE id = $3 AND account_id = $4
	`, newFlags, customFlagsJSON, messageID, accountID)

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
	defer tx.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx, accountID, mailboxPath, nil)
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
	defer tx.Rollback(ctx)

	err = db.DeleteMailbox(ctx, tx, mailbox.ID, accountID)
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
	defer tx.Rollback(ctx)

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
	defer tx.Rollback(ctx)

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
	if bitwiseFlags&FlagRecent != 0 {
		result = append(result, "\\Recent")
	}
	return result
}

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
	case "\\recent":
		return FlagRecent
	default:
		return 0
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func removeString(slice []string, item string) []string {
	var result []string
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}
