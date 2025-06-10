package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/helpers"
	"github.com/yugabyte/pgx/v5"
)

// GetMessageTextBody fetches the plain text body of a message from the message_contents table.
// This text_body is the canonical textual representation used for indexing and
// can be used for IMAP BODY[TEXT] requests.
func (db *Database) GetMessageTextBody(ctx context.Context, uid imap.UID, mailboxID int64) (string, error) {
	var textBody sql.NullString // Use sql.NullString to handle case where LEFT JOIN finds no match
	err := db.Pool.QueryRow(ctx, `
		SELECT mc.text_body 
		FROM messages m
		LEFT JOIN message_contents mc ON m.content_hash = mc.content_hash
		WHERE m.uid = $1 AND m.mailbox_id = $2 AND m.expunged_at IS NULL
	`, uid, mailboxID).Scan(&textBody)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// This means the message itself was not found in the 'messages' table.
			return "", fmt.Errorf("message with UID %d in mailbox %d not found: %w", uid, mailboxID, err)
		}
		// Other database error during query execution.
		log.Printf("[DB] database error fetching text_body for UID %d, MailboxID %d: %v", uid, mailboxID, err)
		return "", fmt.Errorf("database error fetching text_body: %w", err)
	}

	if !textBody.Valid {
		// Message was found in 'messages', but the LEFT JOIN didn't find a corresponding
		// row in 'message_contents'. Since message_contents.text_body is NOT NULL,
		// textBody.Valid being false implies no matching row in message_contents.
		// This indicates a data integrity issue, as a message's content_hash (which is NOT NULL)
		// should always exist in message_contents.
		log.Printf("[DB] data integrity issue: Message found (UID %d, Mailbox %d) but no corresponding entry in message_contents.", uid, mailboxID)
		return "", fmt.Errorf("message text content missing for UID %d, Mailbox %d (data integrity)", uid, mailboxID)
	}

	return textBody.String, nil
}

func (db *Database) GetMessageEnvelope(ctx context.Context, UID imap.UID, mailboxID int64) (*imap.Envelope, error) {
	var envelope imap.Envelope

	var inReplyTo string
	var recipientsJSON []byte
	var internalMessageDBId int64

	err := db.Pool.QueryRow(ctx, `
        SELECT 
            id, internal_date, subject, in_reply_to, message_id, recipients_json 
        FROM 
            messages
        WHERE 
            uid = $1 AND
						mailbox_id = $2 AND
						expunged_at IS NULL
    `, UID, mailboxID).Scan(
		&internalMessageDBId,
		&envelope.Date,
		&envelope.Subject,
		&inReplyTo,
		&envelope.MessageID,
		&recipientsJSON,
	)
	if err != nil {
		log.Printf("[DB] failed to fetch envelope fields for UID %d, MailboxID %d: %v", UID, mailboxID, err)
		return nil, err
	}

	// Split the In-Reply-To header into individual message IDs
	if inReplyTo != "" {
		envelope.InReplyTo = strings.Split(inReplyTo, " ")
	} else {
		envelope.InReplyTo = nil
	}

	var recipients []helpers.Recipient
	if err := json.Unmarshal(recipientsJSON, &recipients); err != nil {
		log.Printf("[DB] failed to decode recipients JSON: %v", err)
		return nil, err
	}

	for _, recipient := range recipients {
		var addressType, name, emailAddress string
		addressType = recipient.AddressType
		name = recipient.Name
		emailAddress = recipient.EmailAddress

		parts := strings.Split(emailAddress, "@")
		if len(parts) != 2 {
			log.Printf("[DB] WARNING: malformed email address '%s' for recipient type '%s' (UID %d, MailboxID %d)", emailAddress, addressType, UID, mailboxID)
			continue
		}
		mailboxPart, hostNamePart := parts[0], parts[1]

		address := imap.Address{
			Name:    name,
			Mailbox: mailboxPart,
			Host:    hostNamePart,
		}

		switch addressType {
		case "to":
			envelope.To = append(envelope.To, address)
		case "cc":
			envelope.Cc = append(envelope.Cc, address)
		case "bcc":
			envelope.Bcc = append(envelope.Bcc, address)
		case "reply-to":
			envelope.ReplyTo = append(envelope.ReplyTo, address)
		case "from":
			envelope.From = append(envelope.From, address)
		default:
			log.Printf("[DB] WARNING: unhandled address type: %s (UID %d, MailboxID %d)", addressType, UID, mailboxID)
		}
	}

	return &envelope, nil
}
