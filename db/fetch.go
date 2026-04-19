package db

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
)

// BuildEnvelope efficiently constructs an IMAP envelope natively from a pre-fetched Message.
func BuildEnvelope(msg *Message) (*imap.Envelope, error) {
	var envelope imap.Envelope
	envelope.Date = msg.InternalDate
	envelope.Subject = msg.Subject
	envelope.MessageID = msg.MessageID

	// Split the In-Reply-To header into individual message IDs
	if msg.InReplyTo != "" {
		envelope.InReplyTo = strings.Split(msg.InReplyTo, " ")
	} else {
		envelope.InReplyTo = nil
	}

	var recipients []helpers.Recipient
	if err := json.Unmarshal(msg.RecipientsJSON, &recipients); err != nil {
		logger.Error("Database: failed to decode recipients JSON", "err", err)
		return nil, err
	}

	for _, recipient := range recipients {
		var addressType, name, emailAddress string
		addressType = recipient.AddressType
		name = recipient.Name
		emailAddress = recipient.EmailAddress

		parts := strings.Split(emailAddress, "@")
		if len(parts) != 2 {
			logger.Warn("Database: malformed email address for recipient", "email", emailAddress, "type", addressType, "uid", msg.UID, "mailbox_id", msg.MailboxID)
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
		case "sender":
			envelope.Sender = append(envelope.Sender, address)
		default:
			logger.Warn("Database: unhandled address type", "type", addressType, "uid", msg.UID, "mailbox_id", msg.MailboxID)
		}
	}

	// RFC 3501: If Sender is not present in the message, it defaults to From
	if len(envelope.Sender) == 0 && len(envelope.From) > 0 {
		envelope.Sender = envelope.From
	}

	return &envelope, nil
}

func (db *Database) GetMessageEnvelope(ctx context.Context, UID imap.UID, mailboxID int64) (*imap.Envelope, error) {
	var msg Message
	msg.UID = UID
	msg.MailboxID = mailboxID

	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
        SELECT 
            internal_date, subject, in_reply_to, message_id, recipients_json 
        FROM messages 
        WHERE uid = $1 AND mailbox_id = $2 AND expunged_at IS NULL
    `, int64(UID), mailboxID).Scan(
		&msg.InternalDate,
		&msg.Subject,
		&msg.InReplyTo,
		&msg.MessageID,
		&msg.RecipientsJSON,
	)
	if err != nil {
		logger.Error("Database: failed to fetch envelope fields", "uid", UID, "mailbox_id", mailboxID, "err", err)
		return nil, err
	}

	return BuildEnvelope(&msg)
}
