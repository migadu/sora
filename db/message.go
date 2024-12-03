package db

import (
	"net/mail"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-message"
)

// Message struct to represent an email message
type Message struct {
	ID             int       // Unique ID of the message
	S3UUID         string    // UUID of the message in S3
	MailboxID      int       // ID of the mailbox the message belongs to
	Seq            int       // Sequence number of the message in the mailbox
	BitwiseFlags   int       // Bitwise flags for the message (e.g., \Seen, \Flagged)
	FlagsChangedAt time.Time // Time when the flags were last changed
	Subject        string    // Subject of the message
	InternalDate   time.Time // The internal date the message was received
	SentDate       time.Time // The date the message was sent
	Size           int       // Size of the message in bytes
	MessageID      string    // Unique Message-ID from the message headers
	TextBody       string    // Text body of the message
	BodyStructure  imap.BodyStructure
}

// MessagePart represents a part of an email message (e.g., body, attachments)
type MessagePart struct {
	MessageID  int    // Reference to the message ID
	PartNumber int    // Part number (e.g., 1 for body, 2 for attachments)
	Size       int    // Size of the part in bytes
	S3Key      string // S3 key to reference the part's storage location
	Type       string // MIME type of the part (e.g., "text/plain", "text/html", "application/pdf")
}

type Recipient struct {
	MessageID    int
	EmailAddress string
	AddressType  string
	Name         string
}

// IMAP message flags as bitwise constants
const (
	FlagSeen     = 1 << iota // 1: 000001
	FlagAnswered             // 2: 000010
	FlagFlagged              // 4: 000100
	FlagDeleted              // 8: 001000
	FlagDraft                // 16: 010000
	FlagRecent               // 32: 100000
)

func ContainsFlag(flags int, flag int) bool {
	return flags&flag != 0
}

func FlagToBitwise(flag imap.Flag) int {
	switch strings.ToLower(string(flag)) {
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
	}

	return 0
}

// Convert IMAP flags (e.g., "\Seen", "\Answered") to bitwise flags
func FlagsToBitwise(flags []imap.Flag) int {
	var bitwiseFlags int

	for _, flag := range flags {
		bitwiseFlags |= FlagToBitwise(flag)
	}
	return bitwiseFlags
}

// Convert bitwise flags to IMAP flag strings
func BitwiseToFlags(bitwiseFlags int) []imap.Flag {
	var flags []imap.Flag

	if bitwiseFlags&FlagSeen != 0 {
		flags = append(flags, imap.FlagSeen)
	}
	if bitwiseFlags&FlagAnswered != 0 {
		flags = append(flags, imap.FlagAnswered)
	}
	if bitwiseFlags&FlagFlagged != 0 {
		flags = append(flags, imap.FlagFlagged)
	}
	if bitwiseFlags&FlagDeleted != 0 {
		flags = append(flags, imap.FlagDeleted)
	}
	if bitwiseFlags&FlagDraft != 0 {
		flags = append(flags, imap.FlagDraft)
	}
	// if bitwiseFlags&FlagRecent != 0 {
	// 	flags = append(flags, imap.FlagRecent)
	// }

	return flags
}

func ExtractRecipients(msg *message.Entity) []Recipient {
	header := msg.Header
	recipients := make([]Recipient, 0)
	uniquePairs := make(map[string]struct{})

	extractAddresses := func(key string) {
		values := header.Values(key)
		for _, value := range values {
			addresses, err := mail.ParseAddressList(value)
			if err == nil {
				for _, addr := range addresses {
					addressType := strings.ToLower(key)
					uniqueKey := addr.Address + "|" + addressType

					if _, exists := uniquePairs[uniqueKey]; !exists {
						recipient := Recipient{
							EmailAddress: addr.Address,
							AddressType:  addressType,
							Name:         addr.Name,
						}
						recipients = append(recipients, recipient)
						uniquePairs[uniqueKey] = struct{}{}
					}
				}
			}
		}
	}

	extractAddresses("To")
	extractAddresses("Cc")
	extractAddresses("Bcc")
	extractAddresses("From")
	extractAddresses("Reply-To")

	return recipients
}
