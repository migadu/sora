package server

import (
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
)

type SoraMailbox struct {
	name        string
	ID          int
	uidValidity uint32
	subscribed  bool
	uidNext     int
	readOnly    bool
	lastPollAt  time.Time
	numMessages int
}

func (m *SoraMailbox) Name() string {
	return m.name
}

func (m *SoraMailbox) PermittedFlags() []imap.Flag {
	var permFlags []imap.Flag
	switch strings.ToUpper(m.name) {
	case "DRAFTS":
		// Special case for the Drafts folder
		permFlags = []imap.Flag{
			imap.FlagSeen,     // Messages can be marked as read
			imap.FlagAnswered, // Messages can be marked as answered
			imap.FlagFlagged,  // Messages can be flagged
			imap.FlagDeleted,  // Messages can be marked for deletion
			imap.FlagDraft,    // Special Draft flag for drafts
		}
	case "INBOX":
		// Common flags for INBOX, excluding the Draft flag
		permFlags = []imap.Flag{
			imap.FlagSeen,
			imap.FlagAnswered,
			imap.FlagFlagged,
			imap.FlagDeleted,
		}
	default:
		// General case for other mailboxes like Sent, Trash, etc.
		permFlags = []imap.Flag{
			imap.FlagSeen,
			imap.FlagAnswered,
			imap.FlagFlagged,
			imap.FlagDeleted,
		}
	}
	return permFlags
}

// JoinMailboxPath joins the parent path components with the mailbox delimiter
func JoinMailboxPath(parentPathComponents []string) string {
	return strings.Join(parentPathComponents, string(consts.MailboxDelimiter))
}
