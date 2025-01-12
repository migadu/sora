package imap

import (
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

type Mailbox struct {
	*db.DBMailbox

	tracker *imapserver.MailboxTracker
}

func NewMailbox(dbmbx *db.DBMailbox) *Mailbox {
	return &Mailbox{
		tracker:   imapserver.NewMailboxTracker(0),
		DBMailbox: dbmbx,
	}
}

func (m *Mailbox) PermittedFlags() []imap.Flag {
	var permFlags []imap.Flag
	switch strings.ToUpper(m.Name) {
	case strings.ToUpper(consts.MAILBOX_DRAFTS):
		// Special case for the Drafts folder
		permFlags = []imap.Flag{
			imap.FlagSeen,     // Messages can be marked as read
			imap.FlagAnswered, // Messages can be marked as answered
			imap.FlagFlagged,  // Messages can be flagged
			imap.FlagDeleted,  // Messages can be marked for deletion
			imap.FlagDraft,    // Special Draft flag for drafts
		}
	case strings.ToUpper(consts.MAILBOX_INBOX):
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
