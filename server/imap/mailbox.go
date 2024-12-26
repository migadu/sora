package imap

import (
	"strings"
	"sync"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

type Mailbox struct {
	*db.DBMailbox

	tracker *imapserver.MailboxTracker
	mutex   sync.Mutex
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

// // JoinMailboxPath joins the parent path components with the mailbox delimiter
// func JoinMailboxPath(parentPathComponents []string) string {
// 	return strings.Join(parentPathComponents, string(consts.MailboxDelimiter))
// }

func (mbox *Mailbox) list(options *imap.ListOptions) *imap.ListData {
	mbox.mutex.Lock()
	defer mbox.mutex.Unlock()

	// Check if the mailbox should be listed
	if options.SelectSubscribed && !mbox.Subscribed {
		return nil
	}

	// Prepare attributes
	attributes := []imap.MailboxAttr{}

	if mbox.HasChildren {
		attributes = append(attributes, imap.MailboxAttrHasChildren)
	} else {
		attributes = append(attributes, imap.MailboxAttrHasNoChildren)
	}

	// Add special attributes
	switch strings.ToUpper(mbox.Name) {
	case "SENT":
		attributes = append(attributes, imap.MailboxAttrSent)
	case "TRASH":
		attributes = append(attributes, imap.MailboxAttrTrash)
	case "DRAFTS":
		attributes = append(attributes, imap.MailboxAttrDrafts)
	case "ARCHIVE":
		attributes = append(attributes, imap.MailboxAttrArchive)
	case "JUNK":
		attributes = append(attributes, imap.MailboxAttrJunk)
	}

	data := imap.ListData{
		Mailbox: mbox.Name,
		Delim:   consts.MailboxDelimiter,
		Attrs:   attributes,
	}
	if mbox.Subscribed {
		data.Attrs = append(data.Attrs, imap.MailboxAttrSubscribed)
	}
	return &data
}
