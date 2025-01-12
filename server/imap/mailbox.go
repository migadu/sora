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

	mboxTracker    *imapserver.MailboxTracker
	sessionTracker *imapserver.SessionTracker
	numMessages    uint32
}

func NewMailbox(dbmbx *db.DBMailbox, numMessages uint32) *Mailbox {
	mboxTracker := imapserver.NewMailboxTracker(numMessages)
	sessionTracker := mboxTracker.NewSession()
	return &Mailbox{
		DBMailbox:      dbmbx,
		mboxTracker:    mboxTracker,
		sessionTracker: sessionTracker,
		numMessages:    numMessages,
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

func (m *Mailbox) decodeNumSet(numSet imap.NumSet) imap.NumSet {
	seqSet, ok := numSet.(imap.SeqSet)
	if !ok {
		return numSet
	}

	// TODO: lift up to a go-imap helper
	var out imap.SeqSet
	for _, seqRange := range seqSet {
		start := m.sessionTracker.DecodeSeqNum(seqRange.Start)
		stop := m.sessionTracker.DecodeSeqNum(seqRange.Stop)
		// TODO: don't skip range if bound is expunged
		if start != 0 && stop != 0 {
			out = append(out, imap.SeqRange{Start: start, Stop: stop})
		}
	}

	return out
}
