package imap

import (
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
)

type Mailbox struct {
	*db.DBMailbox

	mboxTracker    *imapserver.MailboxTracker
	sessionTracker *imapserver.SessionTracker
	numMessages    uint32
	highestModSeq  uint64
	sync.Mutex
}

func NewMailbox(dbmbx *db.DBMailbox, numMessages uint32, highestModSeq uint64) *Mailbox {
	mboxTracker := imapserver.NewMailboxTracker(numMessages)
	sessionTracker := mboxTracker.NewSession()
	return &Mailbox{
		DBMailbox:      dbmbx,
		mboxTracker:    mboxTracker,
		sessionTracker: sessionTracker,
		numMessages:    numMessages,
		highestModSeq:  highestModSeq,
	}
}

// getPermanentFlags returns the flags the user can permanently change, restricted
// to the rights they hold (RFC 4314 §5.1.1: FLAGS/PERMANENTFLAGS MUST reflect the
// current user's rights). Per RFC 4314 §4: \Seen needs 's', \Deleted needs 't',
// every other flag (and custom keywords, signalled by \*) needs 'w'. The mailbox
// owner holds all rights, so this returns the full set for personal mailboxes.
func getPermanentFlags(rights string) []imap.Flag {
	hasW := strings.ContainsRune(rights, 'w')
	flags := make([]imap.Flag, 0, 6)
	if strings.ContainsRune(rights, 's') {
		flags = append(flags, imap.FlagSeen)
	}
	if hasW {
		flags = append(flags, imap.FlagAnswered, imap.FlagFlagged)
	}
	if strings.ContainsRune(rights, 't') {
		flags = append(flags, imap.FlagDeleted)
	}
	if hasW {
		// \Draft is an ordinary system flag ('w'); \* signals that the client may
		// define its own keywords, which also requires 'w'.
		flags = append(flags, imap.FlagDraft, imap.FlagWildcard)
	}
	return flags
}

// GetDisplayFlags returns flags that are "defined" for this mailbox.
// This includes standard system flags, common keywords, and any custom flags
// found to be in use within this specific mailbox.
// This is used for the FLAGS response in SELECT/EXAMINE.
func getDisplayFlags(ctx context.Context, rdb *resilient.ResilientDatabase, dbMbox *db.DBMailbox, debugLog func(string, ...any)) []imap.Flag {
	// Keyword identity is case-insensitive (RFC 9051 §2.3.2), so we must never
	// advertise two case-variants of the same keyword. Key the set by the folded
	// (lower-cased) flag name and keep one representative case per identity.
	// Base/system flags are added first and win the case choice, so a stored
	// "$junk" never overrides the conventional "$Junk".
	flagsByFold := make(map[string]imap.Flag)
	addFlag := func(f imap.Flag) {
		key := strings.ToLower(string(f))
		if _, exists := flagsByFold[key]; !exists {
			flagsByFold[key] = f
		}
	}

	baseFlags := []imap.Flag{
		// Standard system flags
		imap.FlagSeen,
		imap.FlagAnswered,
		imap.FlagFlagged,
		imap.FlagDeleted,
		imap.FlagDraft,
		// Common custom flags (keywords) that clients might expect or use
		imap.FlagForwarded, // $Forwarded
		imap.FlagImportant, // $Important (RFC 8457)
		imap.FlagPhishing,  // $Phishing
		imap.FlagJunk,      // $Junk
		imap.FlagNotJunk,   // $NotJunk
	}

	for _, f := range baseFlags {
		addFlag(f)
	}

	// Fetch custom flags actually used in this mailbox from the database
	// m.DBMailbox is embedded, so m.ID gives the mailbox ID.
	if rdb != nil && dbMbox.ID > 0 {
		customFlagsFromDB, err := rdb.GetUniqueCustomFlagsForMailboxWithRetry(ctx, dbMbox.ID)
		if err != nil {
			// Log the error, but don't fail the SELECT/EXAMINE.
			// The client will still get the base set of flags.
			debugLog("error fetching custom flags for mailbox", "mailbox_id", dbMbox.ID, "name", dbMbox.Name, "error", err)
		} else {
			for _, cf := range customFlagsFromDB {
				addFlag(imap.Flag(cf))
			}
		}
	}

	finalFlagsList := make([]imap.Flag, 0, len(flagsByFold))
	for _, f := range flagsByFold {
		finalFlagsList = append(finalFlagsList, f)
	}
	slices.Sort(finalFlagsList) // For consistent order
	return finalFlagsList
}
