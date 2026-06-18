package imap

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/migadu/sora/logger"

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

// GetPermanentFlags returns flags that can be permanently changed, including \* for custom flags.
func getPermanentFlags() []imap.Flag {
	// All mailboxes allow standard system flags to be set.
	// The \* indicates that clients can define their own keywords.
	return []imap.Flag{
		imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagDraft, imap.FlagWildcard,
	}
}

// GetDisplayFlags returns flags that are "defined" for this mailbox.
// This includes standard system flags, common keywords, and any custom flags
// found to be in use within this specific mailbox.
// This is used for the FLAGS response in SELECT/EXAMINE.
func getDisplayFlags(ctx context.Context, rdb *resilient.ResilientDatabase, dbMbox *db.DBMailbox) []imap.Flag {
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
			logger.Debug("Error fetching custom flags for mailbox", "mailbox_id", dbMbox.ID, "name", dbMbox.Name, "error", err)
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
	sort.Slice(finalFlagsList, func(i, j int) bool { return finalFlagsList[i] < finalFlagsList[j] }) // For consistent order
	return finalFlagsList
}
