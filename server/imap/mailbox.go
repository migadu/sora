package imap

import (
	"context"
	"github.com/migadu/sora/logger"
	"sort"
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
	// Start with a base set of system flags and common keywords
	// Using a map to ensure uniqueness
	flagsMap := make(map[imap.Flag]struct{})

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
		flagsMap[f] = struct{}{}
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
				flagsMap[imap.Flag(cf)] = struct{}{}
			}
		}
	}

	finalFlagsList := make([]imap.Flag, 0, len(flagsMap))
	for f := range flagsMap {
		finalFlagsList = append(finalFlagsList, f)
	}
	sort.Slice(finalFlagsList, func(i, j int) bool { return finalFlagsList[i] < finalFlagsList[j] }) // For consistent order
	return finalFlagsList
}
