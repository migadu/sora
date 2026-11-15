package imap

import (
	"context"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
)

// setImplicitSeen sets \Seen on msg, whose BODY[] or BINARY[] section the FETCH
// is about to return (RFC 9051 §6.4.5: "The \Seen flag is implicitly set; if
// this causes the flags to change, they SHOULD be included as part of the
// FETCH responses"), and returns the options to write its response with.
//
// It is called for one message at a time, after its body is loaded and its
// BINARY sections are decoded, so a FETCH that fails part way sets \Seen only
// on the messages it answered (#1222). Setting it for a whole stream chunk
// ahead would have to be undone on failure, which would also clear a \Seen
// another session set, or found already set, in the meantime. The update is
// one write next to the body load the message needs anyway, and none for a
// message that is \Seen already.
func (s *IMAPSession) setImplicitSeen(ctx context.Context, msg *db.Message, options *imap.FetchOptions, mailboxID int64) *imap.FetchOptions {
	if db.ContainsFlag(msg.BitwiseFlags, db.FlagSeen) {
		return options
	}
	results, err := s.server.rdb.AddMessageFlagsBatchWithRetry(ctx, []imap.UID{msg.UID}, mailboxID, []imap.Flag{imap.FlagSeen})
	if err != nil {
		s.DebugLog("failed to mark message as seen", "uid", msg.UID, "error", err)
		return options
	}
	s.useMasterDB.Store(true)
	return s.fetchOptionsForImplicitSeen(options, applyImplicitSeenUpdate(msg, results))
}

// applyImplicitSeenUpdate updates the in-memory message model with the
// authoritative post-update flags and mod-sequence AddMessageFlagsBatch
// returned for it, reporting whether its flags actually changed.
func applyImplicitSeenUpdate(msg *db.Message, results []db.BatchFlagUpdateResult) bool {
	for _, res := range results {
		if res.UID != msg.UID || res.PreconditionFailed {
			continue
		}
		sysFlags, customFlags := db.SplitFlags(res.Flags)
		msg.BitwiseFlags = db.FlagsToBitwise(sysFlags)
		msg.CustomFlags = customFlags
		modSeq := res.ModSeq
		msg.UpdatedModSeq = &modSeq
		return true
	}
	return false
}

// fetchOptionsForImplicitSeen returns the per-message FetchOptions to use when
// writing FETCH data items. When FETCH implicitly added \Seen to this message:
//   - FLAGS is included so the client learns of the flag change even when Poll
//     does not emit a separate FlagChange response (RFC 3501 §6.4.5 / RFC 9051 §6.4.5);
//   - MODSEQ and UID are included when the session is CONDSTORE-aware. RFC 7162
//     §3.2.4: "Once a CONDSTORE enabling command is issued by the client, the
//     server MUST automatically include both UID and mod-sequence data in all
//     subsequent untagged FETCH responses", naming "a FETCH/UID FETCH that
//     implicitly set the \Seen flag". The trigger is any CONDSTORE enabling
//     command (ENABLE QRESYNC is one), and §3.1 asks the same of a session
//     that offers CONDSTORE without QRESYNC.
func (s *IMAPSession) fetchOptionsForImplicitSeen(options *imap.FetchOptions, seenChanged bool) *imap.FetchOptions {
	if !seenChanged {
		return options
	}
	opts := *options
	opts.Flags = true
	if s.condStoreEnabled() {
		opts.ModSeq = true
		opts.UID = true
	}
	return &opts
}
