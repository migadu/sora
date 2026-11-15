package imap

import (
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
)

// unseenMessageUIDs returns the UIDs of messages in the batch that do not yet
// carry \Seen.
func unseenMessageUIDs(messages []db.Message) []imap.UID {
	var uids []imap.UID
	for i := range messages {
		if !db.ContainsFlag(messages[i].BitwiseFlags, db.FlagSeen) {
			uids = append(uids, messages[i].UID)
		}
	}
	return uids
}

// applyImplicitSeenUpdates updates the in-memory message models with the
// authoritative post-update flags and mod-sequences returned by
// AddMessageFlagsBatch, returning the set of UIDs whose flags actually changed.
func applyImplicitSeenUpdates(messages []db.Message, batchResults []db.BatchFlagUpdateResult) map[imap.UID]bool {
	if len(batchResults) == 0 {
		return nil
	}
	byUID := make(map[imap.UID]db.BatchFlagUpdateResult, len(batchResults))
	for _, res := range batchResults {
		if !res.PreconditionFailed {
			byUID[res.UID] = res
		}
	}
	changed := make(map[imap.UID]bool, len(byUID))
	for i := range messages {
		res, ok := byUID[messages[i].UID]
		if !ok {
			continue
		}
		sysFlags, customFlags := db.SplitFlags(res.Flags)
		messages[i].BitwiseFlags = db.FlagsToBitwise(sysFlags)
		messages[i].CustomFlags = customFlags
		modSeq := res.ModSeq
		messages[i].UpdatedModSeq = &modSeq
		changed[messages[i].UID] = true
	}
	return changed
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
