package imap

import (
	"context"
	"sync"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/db"
)

// A streamed FETCH can name an entire mailbox while Poll waits for its sequence
// view. Keep its optional echo memo bounded; updates beyond this limit are
// reported again by Poll instead of retaining one entry per mailbox message.
const maxFetchSeenEchoEntries = 65536

// setImplicitSeen sets \Seen on msg, whose BODY[] or BINARY[] section the FETCH
// is about to return (RFC 9051 §6.4.5: "The \Seen flag is implicitly set; if
// this causes the flags to change, they SHOULD be included as part of the
// FETCH responses"), and returns the options to write its response with. A
// non-nil answer must be released after the response; answered is called only
// once the response successfully closes.
//
// It is called for one message at a time, after its body is loaded and its
// BINARY sections are decoded, so a FETCH that fails part way sets \Seen only
// on the messages it answered (#1222). Setting it for a whole stream chunk
// ahead would have to be undone on failure, which would also clear a \Seen
// another session set, or found already set, in the meantime. The update is
// one write next to the body load the message needs anyway, and none for a
// message that is \Seen already.
func (s *IMAPSession) setImplicitSeen(ctx context.Context, msg *db.Message, options *imap.FetchOptions, mailboxID int64, tracker *imapserver.SessionTracker) (*imap.FetchOptions, *implicitSeenAnswer) {
	if db.ContainsFlag(msg.BitwiseFlags, db.FlagSeen) {
		return options, nil
	}
	answer := s.lockImplicitSeenAnswer(mailboxID)
	results, err := s.server.rdb.AddMessageFlagsBatchWithRetry(ctx, []imap.UID{msg.UID}, mailboxID, []imap.Flag{imap.FlagSeen})
	if err != nil {
		s.DebugLog("failed to mark message as seen", "uid", msg.UID, "error", err)
		answer.release()
		return options, nil
	}
	s.useMasterDB.Store(true)
	if !applyImplicitSeenUpdate(msg, results) {
		answer.release()
		return options, nil
	}
	answer.expect(map[imap.UID]bool{msg.UID: true}, tracker)
	return s.fetchOptionsForImplicitSeen(options, true), answer
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

// implicitSeenAnswer keeps Poll from reporting again the \Seen that one FETCH
// update set and its FETCH response already carried (as STORE does with its
// own answers): each message answered with FLAGS is recorded in ownStoreEcho
// at the mod-sequence the update gave it, and Poll skips exactly that update.
//
// ownStoreMu is taken before the update, so Poll (the NOTIFY pump polls
// concurrently with the command) either reads its delta before the update or
// finds the answered row recorded. It is released when that response completes,
// or when an error leaves its update to Poll. It is not held during preflight
// body loading or between messages. Poll and
// another FETCH registering its metadata read contend for it. A message whose
// response was not written, because the FETCH failed or stopped before it, is never recorded:
// Poll reports its \Seen instead, or the client would never learn of it.
type implicitSeenAnswer struct {
	s         *IMAPSession
	mailboxID int64
	pending   int // changed messages not yet answered; 0 once nothing more is recorded
	unlock    func()
}

// beginFetch tracks a FETCH from before its metadata read through its final
// response. A concurrent NOTIFY fetch-att response can carry an older flag
// snapshot, so a Seen answer must leave its update to Poll while another FETCH
// is in flight. Taking ownStoreMu before the read also prevents a new FETCH
// from reading old flags during an implicit Seen update already holding it.
func (s *IMAPSession) beginFetch() func() {
	s.ownStoreMu.Lock()
	s.fetchInFlight++
	s.ownStoreMu.Unlock()
	return func() {
		s.ownStoreMu.Lock()
		s.fetchInFlight--
		s.ownStoreMu.Unlock()
	}
}

// lockImplicitSeenAnswer takes ownStoreMu ahead of a FETCH's \Seen
// update. The caller must call release once its response ends.
func (s *IMAPSession) lockImplicitSeenAnswer(mailboxID int64) *implicitSeenAnswer {
	s.ownStoreMu.Lock()
	return &implicitSeenAnswer{s: s, mailboxID: mailboxID, unlock: sync.OnceFunc(s.ownStoreMu.Unlock)}
}

// expect is given the messages whose \Seen the update set. Nothing is recorded
// while the session tracker holds updates an earlier Poll queued (behind an
// EXPUNGE that FETCH, STORE and SEARCH cannot carry, RFC 3501 §7.4.1, or one
// NOTIFY SELECTED-DELAYED defers): they reach the client after the FETCH
// responses and may be an older state of a message answered here, so Poll
// must queue each message's current state behind them. The same applies to an
// older snapshot another in-flight FETCH may still write, such as NOTIFY's
// MessageNew fetch-atts. The current FETCH itself contributes one to the count.
func (a *implicitSeenAnswer) expect(changed map[imap.UID]bool, tracker *imapserver.SessionTracker) {
	if len(changed) == 0 || tracker == nil || tracker.QueuedUpdates() > 0 || a.s.fetchInFlight > 1 {
		a.unlock()
		return
	}
	s := a.s
	entries := len(changed)
	if s.ownStoreEchoMailboxID == a.mailboxID {
		entries += len(s.ownStoreEcho)
	}
	// This metadata is optional: use a conservative map-space estimate for
	// admission without reclaiming body cache or changing response budgets.
	if entries > maxFetchSeenEchoEntries || (s.memTracker != nil && !s.memTracker.CanAllocate(256+64*int64(entries))) {
		a.unlock()
		return
	}
	a.pending = len(changed)
}

// answered records uid, one of the changed messages, once its FETCH response
// has carried its flags as of modSeq.
func (a *implicitSeenAnswer) answered(uid imap.UID, modSeq uint64) {
	if a.pending == 0 {
		return
	}
	s := a.s
	if s.ownStoreEcho == nil || s.ownStoreEchoMailboxID != a.mailboxID {
		s.ownStoreEcho = make(map[imap.UID]uint64, a.pending)
		s.ownStoreEchoMailboxID = a.mailboxID
	}
	s.ownStoreEcho[uid] = modSeq
	a.pending--
	if a.pending == 0 {
		a.unlock()
	}
}

// release ends the update: messages not answered by now are left to Poll.
func (a *implicitSeenAnswer) release() {
	a.pending = 0
	a.unlock()
}
