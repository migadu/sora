package imap

import (
	"sync"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/db"
)

// A streamed FETCH can name an entire mailbox while Poll waits for its sequence
// view. Keep its optional echo memo bounded; batches beyond this limit are
// reported again by Poll instead of retaining one entry per mailbox message.
const maxFetchSeenEchoEntries = 65536

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
//   - MODSEQ is included when the session is CONDSTORE-aware (RFC 7162 §3.1.3 / §3.2);
//   - UID is included when QRESYNC is enabled on the session (RFC 7162 §3.2.4).
func (s *IMAPSession) fetchOptionsForImplicitSeen(options *imap.FetchOptions, seenChanged bool) *imap.FetchOptions {
	if !seenChanged {
		return options
	}
	opts := *options
	opts.Flags = true
	if s.condStoreEnabled() {
		opts.ModSeq = true
	}
	if s.conn != nil && s.conn.EnabledCaps().Has(imap.CapQResync) && s.GetCapabilities().Has(imap.CapQResync) {
		opts.UID = true
	}
	return &opts
}

// implicitSeenAnswer keeps Poll from reporting again the \Seen that one FETCH
// batch set and its FETCH responses already carried (as STORE does with its
// own answers): each message answered with FLAGS is recorded in ownStoreEcho
// at the mod-sequence the update gave it, and Poll skips exactly that update.
//
// ownStoreMu is taken before the update, so Poll (the NOTIFY pump polls
// concurrently with the command) either reads its delta before the update or
// finds the answered rows recorded. It is released as soon as the last changed
// message is recorded, so it is not held while the rest of the batch streams
// bodies, nor across batches, and at the latest when the batch ends. Poll and
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

// lockImplicitSeenAnswer takes ownStoreMu ahead of a FETCH batch's \Seen
// update. The caller must call release once the batch ends.
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

// release ends the batch: the messages not answered by now are left to Poll.
func (a *implicitSeenAnswer) release() {
	a.pending = 0
	a.unlock()
}
