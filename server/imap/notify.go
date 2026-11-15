package imap

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/metrics"
)

// notifyPollInterval is the cadence of the NOTIFY watch loop. Like IDLE, all
// change detection is modseq polling against the shared database, which is
// what makes NOTIFY correct across multiple sora servers and read replicas:
// any node's write bumps modseq via triggers, and a watcher on any other node
// observes it on the next tick. Worst-case notification latency is one tick
// plus replica lag.
var notifyPollInterval = idlePollInterval

// notifyMaxChangedMailboxes bounds the per-tick STATUS burst. When a single
// tick observes more changed mailboxes than this, the watch is dropped with
// an untagged OK [NOTIFICATIONOVERFLOW], as sanctioned by RFC 5465 §5.8, and
// the client is expected to re-sync and re-issue NOTIFY.
var notifyMaxChangedMailboxes = 100

// SetNotifyMaxChangedMailboxesForTests overrides the per-tick overflow cap so
// tests can exercise the NOTIFICATIONOVERFLOW path without churning hundreds of
// mailboxes. It must not be called outside tests.
func SetNotifyMaxChangedMailboxesForTests(n int) {
	notifyMaxChangedMailboxes = n
}

// notifyMaxFetchPerTick bounds the number of MessageNew fetch-atts responses
// emitted for the selected mailbox in a single pump tick, so a bulk delivery
// cannot turn one iteration into an unbounded FETCH. The remainder is
// delivered on subsequent ticks.
const notifyMaxFetchPerTick = 64

// notifyMaxFetchAttempts bounds the ticks in a row that MessageNew fetch-atts
// delivery retries a message it could not answer for now, such as one whose
// body cannot be read yet (NO [UNAVAILABLE]). The new messages after it wait
// for it, so one that stays unanswerable is given up after this many attempts
// instead of holding them back.
const notifyMaxFetchAttempts = 4

// SetNotifyPollIntervalForTests overrides the NOTIFY watch cadence. It exists
// so integration tests can observe asynchronous notifications without waiting
// out the production interval; it must not be called outside tests.
func SetNotifyPollIntervalForTests(d time.Duration) {
	notifyPollInterval = d
}

// notifySupportedEvents is advertised in the BADEVENT response code when a
// client requests an event sora does not support (RFC 5465 §4).
var notifySupportedEvents = []imap.NotifyEvent{
	imap.NotifyEventMessageNew,
	imap.NotifyEventMessageExpunge,
	imap.NotifyEventFlagChange,
	imap.NotifyEventMailboxName,
	imap.NotifyEventSubscriptionChange,
}

// notifySnapshotEntry is the per-mailbox slice of the account snapshot used
// for MailboxName/SubscriptionChange diffing and for specifier matching.
type notifySnapshotEntry struct {
	name        string
	uidValidity uint32
	subscribed  bool
}

// notifyWatch is the per-session NOTIFY state installed by SetNotify. After
// installation it is only touched by the pump goroutine (the library
// guarantees NotifyPoll is stopped before SetNotify runs again), except for
// the pointer swap itself and own, which are guarded by
// IMAPSession.notifyMutex.
type notifyWatch struct {
	options *imap.NotifyOptions

	// selected is the SELECTED/SELECTED-DELAYED item, if any; delayed
	// distinguishes the two.
	selected *imap.NotifyItem
	delayed  bool

	// statusMarks holds a per-mailbox high-water modseq for the STATUS fan-in:
	// mailbox M is reported only when its highest_modseq exceeds statusMarks[M].
	// A single account-wide cursor is unsound because global-sequence modseqs
	// are not commit-ordered across mailboxes — a busier mailbox committing a
	// higher modseq first would advance a shared cursor past a slower
	// mailbox's still-unreported lower-modseq change, suppressing it until that
	// mailbox's next change. A mailbox entering the matched set is initialized
	// to its current modseq (no STATUS for history that predates the watch's
	// interest in it), and marks for mailboxes that leave the set are dropped.
	statusMarks map[int64]uint64

	// snapshot is the previous tick's view of the account's mailboxes,
	// diffed to detect MailboxName and SubscriptionChange events.
	snapshot map[int64]notifySnapshotEntry

	// selectedMailboxID / nextFetchUID track MessageNew fetch-atts delivery
	// for the selected mailbox: messages with UID >= nextFetchUID have not
	// been announced with a FETCH response yet. selectedMailboxID detects
	// mailbox switches so the high-water mark is rebound.
	selectedMailboxID int64
	nextFetchUID      imap.UID

	// fetchAttempts counts the ticks in a row whose fetch failed at
	// nextFetchUID (see notifyMaxFetchAttempts).
	fetchAttempts int

	// own is written by APPEND and MOVE on the command goroutine too.
	own notifyOwnMessages
}

// notifyOwnMessages records the messages this connection's own APPEND and
// MOVE added to the selected mailbox. RFC 5465 §5.2: "A FETCH response SHOULD
// NOT be generated for a new message created by the client on this particular
// connection, for instance, as the result of an APPEND or COPY command to the
// selected mailbox performed by the client itself." The client has their UIDs
// from APPENDUID and COPYUID. (A COPY never adds to the selected mailbox: its
// source is that mailbox, and a COPY into its own source is refused.)
type notifyOwnMessages struct {
	// writes counts the own writes into the selected mailbox still in flight.
	// One may already have committed under a UID it has not recorded yet, so
	// the MessageNew fetch waits until none is.
	writes    int
	mailboxID int64
	uids      imap.UIDSet
}

// beginOwnMessages is called by APPEND and MOVE before they add messages to
// mailboxID. When a NOTIFY watch sends MessageNew fetch-atts and mailboxID is
// the selected mailbox, the write is announced to the watch, and the returned
// function, which the caller must call once the write is done, records the
// UIDs it created (none when it failed). Otherwise the function does nothing.
func (s *IMAPSession) beginOwnMessages(mailboxID int64) (done func(created ...imap.UID)) {
	s.notifyMutex.Lock()
	watch := s.notifyWatch
	s.notifyMutex.Unlock()
	if watch == nil || watch.selected == nil || watch.selected.MessageNewFetch == nil {
		return func(...imap.UID) {}
	}
	if selectedID, ok := s.currentSelectedMailboxID(); !ok || selectedID != mailboxID {
		return func(...imap.UID) {}
	}

	s.notifyMutex.Lock()
	watch.own.writes++
	s.notifyMutex.Unlock()
	return func(created ...imap.UID) {
		s.notifyMutex.Lock()
		defer s.notifyMutex.Unlock()
		watch.own.writes--
		if len(created) == 0 {
			return
		}
		if watch.own.mailboxID != mailboxID {
			watch.own.mailboxID, watch.own.uids = mailboxID, nil
		}
		watch.own.uids.AddNum(created...)
	}
}

// ownMessages returns the UIDs from nextFetchUID on that this connection's
// own writes added to the selected mailbox, forgetting the ones the fetch has
// passed and those of a mailbox no longer selected. busy reports an own write
// still in flight, whose UIDs are not known yet.
func (s *IMAPSession) ownMessages(watch *notifyWatch) (uids imap.UIDSet, busy bool) {
	s.notifyMutex.Lock()
	defer s.notifyMutex.Unlock()
	own := &watch.own
	if own.mailboxID != watch.selectedMailboxID {
		own.mailboxID, own.uids = watch.selectedMailboxID, nil
	}
	passed := 0
	for passed < len(own.uids) && own.uids[passed].Stop < watch.nextFetchUID {
		passed++
	}
	own.uids = own.uids[passed:]
	return slices.Clone(own.uids), own.writes > 0
}

// uidRangeExcept returns the UIDs from first to last that are not in except,
// which is sorted and merged, as UIDSet.AddNum keeps it.
func uidRangeExcept(first, last imap.UID, except imap.UIDSet) imap.UIDSet {
	var set imap.UIDSet
	for _, r := range except {
		if r.Stop < first {
			continue
		}
		if r.Start > last {
			break
		}
		if r.Start > first {
			set.AddRange(first, r.Start-1)
		}
		if r.Stop >= last {
			return set
		}
		first = r.Stop + 1
	}
	set.AddRange(first, last)
	return set
}

// hasSelectedMessageEvents reports whether the watch requests message events
// for the currently selected mailbox.
func (watch *notifyWatch) hasSelectedMessageEvents() bool {
	return watch.selected != nil && len(watch.selected.Events) > 0
}

// wantsTreeEvents reports whether any specifier requests MailboxName or
// SubscriptionChange events.
func (watch *notifyWatch) wantsTreeEvents() bool {
	for i := range watch.options.Items {
		for _, ev := range watch.options.Items[i].Events {
			if ev == imap.NotifyEventMailboxName || ev == imap.NotifyEventSubscriptionChange {
				return true
			}
		}
	}
	return false
}

// wantsNonSelectedItems reports whether the watch has any specifier other
// than SELECTED/SELECTED-DELAYED. When false, the pump can skip the account
// snapshot and fan-in queries entirely (a client watching only its selected
// mailbox costs no more than IDLE).
func (watch *notifyWatch) wantsNonSelectedItems() bool {
	for i := range watch.options.Items {
		item := &watch.options.Items[i]
		if item.MailboxSpec != imap.NotifyMailboxSpecSelected &&
			item.MailboxSpec != imap.NotifyMailboxSpecSelectedDelayed {
			return true
		}
	}
	return false
}

// eventsForMailbox returns the union of events requested for the given
// mailbox by all non-selected specifiers. RFC 5465 §6: multiple event groups
// can apply to the same mailbox and their events accumulate; only
// SELECTED/SELECTED-DELAYED match the currently selected mailbox, so callers
// must exclude it for message events. Mailbox names are compared
// case-insensitively, matching sora's case-insensitive unique mailbox names.
func (watch *notifyWatch) eventsForMailbox(name string, subscribed bool, sharedRoot string) map[imap.NotifyEvent]bool {
	var events map[imap.NotifyEvent]bool
	add := func(item *imap.NotifyItem) {
		if events == nil {
			events = make(map[imap.NotifyEvent]bool)
		}
		for _, ev := range item.Events {
			events[ev] = true
		}
	}

	for i := range watch.options.Items {
		item := &watch.options.Items[i]
		switch item.MailboxSpec {
		case imap.NotifyMailboxSpecSelected, imap.NotifyMailboxSpecSelectedDelayed:
			continue
		case imap.NotifyMailboxSpecPersonal:
			// RFC 5465 §6.2: all selectable mailboxes in the personal
			// namespace(s) — the shared namespace is excluded.
			if sharedRoot == "" || !mailboxNameHasPrefix(name, sharedRoot) {
				add(item)
			}
		case imap.NotifyMailboxSpecInboxes:
			// RFC 5465 §6.3: mailboxes an MDA may deliver to. Sieve fileinto
			// can target any personal mailbox, but computing that set is not
			// tractable per-connection; like Dovecot, sora maps INBOXES to
			// INBOX.
			if strings.EqualFold(name, "INBOX") {
				add(item)
			}
		case imap.NotifyMailboxSpecSubscribed:
			if subscribed {
				add(item)
			}
		default:
			for _, root := range item.Mailboxes {
				if strings.EqualFold(name, root) ||
					(item.Subtree && mailboxNameHasPrefix(name, root)) {
					add(item)
					break
				}
			}
		}
	}
	return events
}

// mailboxNameHasPrefix reports whether name is inside the subtree rooted at
// root (root itself excluded), comparing case-insensitively.
func mailboxNameHasPrefix(name, root string) bool {
	prefixLen := len(root) + 1 // root plus delimiter
	if len(name) <= prefixLen {
		return false
	}
	return strings.EqualFold(name[:len(root)], root) && name[len(root)] == byte(consts.MailboxDelimiter)
}

// notifyStatusOptions maps the message events enabled for a non-selected
// mailbox to the STATUS items required by RFC 5465 §5.1–§5.3 (and §3.1 for
// the initial STATUS responses). It returns nil when no message event is
// enabled, i.e. no STATUS response is due.
func notifyStatusOptions(events map[imap.NotifyEvent]bool, condStore bool) *imap.StatusOptions {
	options := &imap.StatusOptions{}
	any := false
	if events[imap.NotifyEventMessageNew] {
		// §5.2: STATUS (UIDNEXT MESSAGES); §3.1 adds UIDVALIDITY.
		options.NumMessages = true
		options.UIDNext = true
		options.UIDValidity = true
		any = true
	}
	if events[imap.NotifyEventMessageExpunge] {
		// §5.3: STATUS (UIDNEXT MESSAGES).
		options.NumMessages = true
		options.UIDNext = true
		any = true
	}
	if events[imap.NotifyEventFlagChange] {
		// §5.1: UIDVALIDITY and HIGHESTMODSEQ with CONDSTORE/QRESYNC,
		// otherwise the server MAY report UNSEEN (without it there would be
		// nothing to notify).
		options.UIDValidity = true
		if condStore {
			options.HighestModSeq = true
		} else {
			options.NumUnseen = true
		}
		any = true
	}
	if !any {
		return nil
	}
	if condStore {
		options.HighestModSeq = true
	}
	return options
}

// notifyStatusData builds the StatusData for one fan-in row, populating every
// field the options request.
func notifyStatusData(name string, uidValidity uint32, row db.MailboxStatsRow, options *imap.StatusOptions) *imap.StatusData {
	data := &imap.StatusData{Mailbox: name}
	if options.NumMessages {
		numMessages := row.MessageCount
		data.NumMessages = &numMessages
	}
	if options.UIDNext {
		data.UIDNext = imap.UID(row.HighestUID + 1)
	}
	if options.UIDValidity {
		data.UIDValidity = uidValidity
	}
	if options.NumUnseen {
		numUnseen := row.UnseenCount
		data.NumUnseen = &numUnseen
	}
	if options.HighestModSeq {
		// A mailbox that has never held a message has no mailbox_stats row
		// and a raw highest_modseq of 0, which the callers need as-is for
		// their activity checks and statusMarks. The client must see 1, as
		// STATUS, LIST-STATUS and SELECT report (GetMailboxSummary): RFC 7162
		// section 7 reserves HIGHESTMODSEQ 0 for a mailbox without persistent
		// mod-sequences.
		data.HighestModSeq = max(row.HighestModSeq, 1)
	}
	return data
}

// sharedNamespaceRoot returns the shared-mailbox namespace root ("Shared" for
// prefix "Shared/"), or "" when shared mailboxes are disabled.
func (s *IMAPSession) sharedNamespaceRoot() string {
	if s.server.config != nil && s.server.config.SharedMailboxes.Enabled {
		return strings.TrimSuffix(s.server.config.SharedMailboxes.NamespacePrefix, string(consts.MailboxDelimiter))
	}
	return ""
}

// notifyWatchActive reports whether a NOTIFY watch is installed. Used by
// Idle to hand event delivery over to the pump while a watch is active.
func (s *IMAPSession) notifyWatchActive() bool {
	s.notifyMutex.Lock()
	defer s.notifyMutex.Unlock()
	return s.notifyWatch != nil
}

// SetNotify implements imapserver.SessionNotify. It validates the requested
// events, resolves the watch against the account's current mailboxes,
// initializes the fan-in cursor, and — when the STATUS indicator is present —
// writes the initial STATUS responses (RFC 5465 §3.1) before returning, so
// they precede NOTIFY's tagged OK.
func (s *IMAPSession) SetNotify(ctx context.Context, options *imap.NotifyOptions, w *imapserver.UpdateWriter) error {
	if options == nil {
		s.notifyMutex.Lock()
		s.notifyWatch = nil
		s.notifyMutex.Unlock()
		s.InfoLog("NOTIFY watch cleared")
		return nil
	}

	for i := range options.Items {
		for _, ev := range options.Items[i].Events {
			switch ev {
			case imap.NotifyEventMessageNew, imap.NotifyEventMessageExpunge,
				imap.NotifyEventFlagChange, imap.NotifyEventMailboxName,
				imap.NotifyEventSubscriptionChange:
				// supported
			default:
				return &imapserver.UnsupportedNotifyEventError{Supported: notifySupportedEvents}
			}
		}
		// The MessageNew fetch-atts are answered through Fetch: refuse here
		// what Fetch would refuse for every new message (RFC 5465 §3.1: "BAD -
		// Command unknown, invalid, unsupported, or has unknown arguments").
		if fetch := options.Items[i].MessageNewFetch; fetch != nil {
			if err := s.requireFetchBinary(fetch); err != nil {
				return err
			}
		}
	}

	watch := &notifyWatch{options: options}
	for i := range options.Items {
		item := &options.Items[i]
		if item.MailboxSpec == imap.NotifyMailboxSpecSelected ||
			item.MailboxSpec == imap.NotifyMailboxSpecSelectedDelayed {
			watch.selected = item
			watch.delayed = item.MailboxSpec == imap.NotifyMailboxSpecSelectedDelayed
		}
	}

	// Honor the session's master-DB pinning for read-your-own-writes, like
	// Poll does.
	readCtx := ctx
	if s.useMasterDB.Load() {
		readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	}

	// If the session lock is momentarily contended, treat as "none selected"
	// for bootstrap: the first tick sees the real selection as a switch and
	// rebinds the fetch high-water mark, so nothing is lost.
	selectedID, _ := s.currentSelectedMailboxID()
	watch.selectedMailboxID = selectedID

	// Bootstrap the watch: the account snapshot (specifier matching and
	// tree-event diffing), the fan-in cursor, the MessageNew fetch-atts
	// high-water mark, and — when the STATUS indicator is present — the
	// initial STATUS responses, all from at most two queries. A watch
	// covering only the selected mailbox skips the snapshot entirely.
	needSelectedStats := selectedID != 0 && watch.selected != nil && watch.selected.MessageNewFetch != nil
	var bootstrapIDs []int64
	if watch.wantsNonSelectedItems() {
		snapshot, matchedIDs, err := s.notifySnapshotAndMatches(readCtx, watch, selectedID)
		if err != nil {
			return s.internalError("failed to resolve NOTIFY watch: %v", err)
		}
		watch.snapshot = snapshot
		bootstrapIDs = matchedIDs
	}
	if needSelectedStats {
		bootstrapIDs = append(append([]int64{}, bootstrapIDs...), selectedID)
	}
	if len(bootstrapIDs) > 0 {
		rows, err := s.server.rdb.GetMailboxesStatsWithRetry(readCtx, bootstrapIDs)
		if err != nil {
			return s.internalError("failed to bootstrap NOTIFY watch: %v", err)
		}
		watch.statusMarks = make(map[int64]uint64, len(bootstrapIDs))
		sharedRoot := s.sharedNamespaceRoot()
		for _, row := range rows {
			if row.MailboxID == selectedID {
				watch.nextFetchUID = imap.UID(row.HighestUID + 1)
				continue
			}
			// Seed the per-mailbox mark at the current modseq so only changes
			// after NOTIFY SET are reported. The initial STATUS responses of
			// NOTIFY SET STATUS (RFC 5465 §3.1) are absolute snapshots and are
			// sent here regardless.
			watch.statusMarks[row.MailboxID] = row.HighestModSeq
			if options.Status {
				entry, ok := watch.snapshot[row.MailboxID]
				if !ok {
					continue
				}
				statusOptions := notifyStatusOptions(watch.eventsForMailbox(entry.name, entry.subscribed, sharedRoot), w.CondStoreEnabled())
				if statusOptions == nil {
					continue
				}
				if err := w.WriteStatus(notifyStatusData(entry.name, entry.uidValidity, row, statusOptions), statusOptions); err != nil {
					return err
				}
			}
		}
	}

	s.notifyMutex.Lock()
	s.notifyWatch = watch
	s.notifyMutex.Unlock()

	s.InfoLog("NOTIFY watch installed",
		"groups", len(options.Items),
		"status", options.Status,
		"selected_events", watch.hasSelectedMessageEvents(),
		"delayed", watch.delayed)
	return nil
}

// NotifyPoll implements imapserver.SessionNotify: the watch pump. It runs on
// a dedicated goroutine, concurrently with command processing, until stop is
// closed or the connection goes away.
func (s *IMAPSession) NotifyPoll(ctx context.Context, w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	s.notifyMutex.Lock()
	watch := s.notifyWatch
	s.notifyMutex.Unlock()
	if watch == nil {
		return nil
	}

	metrics.IMAPNotifySessions.Inc()
	defer metrics.IMAPNotifySessions.Dec()

	ticker := time.NewTicker(notifyPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return nil
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			done, err := s.notifyTick(ctx, watch, w)
			if err != nil || done {
				return err
			}
		}
	}
}

// notifyTick runs one iteration of the watch: selected-mailbox delivery via
// the regular poll pipeline, then the account fan-in (snapshot diff for
// mailbox-tree events, one mailbox_stats poll for message events in
// non-selected mailboxes). It returns done=true when the watch ended (dropped
// on overflow, or the connection must close).
func (s *IMAPSession) notifyTick(ctx context.Context, watch *notifyWatch, w *imapserver.UpdateWriter) (done bool, err error) {
	if ctx.Err() != nil {
		return true, nil
	}

	readCtx := ctx
	if s.useMasterDB.Load() {
		readCtx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	}

	selectedID, ok := s.currentSelectedMailboxID()
	if !ok {
		// Could not read the selected mailbox (session lock contended). Skip
		// this tick rather than misread it as "nothing selected"; retry next
		// tick.
		return false, nil
	}
	if selectedID != watch.selectedMailboxID {
		// The client selected another mailbox: rebind the MessageNew
		// fetch-atts high-water mark so only messages arriving from now on
		// are announced with a FETCH.
		watch.selectedMailboxID = selectedID
		watch.nextFetchUID, watch.fetchAttempts = 0, 0
		if selectedID != 0 && watch.selected != nil && watch.selected.MessageNewFetch != nil {
			rows, err := s.server.rdb.GetMailboxesStatsWithRetry(readCtx, []int64{selectedID})
			if err != nil {
				s.WarnLog("NOTIFY: failed to rebind fetch high-water mark", "error", err)
			} else if len(rows) == 1 {
				watch.nextFetchUID = imap.UID(rows[0].HighestUID + 1)
			}
		}
	}

	// Selected mailbox: reuse the regular poll pipeline (tracker, desync
	// protection, CONDSTORE handling) to deliver EXISTS/EXPUNGE/flag updates,
	// then the MessageNew fetch attributes.
	if selectedID != 0 && watch.hasSelectedMessageEvents() {
		wantFetch := watch.selected != nil && watch.selected.MessageNewFetch != nil

		// Capture the fetch-atts upper bound BEFORE delivering EXISTS. The
		// EXISTS that s.Poll delivers is read from the database at a point at
		// or after this read, so it is guaranteed to announce every UID up to
		// fetchUpto — satisfying RFC 5465 §5.2 (EXISTS precedes the FETCH).
		// Reading it after s.Poll (as the fan-in did) could pick up a message
		// delivered between the two reads whose EXISTS was not sent, producing
		// a FETCH for a message the client has not been told exists.
		var fetchUpto imap.UID
		if wantFetch {
			if rows, statErr := s.server.rdb.GetMailboxesStatsWithRetry(readCtx, []int64{selectedID}); statErr == nil && len(rows) == 1 {
				fetchUpto = imap.UID(rows[0].HighestUID)
			}
		}
		// w.ExpungeAllowed() withholds expunges while FETCH, STORE, SEARCH,
		// SORT or THREAD is in progress (RFC 3501 §7.4.1). SELECTED-DELAYED
		// "requires the server to delay a MessageExpunge event until the
		// client issues a command that allows returning information about
		// expunged messages" (RFC 5465 §6.1.2), so they also wait while no
		// command is in progress: the pump releases them during NOOP, IDLE,
		// CHECK and EXPUNGE, and any other command that allows them releases
		// them in its own poll when it ends.
		allowExpunge := w.ExpungeAllowed()
		if watch.delayed {
			allowExpunge = w.DelayedExpungeAllowed()
		}
		polled := true
		if err := s.Poll(ctx, w, allowExpunge); err != nil {
			var imapErr *imap.Error
			if errors.As(err, &imapErr) && imapErr.Type == imap.StatusResponseTypeBye {
				// The poll pipeline decided the session is beyond repair
				// (tracker desync): terminate the connection like the
				// command path would.
				s.WarnLog("NOTIFY: terminating connection on poll desync", "error", imapErr.Text)
				_ = s.conn.Bye(imapErr.Text)
				return true, nil
			}
			// Transient failure (e.g. database hiccup): keep the watch, try
			// again next tick.
			s.WarnLog("NOTIFY: selected mailbox poll failed", "error", err)
			polled = false
		}

		// Deliver fetch-atts only once the EXISTS was delivered (RFC 5465 §5.2:
		// the EXISTS comes first): the poll succeeded and left nothing queued.
		// A withheld expunge holds back the EXISTS queued behind it, and the
		// FETCH then waits for the client's next sync point, as §6.1.2 allows
		// for SELECTED-DELAYED ("the server MAY also delay returning other
		// <message-event>s"). nextFetchUID stays unadvanced, so nothing is
		// lost.
		if wantFetch && polled && s.selectedUpdatesDelivered() {
			if err := s.notifyFetchNewMessages(ctx, watch, fetchUpto, w); err != nil {
				return false, err
			}
		}
	}

	if !watch.wantsNonSelectedItems() {
		return false, nil
	}

	// Account snapshot: powers specifier matching, tree-event diffing, and
	// the fan-in ID set. Skipped when only the selected mailbox is watched.
	var (
		snapshot   map[int64]notifySnapshotEntry
		matchedIDs []int64
	)
	sharedRoot := s.sharedNamespaceRoot()
	if watch.wantsNonSelectedItems() {
		var err error
		snapshot, matchedIDs, err = s.notifySnapshotAndMatches(readCtx, watch, selectedID)
		if err != nil {
			s.WarnLog("NOTIFY: account snapshot failed", "error", err)
			return false, nil
		}

		// Guard against a read-pool failover to a more-lagged replica, whose
		// sharply smaller view would otherwise be diffed into a storm of false
		// deletions (and, next tick, false creations). Skip the whole tick and
		// keep the prior snapshot/marks; retry next tick.
		if watch.snapshot != nil && notifySnapshotLooksStale(watch.snapshot, snapshot) {
			s.WarnLog("NOTIFY: account snapshot shrank sharply, likely replica lag; skipping tick",
				"prev", len(watch.snapshot), "cur", len(snapshot))
			return false, nil
		}

		if watch.wantsTreeEvents() {
			if err := s.notifyDiffSnapshots(watch, snapshot, sharedRoot, w); err != nil {
				return false, err
			}
		}
		watch.snapshot = snapshot
	}

	// Fan-in: detect message events in non-selected matched mailboxes and
	// report them as STATUS. The selected mailbox is deliberately excluded —
	// its changes flow through the tracker (EXISTS/EXPUNGE/FETCH) above, never
	// STATUS, and it must not pollute the per-mailbox marks.
	if watch.statusMarks == nil {
		watch.statusMarks = make(map[int64]uint64)
	}
	if len(matchedIDs) == 0 {
		// No matched mailbox this tick: forget all marks so a mailbox that
		// re-enters the set later is re-initialized to its then-current state.
		if len(watch.statusMarks) > 0 {
			watch.statusMarks = make(map[int64]uint64)
		}
		return false, nil
	}

	// Split the matched set into mailboxes already tracked (a mark from a prior
	// tick) and mailboxes newly entering the set this tick. Drop marks for
	// mailboxes that left the set.
	matchedSet := make(map[int64]struct{}, len(matchedIDs))
	var knownIDs, newIDs []int64
	for _, id := range matchedIDs {
		matchedSet[id] = struct{}{}
		if _, ok := watch.statusMarks[id]; ok {
			knownIDs = append(knownIDs, id)
		} else {
			newIDs = append(newIDs, id)
		}
	}
	for id := range watch.statusMarks {
		if _, ok := matchedSet[id]; !ok {
			delete(watch.statusMarks, id)
		}
	}

	var changed []db.MailboxStatsRow

	// Newly-matched mailboxes: a mailbox that enters the set after the watch was
	// installed represents activity the client has not heard about — a mailbox
	// created after NOTIFY SET (report it), or a pre-existing one re-entering the
	// set, e.g. after UNSELECT (a single absolute STATUS is harmless). Report
	// those with any message activity once (highest_modseq > 0), and mark every
	// new mailbox at its current modseq so it is not re-reported next tick. This
	// differs from the SetNotify bootstrap, which seeds marks silently because
	// pre-watch state is not "new".
	if len(newIDs) > 0 {
		initRows, initErr := s.server.rdb.GetMailboxesStatsWithRetry(readCtx, newIDs)
		if initErr != nil {
			s.WarnLog("NOTIFY: mailbox stats init failed", "error", initErr)
			return false, nil
		}
		seen := make(map[int64]struct{}, len(initRows))
		for _, r := range initRows {
			watch.statusMarks[r.MailboxID] = r.HighestModSeq
			seen[r.MailboxID] = struct{}{}
			if r.HighestModSeq > 0 {
				changed = append(changed, r)
			}
		}
		// A mailbox that vanished before its init read still needs a mark so it
		// is not treated as new every tick until it leaves the set.
		for _, id := range newIDs {
			if _, ok := seen[id]; !ok {
				watch.statusMarks[id] = 0
			}
		}
	}

	// Known mailboxes: poll from the lowest of their marks, then keep each row
	// that advanced past its own mailbox's mark. This reports every mailbox
	// exactly once per change without a shared cursor skipping any (see
	// statusMarks), and keeps the query floor high so a single new mailbox does
	// not force a full-history scan of the whole matched set.
	if len(knownIDs) > 0 {
		floor := watch.statusMarks[knownIDs[0]]
		for _, id := range knownIDs[1:] {
			if m := watch.statusMarks[id]; m < floor {
				floor = m
			}
		}
		rows, err := s.server.rdb.PollMailboxStatsWithRetry(readCtx, knownIDs, floor)
		if err != nil {
			s.WarnLog("NOTIFY: mailbox stats poll failed", "error", err)
			return false, nil
		}
		for _, row := range rows {
			if row.HighestModSeq > watch.statusMarks[row.MailboxID] {
				changed = append(changed, row)
			}
		}
	}

	if len(changed) > notifyMaxChangedMailboxes {
		// RFC 5465 §5.8: tell the client and behave as if NOTIFY NONE was
		// received. The library treats NotifyPoll returning as the pump
		// ending; the watch state is cleared here.
		s.WarnLog("NOTIFY: notification overflow, dropping watch", "changed_mailboxes", len(changed))
		metrics.IMAPNotifyOverflows.Inc()
		s.notifyMutex.Lock()
		s.notifyWatch = nil
		s.notifyMutex.Unlock()
		return true, w.WriteNotificationOverflow()
	}

	condStore := w.CondStoreEnabled()
	for _, row := range changed {
		watch.statusMarks[row.MailboxID] = row.HighestModSeq

		entry, ok := snapshot[row.MailboxID]
		if !ok {
			continue
		}
		statusOptions := notifyStatusOptions(watch.eventsForMailbox(entry.name, entry.subscribed, sharedRoot), condStore)
		if statusOptions == nil {
			continue
		}
		if err := w.WriteStatus(notifyStatusData(entry.name, entry.uidValidity, row, statusOptions), statusOptions); err != nil {
			return false, err
		}
		metrics.IMAPNotifyEventsSent.WithLabelValues("status").Inc()
	}

	return false, nil
}

// notifySnapshotAndMatches loads the account's current mailboxes and returns
// the snapshot (used for tree-event diffing, which needs only the RFC 4314 'l'
// lookup right that GetMailboxes already enforces) plus the IDs of
// non-selected mailboxes whose message events the client requested — the
// STATUS fan-in set.
//
// Message events additionally require the 'r' (read) right on the mailbox
// (RFC 5465 §5): a shared mailbox the user can LIST ('l') but not read must
// not disclose message counts via NOTIFY STATUS. Owned mailboxes
// (AccountID == the session's account) always have full rights; shared
// mailboxes accessed via ACL are checked for 'r' and dropped from the fan-in
// if it is absent.
func (s *IMAPSession) notifySnapshotAndMatches(ctx context.Context, watch *notifyWatch, selectedID int64) (map[int64]notifySnapshotEntry, []int64, error) {
	accountID := s.AccountID()
	mboxes, err := s.server.rdb.GetMailboxNotifySnapshotWithRetry(ctx, accountID)
	if err != nil {
		return nil, nil, err
	}

	sharedRoot := s.sharedNamespaceRoot()
	snapshot := make(map[int64]notifySnapshotEntry, len(mboxes))
	var matchedIDs []int64
	for _, m := range mboxes {
		snapshot[m.ID] = notifySnapshotEntry{
			name:        m.Name,
			uidValidity: m.UIDValidity,
			subscribed:  m.Subscribed,
		}
		if m.ID == selectedID {
			continue
		}
		events := watch.eventsForMailbox(m.Name, m.Subscribed, sharedRoot)
		if !(events[imap.NotifyEventMessageNew] || events[imap.NotifyEventMessageExpunge] || events[imap.NotifyEventFlagChange]) {
			continue
		}
		if m.OwnerID != accountID {
			// Shared mailbox accessed via ACL: message events need the 'r'
			// right (RFC 5465 §5), which is stronger than the 'l' right
			// the snapshot query verified.
			hasRead, err := s.server.rdb.CheckMailboxPermissionWithRetry(ctx, m.ID, accountID, db.ACLRightRead)
			if err != nil {
				s.WarnLog("NOTIFY: read-right check failed, excluding shared mailbox from STATUS fan-in", "mailbox_id", m.ID, "error", err)
				continue
			}
			if !hasRead {
				continue
			}
		}
		matchedIDs = append(matchedIDs, m.ID)
	}
	return snapshot, matchedIDs, nil
}

// notifyTreeEvent is one detected mailbox-tree change.
type notifyTreeEvent struct {
	event   imap.NotifyEvent // MailboxName or SubscriptionChange
	name    string
	oldName string // for renames
	// deleted marks a name that refers to no mailbox the client can access
	// after the change: a deleted mailbox, or the missing parent of a
	// created or deleted one.
	deleted bool
	// hasChildren reports whether a mailbox the client can access is below
	// name after the change.
	hasChildren bool
	entry       notifySnapshotEntry
}

// diffNotifySnapshots compares two account snapshots and returns the
// mailbox-tree changes between them: creations, deletions, renames (same ID,
// new name) and subscription flips.
//
// RFC 5465 §5.4: "If a mailbox is created or deleted, the mailbox itself and
// its direct parent (whether it is an existing mailbox or not) are considered
// to be affected", so the parent of each created or deleted mailbox is
// reported too, once. "When a mailbox is renamed, its children are renamed
// too. No additional MailboxName events are sent for children in this case":
// a mailbox whose rename is that of a superior renamed in the same diff is not
// reported (renamedWithSuperior).
//
// Deletions are emitted before creations/renames so that a delete+recreate of
// a same-named mailbox within one tick (distinct IDs: the old ID vanishes, a
// new ID appears under the same name) leaves the client with the mailbox
// present. Emitting the create-then-delete order would leave it believing the
// name no longer exists. The parents come last, as they are after all the
// changes.
func diffNotifySnapshots(prev, cur map[int64]notifySnapshotEntry) []notifyTreeEvent {
	// renamed maps the lower-cased old name of each mailbox renamed in this
	// diff to its new name.
	var renamed map[string]string
	for id, entry := range cur {
		if old, existed := prev[id]; existed && old.name != entry.name {
			if renamed == nil {
				renamed = make(map[string]string)
			}
			renamed[strings.ToLower(old.name)] = entry.name
		}
	}

	var events []notifyTreeEvent
	var createdOrDeleted []string
	for id, old := range prev {
		if _, exists := cur[id]; !exists {
			events = append(events, notifyTreeEvent{event: imap.NotifyEventMailboxName, name: old.name, deleted: true, entry: old})
			createdOrDeleted = append(createdOrDeleted, old.name)
		}
	}
	for id, entry := range cur {
		old, existed := prev[id]
		switch {
		case !existed:
			events = append(events, notifyTreeEvent{event: imap.NotifyEventMailboxName, name: entry.name, entry: entry})
			createdOrDeleted = append(createdOrDeleted, entry.name)
		case old.name != entry.name && !renamedWithSuperior(old.name, entry.name, renamed):
			events = append(events, notifyTreeEvent{event: imap.NotifyEventMailboxName, name: entry.name, oldName: old.name, entry: entry})
		case old.subscribed != entry.subscribed:
			events = append(events, notifyTreeEvent{event: imap.NotifyEventSubscriptionChange, name: entry.name, entry: entry})
		}
	}
	if len(events) == 0 {
		return nil
	}

	// live holds the mailboxes the client can access by lower-cased name, and
	// superiors every lower-cased name that one of them is below.
	live := make(map[string]notifySnapshotEntry, len(cur))
	superiors := make(map[string]bool)
	for _, entry := range cur {
		lower := strings.ToLower(entry.name)
		live[lower] = entry
		for i := strings.LastIndexByte(lower, consts.MailboxDelimiter); i > 0 && !superiors[lower[:i]]; i = strings.LastIndexByte(lower[:i], consts.MailboxDelimiter) {
			superiors[lower[:i]] = true
		}
	}

	reported := make(map[string]bool, len(events))
	for _, ev := range events {
		if ev.event == imap.NotifyEventMailboxName {
			reported[strings.ToLower(ev.name)] = true
		}
	}
	for _, name := range createdOrDeleted {
		i := strings.LastIndexByte(name, consts.MailboxDelimiter)
		if i <= 0 {
			continue
		}
		parent := name[:i]
		lower := strings.ToLower(parent)
		if reported[lower] {
			continue
		}
		reported[lower] = true
		if entry, ok := live[lower]; ok {
			events = append(events, notifyTreeEvent{event: imap.NotifyEventMailboxName, name: entry.name, entry: entry})
		} else {
			// §5.4: "If, after the event, the mailbox name does not refer
			// to a mailbox accessible to the client, the \Nonexistent flag
			// MUST be included."
			events = append(events, notifyTreeEvent{event: imap.NotifyEventMailboxName, name: parent, deleted: true})
		}
	}

	for i := range events {
		events[i].hasChildren = superiors[strings.ToLower(events[i].name)]
	}
	return events
}

// renamedWithSuperior reports whether the rename of a mailbox from oldName to
// newName is the one a superior renamed in the same diff gave it. A RENAME
// renames the inferiors of the mailbox by replacing its old name at the start
// of their names with the new one (db.RenameMailbox). renamed maps the
// lower-cased old name of each renamed mailbox to its new name.
func renamedWithSuperior(oldName, newName string, renamed map[string]string) bool {
	for i := strings.LastIndexByte(oldName, consts.MailboxDelimiter); i > 0; i = strings.LastIndexByte(oldName[:i], consts.MailboxDelimiter) {
		if to, ok := renamed[strings.ToLower(oldName[:i])]; ok && newName == to+oldName[i:] {
			return true
		}
	}
	return false
}

// notifySnapshotLooksStale reports whether cur is a sharply smaller view of the
// account than prev — the signature of a read-pool failover to a more-lagged
// replica rather than a real bulk deletion. Used to suppress a whole fan-in
// tick so it does not emit a storm of false \NonExistent (then, next tick,
// false creation) LIST events. Genuine bulk deletes beyond the threshold are
// reported when the client next re-LISTs.
func notifySnapshotLooksStale(prev, cur map[int64]notifySnapshotEntry) bool {
	return len(prev) >= 4 && len(cur)*2 < len(prev)
}

// notifyDiffSnapshots emits LIST responses for mailbox-tree changes since the
// previous tick (RFC 5465 §5.4, §5.5). The first tick after SetNotify diffs
// against the bootstrap snapshot, so only changes after NOTIFY SET are
// reported.
func (s *IMAPSession) notifyDiffSnapshots(watch *notifyWatch, cur map[int64]notifySnapshotEntry, sharedRoot string, w *imapserver.UpdateWriter) error {
	events := diffNotifySnapshots(watch.snapshot, cur)
	if len(events) == 0 {
		return nil
	}
	// As in LIST, the child attributes go with the CHILDREN capability.
	children := s.GetCapabilities().Has(imap.CapChildren)
	for _, ev := range events {
		if !watch.eventsForMailbox(ev.name, ev.entry.subscribed, sharedRoot)[ev.event] {
			continue
		}
		data := &imap.ListData{
			Mailbox: ev.name,
			Delim:   consts.MailboxDelimiter,
		}
		if ev.deleted {
			// §5.4: names no longer accessible carry \NonExistent.
			data.Attrs = append(data.Attrs, imap.MailboxAttrNonExistent)
		} else {
			if ev.oldName != "" {
				// §5.4: renames announce the new name with OLDNAME (the
				// NOTIFY writer includes it for every client).
				data.OldName = ev.oldName
			}
			if ev.entry.subscribed {
				// §5.5: \Subscribed if and only if subscribed after the event.
				data.Attrs = append(data.Attrs, imap.MailboxAttrSubscribed)
			}
		}
		if children {
			// §5.4: "The server SHOULD also include \HasChildren or
			// \HasNoChildren attributes [RFC5258] as appropriate."
			data.Attrs = append(data.Attrs, childAttr(ev.hasChildren))
		}
		if err := w.WriteList(data); err != nil {
			return err
		}
		metrics.IMAPNotifyEventsSent.WithLabelValues("list").Inc()
	}
	return nil
}

// notifyFetchNewMessages honors the MessageNew fetch-atts of the selected
// mailbox (RFC 5465 §5.2): for messages up to fetchUpto whose EXISTS the
// caller has already delivered, send a FETCH response with the requested
// items through the regular FETCH machinery. The caller guarantees fetchUpto
// was read no later than the delivered EXISTS, so every fetched UID is already
// announced.
func (s *IMAPSession) notifyFetchNewMessages(ctx context.Context, watch *notifyWatch, fetchUpto imap.UID, w *imapserver.UpdateWriter) error {
	if watch.selected == nil || watch.selected.MessageNewFetch == nil || !watch.hasSelectedMessageEvents() {
		return nil
	}
	if watch.nextFetchUID == 0 {
		// High-water mark not initialized (bootstrap or rebind failure):
		// initialize forward so history is not replayed.
		watch.nextFetchUID = fetchUpto + 1
		return nil
	}
	if fetchUpto < watch.nextFetchUID {
		return nil // nothing new
	}

	// Bound the per-tick fetch: a bulk delivery of many messages must not turn
	// one pump iteration into an unbounded FETCH (potentially with body
	// sections backed by object storage). The remainder is delivered on
	// subsequent ticks. STATUS bursts are capped separately by
	// notifyMaxChangedMailboxes.
	upper := fetchUpto
	if uint64(upper)-uint64(watch.nextFetchUID)+1 > notifyMaxFetchPerTick {
		upper = watch.nextFetchUID + imap.UID(notifyMaxFetchPerTick) - 1
	}

	// The messages this connection added itself get no FETCH (RFC 5465 §5.2).
	// While one of its writes is in flight, one of them may be up to fetchUpto
	// unrecorded: wait for a later tick.
	own, busy := s.ownMessages(watch)
	if busy {
		return nil
	}

	// This is an unsolicited FETCH, not the answer to a FETCH command, so
	// RFC 7162 §3.1 applies in full: a CONDSTORE-aware client gets
	// "mod-sequence data in all subsequent untagged FETCH responses", and
	// §3.2.4 "both UID and mod-sequence data", whatever the fetch-atts name.
	// Request MODSEQ even before CONDSTORE is enabled: a first enabling
	// command can run while this fetch loads a body. The response writer
	// checks current awareness when it writes the unsolicited response.
	options := *watch.selected.MessageNewFetch
	options.UID = true
	options.ModSeq = true

	// The fetch answers the messages in UID order and stops at the first one
	// it cannot answer, so nextFetchUID only passes what it got through: each
	// message is sent its FETCH once (RFC 5465 §5.2: "The server SHOULD avoid
	// sending duplicate data"), and none is lost behind a message that fails.
	// One whose fetch-atts can never be answered, a BINARY section whose
	// Content-Transfer-Encoding cannot be decoded (NO [UNKNOWN-CTE], RFC 9051
	// §7.5.2) or a body or section larger than the session memory budget (NO
	// [LIMIT], sectionMemoryRefused), is passed over at once. Any other
	// failure, such as a body that cannot be read right now (NO
	// [UNAVAILABLE]), is retried on the next tick, until
	// notifyMaxFetchAttempts gives the message up.
	for watch.nextFetchUID <= upper {
		uidSet := uidRangeExcept(watch.nextFetchUID, upper, own)
		if len(uidSet) == 0 {
			watch.nextFetchUID, watch.fetchAttempts = upper+1, 0
			return nil
		}
		var progress fetchProgress
		err := s.fetch(ctx, w.FetchWriter(), uidSet, &options, &progress)
		if err == nil {
			watch.nextFetchUID, watch.fetchAttempts = upper+1, 0
			metrics.IMAPNotifyEventsSent.WithLabelValues("fetch").Inc()
			return nil
		}
		// Resume at the message it failed at; after one that did not fail at
		// a message (busy session, database error), after the last answered.
		resume := progress.answered + 1
		if progress.failed != 0 {
			resume = progress.failed
		}
		if resume > watch.nextFetchUID {
			watch.nextFetchUID, watch.fetchAttempts = resume, 0
		}
		if ctx.Err() != nil {
			return nil // the session is going away
		}

		var imapErr *imap.Error
		if progress.failed != 0 && errors.As(err, &imapErr) &&
			(imapErr.Code == imap.ResponseCodeUnknownCTE || imapErr.Code == imap.ResponseCodeLimit) {
			s.InfoLog("NOTIFY: MessageNew fetch-atts cannot be answered for a message, passing over it",
				"uid", progress.failed, "error", err)
			watch.nextFetchUID, watch.fetchAttempts = progress.failed+1, 0
			continue
		}
		watch.fetchAttempts++
		if watch.fetchAttempts < notifyMaxFetchAttempts {
			s.InfoLog("NOTIFY: MessageNew fetch failed, retrying next tick",
				"uid", progress.failed, "attempt", watch.fetchAttempts, "error", err)
			return nil
		}
		s.WarnLog("NOTIFY: MessageNew fetch failed, giving up",
			"uid", progress.failed, "attempts", watch.fetchAttempts, "error", err)
		watch.fetchAttempts = 0
		if progress.failed == 0 {
			watch.nextFetchUID = upper + 1 // not at a message: give up the range
			return nil
		}
		watch.nextFetchUID = progress.failed + 1
	}
	return nil
}

// selectedUpdatesDelivered reports whether the session tracker holds no update
// for the client, so that every EXISTS a poll queued has been sent. It is
// false when no mailbox is selected, or when the session lock is contended.
func (s *IMAPSession) selectedUpdatesDelivered() bool {
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(s.ctx)
	if !acquired {
		return false
	}
	defer release()
	return s.sessionTracker != nil && s.sessionTracker.QueuedUpdates() == 0
}

// currentSelectedMailboxID reads the selected mailbox ID under the session
// lock. ok is false if the lock could not be acquired within the timeout — the
// caller must not treat that as "nothing selected" (id 0), which would falsely
// look like a mailbox switch and reset watch state; it should retry later.
// When ok is true, id is 0 iff no mailbox is selected.
func (s *IMAPSession) currentSelectedMailboxID() (id int64, ok bool) {
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(s.ctx)
	if !acquired {
		return 0, false
	}
	defer release()
	if s.selectedMailbox == nil {
		return 0, true
	}
	return s.selectedMailbox.ID, true
}
