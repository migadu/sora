package imap

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
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
const notifyMaxChangedMailboxes = 100

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
// the pointer swap itself, which is guarded by IMAPSession.notifyMutex.
type notifyWatch struct {
	options *imap.NotifyOptions

	// selected is the SELECTED/SELECTED-DELAYED item, if any; delayed
	// distinguishes the two.
	selected *imap.NotifyItem
	delayed  bool

	// accountModSeq is the monotonic fan-in cursor over the account's
	// mailbox_stats. Comparable across mailboxes because modseqs come from
	// the global messages_modseq sequence.
	accountModSeq uint64

	// snapshot is the previous tick's view of the account's mailboxes,
	// diffed to detect MailboxName and SubscriptionChange events.
	snapshot map[int64]notifySnapshotEntry

	// selectedMailboxID / nextFetchUID track MessageNew fetch-atts delivery
	// for the selected mailbox: messages with UID >= nextFetchUID have not
	// been announced with a FETCH response yet. selectedMailboxID detects
	// mailbox switches so the high-water mark is rebound.
	selectedMailboxID int64
	nextFetchUID      imap.UID
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
		data.HighestModSeq = row.HighestModSeq
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

	selectedID := s.currentSelectedMailboxID()
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
		sharedRoot := s.sharedNamespaceRoot()
		for _, row := range rows {
			if row.HighestModSeq > watch.accountModSeq {
				watch.accountModSeq = row.HighestModSeq
			}
			if row.MailboxID == selectedID {
				watch.nextFetchUID = imap.UID(row.HighestUID + 1)
				continue
			}
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

	selectedID := s.currentSelectedMailboxID()
	if selectedID != watch.selectedMailboxID {
		// The client selected another mailbox: rebind the MessageNew
		// fetch-atts high-water mark so only messages arriving from now on
		// are announced with a FETCH.
		watch.selectedMailboxID = selectedID
		watch.nextFetchUID = 0
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
	// protection, CONDSTORE handling). SELECTED-DELAYED defers expunges to
	// the next command sync point (RFC 5465 §6.1.2); plain SELECTED delivers
	// immediately unless an expunge-unsafe command is in progress.
	if selectedID != 0 && watch.hasSelectedMessageEvents() {
		allowExpunge := !watch.delayed && w.ExpungeAllowed()
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
		}
	}

	if !watch.wantsNonSelectedItems() && (watch.selected == nil || watch.selected.MessageNewFetch == nil) {
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

		if watch.wantsTreeEvents() {
			if err := s.notifyDiffSnapshots(watch, snapshot, sharedRoot, w); err != nil {
				return false, err
			}
		}
		watch.snapshot = snapshot
	}

	// Fan-in: one mailbox_stats poll over the matched set detects message
	// events in non-selected mailboxes; the selected mailbox rides along for
	// the fetch-atts high-water mark.
	pollIDs := matchedIDs
	if selectedID != 0 && watch.selected != nil && watch.selected.MessageNewFetch != nil {
		pollIDs = append(append([]int64{}, matchedIDs...), selectedID)
	}
	if len(pollIDs) == 0 {
		return false, nil
	}
	rows, err := s.server.rdb.PollMailboxStatsWithRetry(readCtx, pollIDs, watch.accountModSeq)
	if err != nil {
		s.WarnLog("NOTIFY: mailbox stats poll failed", "error", err)
		return false, nil
	}

	if len(rows) > notifyMaxChangedMailboxes {
		// RFC 5465 §5.8: tell the client and behave as if NOTIFY NONE was
		// received. The library treats NotifyPoll returning as the pump
		// ending; the watch state is cleared here.
		s.WarnLog("NOTIFY: notification overflow, dropping watch", "changed_mailboxes", len(rows))
		metrics.IMAPNotifyOverflows.Inc()
		s.notifyMutex.Lock()
		s.notifyWatch = nil
		s.notifyMutex.Unlock()
		return true, w.WriteNotificationOverflow()
	}

	condStore := w.CondStoreEnabled()
	for _, row := range rows {
		if row.HighestModSeq > watch.accountModSeq {
			watch.accountModSeq = row.HighestModSeq
		}

		if row.MailboxID == selectedID {
			if err := s.notifyFetchNewMessages(ctx, watch, row, w); err != nil {
				return false, err
			}
			continue
		}

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
// the snapshot plus the IDs of non-selected mailboxes with message events
// enabled (the fan-in set). GetMailboxes already enforces RFC 4314 lookup
// rights on shared mailboxes, satisfying RFC 5465 §3.1's access requirement.
func (s *IMAPSession) notifySnapshotAndMatches(ctx context.Context, watch *notifyWatch, selectedID int64) (map[int64]notifySnapshotEntry, []int64, error) {
	mboxes, err := s.server.rdb.GetMailboxesWithRetry(ctx, s.AccountID(), false)
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
		if events[imap.NotifyEventMessageNew] || events[imap.NotifyEventMessageExpunge] || events[imap.NotifyEventFlagChange] {
			matchedIDs = append(matchedIDs, m.ID)
		}
	}
	return snapshot, matchedIDs, nil
}

// notifyTreeEvent is one detected mailbox-tree change.
type notifyTreeEvent struct {
	event   imap.NotifyEvent // MailboxName or SubscriptionChange
	name    string
	oldName string // for renames
	deleted bool
	entry   notifySnapshotEntry
}

// diffNotifySnapshots compares two account snapshots and returns the
// mailbox-tree changes between them: creations, deletions, renames (same ID,
// new name) and subscription flips.
func diffNotifySnapshots(prev, cur map[int64]notifySnapshotEntry) []notifyTreeEvent {
	var events []notifyTreeEvent
	for id, entry := range cur {
		old, existed := prev[id]
		switch {
		case !existed:
			events = append(events, notifyTreeEvent{event: imap.NotifyEventMailboxName, name: entry.name, entry: entry})
		case old.name != entry.name:
			events = append(events, notifyTreeEvent{event: imap.NotifyEventMailboxName, name: entry.name, oldName: old.name, entry: entry})
		case old.subscribed != entry.subscribed:
			events = append(events, notifyTreeEvent{event: imap.NotifyEventSubscriptionChange, name: entry.name, entry: entry})
		}
	}
	for id, old := range prev {
		if _, exists := cur[id]; !exists {
			events = append(events, notifyTreeEvent{event: imap.NotifyEventMailboxName, name: old.name, deleted: true, entry: old})
		}
	}
	return events
}

// notifyDiffSnapshots emits LIST responses for mailbox-tree changes since the
// previous tick (RFC 5465 §5.4, §5.5). The first tick after SetNotify diffs
// against the bootstrap snapshot, so only changes after NOTIFY SET are
// reported.
func (s *IMAPSession) notifyDiffSnapshots(watch *notifyWatch, cur map[int64]notifySnapshotEntry, sharedRoot string, w *imapserver.UpdateWriter) error {
	for _, ev := range diffNotifySnapshots(watch.snapshot, cur) {
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
				// writer includes it only for IMAP4rev2-enabled clients).
				data.OldName = ev.oldName
			}
			if ev.entry.subscribed {
				// §5.5: \Subscribed if and only if subscribed after the event.
				data.Attrs = append(data.Attrs, imap.MailboxAttrSubscribed)
			}
		}
		if err := w.WriteList(data); err != nil {
			return err
		}
		metrics.IMAPNotifyEventsSent.WithLabelValues("list").Inc()
	}
	return nil
}

// notifyFetchNewMessages honors the MessageNew fetch-atts of the selected
// mailbox (RFC 5465 §5.2): after the poll pipeline announced new messages
// with EXISTS, send a FETCH response with the requested items for each new
// UID, through the regular FETCH machinery.
func (s *IMAPSession) notifyFetchNewMessages(ctx context.Context, watch *notifyWatch, row db.MailboxStatsRow, w *imapserver.UpdateWriter) error {
	if watch.selected == nil || watch.selected.MessageNewFetch == nil || !watch.hasSelectedMessageEvents() {
		return nil
	}
	if watch.nextFetchUID == 0 {
		// High-water mark not initialized (bootstrap or rebind failure):
		// initialize from this row and skip, so history is not replayed.
		watch.nextFetchUID = imap.UID(row.HighestUID + 1)
		return nil
	}
	if imap.UID(row.HighestUID) < watch.nextFetchUID {
		return nil
	}

	var uidSet imap.UIDSet
	uidSet.AddRange(watch.nextFetchUID, imap.UID(row.HighestUID))

	// Advance before writing: a delivery failure tears the connection down,
	// and this avoids duplicate FETCHes on partial failure.
	watch.nextFetchUID = imap.UID(row.HighestUID + 1)

	options := *watch.selected.MessageNewFetch
	options.UID = true
	if err := s.Fetch(ctx, w.FetchWriter(), uidSet, &options); err != nil {
		s.WarnLog("NOTIFY: MessageNew fetch failed", "error", err)
		return nil
	}
	metrics.IMAPNotifyEventsSent.WithLabelValues("fetch").Inc()
	return nil
}

// currentSelectedMailboxID reads the selected mailbox ID under the session
// lock (0 when nothing is selected).
func (s *IMAPSession) currentSelectedMailboxID() int64 {
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(s.ctx)
	if !acquired {
		return 0
	}
	defer release()
	if s.selectedMailbox == nil {
		return 0
	}
	return s.selectedMailbox.ID
}
