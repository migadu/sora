package imap

import (
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// testNameKey stands in for the database's LOWER(name) for the names of these
// tests. The tests of names where Go's case mapping and lower() part ways set
// the keys as the database computes them.
func testNameKey(name string) string {
	return strings.ToLower(name)
}

// keyedSnapshot gives each entry without a key its testNameKey.
func keyedSnapshot(snapshot map[int64]notifySnapshotEntry) map[int64]notifySnapshotEntry {
	for id, entry := range snapshot {
		if entry.key == "" {
			entry.key = testNameKey(entry.name)
			snapshot[id] = entry
		}
	}
	return snapshot
}

// newTestWatch builds the watch NOTIFY SET would install for items, the names
// they give keyed by testNameKey.
func newTestWatch(items ...imap.NotifyItem) *notifyWatch {
	watch := &notifyWatch{
		options:  &imap.NotifyOptions{Items: items},
		nameKeys: map[string]string{consts.MailboxInbox: testNameKey(consts.MailboxInbox)},
	}
	for i := range watch.options.Items {
		item := &watch.options.Items[i]
		if item.MailboxSpec == imap.NotifyMailboxSpecSelected ||
			item.MailboxSpec == imap.NotifyMailboxSpecSelectedDelayed {
			watch.selected = item
			watch.delayed = item.MailboxSpec == imap.NotifyMailboxSpecSelectedDelayed
		}
		for _, name := range item.Mailboxes {
			watch.nameKeys[name] = testNameKey(name)
		}
	}
	return watch
}

// TestNotifyEventsForMailboxMatchesKeys: the INBOXES, MAILBOXES and SUBTREE
// specifiers match mailboxes by key, LOWER(name) as the database computes it,
// never by a Go case mapping of the names (issue #1649). The keys are ICU's.
func TestNotifyEventsForMailboxMatchesKeys(t *testing.T) {
	events := []imap.NotifyEvent{imap.NotifyEventMessageNew}
	watch := func(item imap.NotifyItem, keys map[string]string) *notifyWatch {
		w := newTestWatch(item)
		w.nameKeys = keys
		return w
	}
	tests := []struct {
		name      string
		watch     *notifyWatch
		mailbox   string
		key       string
		wantMatch bool
	}{
		{
			// U+017F is lower case already: "ſx" and "sx" are two mailboxes
			// under every collation, which strings.EqualFold matched.
			name:    "MailboxesLongS",
			watch:   watch(imap.NotifyItem{Mailboxes: []string{"sx"}, Events: events}, map[string]string{"sx": "sx"}),
			mailbox: "ſx", key: "ſx",
		},
		{
			// U+212A KELVIN SIGN is three bytes; its key's "k" one.
			name:    "SubtreeKelvinSign",
			watch:   watch(imap.NotifyItem{Mailboxes: []string{"Kx"}, Subtree: true, Events: events}, map[string]string{"Kx": "kx"}),
			mailbox: "Kx/y", key: "kx/y", wantMatch: true,
		},
		{
			// ICU writes a word-final sigma "ς": "ΑΣ" is "ας".
			name:    "SubtreeFinalSigma",
			watch:   watch(imap.NotifyItem{Mailboxes: []string{"ας"}, Subtree: true, Events: events}, map[string]string{"ας": "ας"}),
			mailbox: "ΑΣ/y", key: "ας/y", wantMatch: true,
		},
		{
			// Under ICU "İNBOX" is a mailbox next to the INBOX.
			name:    "InboxesDottedCapitalI",
			watch:   watch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecInboxes, Events: events}, map[string]string{consts.MailboxInbox: "inbox"}),
			mailbox: "İNBOX", key: "i̇nbox",
		},
		{
			name:    "InboxesInbox",
			watch:   watch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecInboxes, Events: events}, map[string]string{consts.MailboxInbox: "inbox"}),
			mailbox: "INBOX", key: "inbox", wantMatch: true,
		},
		{
			// A name PostgreSQL cannot hold has the empty key and names no mailbox.
			name:    "UnstorableName",
			watch:   watch(imap.NotifyItem{Mailboxes: []string{"a\x00"}, Subtree: true, Events: events}, map[string]string{"a\x00": ""}),
			mailbox: "a", key: "a",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.watch.eventsForMailbox(tc.mailbox, tc.key, false, "")[imap.NotifyEventMessageNew]
			if got != tc.wantMatch {
				t.Errorf("eventsForMailbox(%q, key %q) matched %v, want %v", tc.mailbox, tc.key, got, tc.wantMatch)
			}
		})
	}
}

// TestDiffNotifySnapshotsKeysNames: the diff compares names by key, as the
// database does (issue #1649). The keys are ICU's, under which "İx" and "ix"
// are two mailboxes and "ΑΣ" and "ας" one.
func TestDiffNotifySnapshotsKeysNames(t *testing.T) {
	dotted := notifySnapshotEntry{name: "İx", key: "i̇x"}
	dottedChild := notifySnapshotEntry{name: "İx/a", key: "i̇x/a"}
	ix := notifySnapshotEntry{name: "ix", key: "ix"}

	t.Run("NoChildrenOfAnotherMailbox", func(t *testing.T) {
		events := diffNotifySnapshots(
			map[int64]notifySnapshotEntry{1: dotted, 2: dottedChild},
			map[int64]notifySnapshotEntry{1: dotted, 2: dottedChild, 3: ix})
		if len(events) != 1 || events[0].name != "ix" || events[0].hasChildren {
			t.Errorf("creating ix next to İx/a: %+v, want ix without children", events)
		}
	})

	t.Run("ParentIsTheMailboxOfItsKey", func(t *testing.T) {
		child := notifySnapshotEntry{name: "ix/c", key: "ix/c"}
		events := diffNotifySnapshots(
			map[int64]notifySnapshotEntry{1: ix, 2: dotted},
			map[int64]notifySnapshotEntry{1: ix, 2: dotted, 3: child})
		names := make(map[string]notifyTreeEvent)
		for _, ev := range events {
			names[ev.name] = ev
		}
		if len(events) != 2 || names["ix/c"].name == "" || !names["ix"].hasChildren || names["ix"].deleted {
			t.Errorf("creating ix/c next to İx: %+v, want ix/c and its parent ix with children", events)
		}
	})

	t.Run("RenameCarriesChildOfAnotherSpelling", func(t *testing.T) {
		// "ας/x" was created below "ΑΣ": RENAME ΑΣ New carries it along.
		events := diffNotifySnapshots(
			map[int64]notifySnapshotEntry{1: {name: "ΑΣ", key: "ας"}, 2: {name: "ας/x", key: "ας/x"}},
			map[int64]notifySnapshotEntry{1: {name: "New", key: "new"}, 2: {name: "New/x", key: "new/x"}})
		if len(events) != 1 || events[0].name != "New" || events[0].oldName != "ΑΣ" || !events[0].hasChildren {
			t.Errorf("RENAME ΑΣ New: %+v, want only New (OLDNAME ΑΣ) with children", events)
		}
	})
}

func TestNotifyEventsForMailbox(t *testing.T) {
	msgEvents := []imap.NotifyEvent{imap.NotifyEventMessageNew, imap.NotifyEventMessageExpunge}
	treeEvents := []imap.NotifyEvent{imap.NotifyEventMailboxName, imap.NotifyEventSubscriptionChange}

	tests := []struct {
		name       string
		watch      *notifyWatch
		mailbox    string
		subscribed bool
		sharedRoot string
		want       []imap.NotifyEvent
	}{
		{
			name:    "PersonalMatchesEverything",
			watch:   newTestWatch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecPersonal, Events: msgEvents}),
			mailbox: "Lists/Lemonade",
			want:    msgEvents,
		},
		{
			name:       "PersonalExcludesSharedNamespace",
			watch:      newTestWatch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecPersonal, Events: msgEvents}),
			mailbox:    "Shared/Team",
			sharedRoot: "Shared",
			want:       nil,
		},
		{
			name:    "InboxesMatchesOnlyInbox",
			watch:   newTestWatch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecInboxes, Events: msgEvents}),
			mailbox: "Archive",
			want:    nil,
		},
		{
			name:    "InboxesMatchesInboxCaseInsensitive",
			watch:   newTestWatch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecInboxes, Events: msgEvents}),
			mailbox: "inbox",
			want:    msgEvents,
		},
		{
			name:       "SubscribedRequiresSubscription",
			watch:      newTestWatch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecSubscribed, Events: msgEvents}),
			mailbox:    "Archive",
			subscribed: false,
			want:       nil,
		},
		{
			name:       "SubscribedMatchesSubscription",
			watch:      newTestWatch(imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecSubscribed, Events: msgEvents}),
			mailbox:    "Archive",
			subscribed: true,
			want:       msgEvents,
		},
		{
			name:    "MailboxesExactMatch",
			watch:   newTestWatch(imap.NotifyItem{Mailboxes: []string{"Archive"}, Events: msgEvents}),
			mailbox: "Archive",
			want:    msgEvents,
		},
		{
			name:    "MailboxesNoWildcardExpansion",
			watch:   newTestWatch(imap.NotifyItem{Mailboxes: []string{"Archive"}, Events: msgEvents}),
			mailbox: "Archive/2026",
			want:    nil,
		},
		{
			name:    "SubtreeMatchesChildren",
			watch:   newTestWatch(imap.NotifyItem{Mailboxes: []string{"Lists"}, Subtree: true, Events: msgEvents}),
			mailbox: "Lists/Lemonade/Dev",
			want:    msgEvents,
		},
		{
			name:    "SubtreeMatchesRootItself",
			watch:   newTestWatch(imap.NotifyItem{Mailboxes: []string{"Lists"}, Subtree: true, Events: msgEvents}),
			mailbox: "Lists",
			want:    msgEvents,
		},
		{
			name:    "SubtreeDoesNotMatchSiblingPrefix",
			watch:   newTestWatch(imap.NotifyItem{Mailboxes: []string{"Lists"}, Subtree: true, Events: msgEvents}),
			mailbox: "ListsArchive",
			want:    nil,
		},
		{
			name: "EventGroupsAccumulate",
			watch: newTestWatch(
				imap.NotifyItem{Mailboxes: []string{"INBOX"}, Events: msgEvents},
				imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecPersonal, Events: treeEvents},
			),
			mailbox: "INBOX",
			// RFC 5465 section 6: both groups apply, events are the union.
			want: append(append([]imap.NotifyEvent{}, msgEvents...), treeEvents...),
		},
		{
			name: "SelectedSpecifierNeverMatchesByName",
			watch: newTestWatch(
				imap.NotifyItem{MailboxSpec: imap.NotifyMailboxSpecSelected, Events: msgEvents},
			),
			mailbox: "INBOX",
			want:    nil,
		},
		{
			name:    "NoneEventGroupContributesNothing",
			watch:   newTestWatch(imap.NotifyItem{Mailboxes: []string{"Archive"}, Events: nil}),
			mailbox: "Archive",
			want:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events := tc.watch.eventsForMailbox(tc.mailbox, testNameKey(tc.mailbox), tc.subscribed, tc.sharedRoot)
			if len(events) != len(tc.want) {
				t.Fatalf("eventsForMailbox(%q) = %v, want %v", tc.mailbox, events, tc.want)
			}
			for _, ev := range tc.want {
				if !events[ev] {
					t.Errorf("eventsForMailbox(%q) is missing %v", tc.mailbox, ev)
				}
			}
		})
	}
}

func TestDiffNotifySnapshots(t *testing.T) {
	prev := map[int64]notifySnapshotEntry{
		1: {name: "INBOX", subscribed: true},
		2: {name: "Old", subscribed: false},
		3: {name: "Doomed", subscribed: false},
		4: {name: "Stable", subscribed: false},
	}
	cur := map[int64]notifySnapshotEntry{
		1: {name: "INBOX", subscribed: true},   // unchanged
		2: {name: "New", subscribed: false},    // renamed
		4: {name: "Stable", subscribed: true},  // subscription flip
		5: {name: "Created", subscribed: true}, // created
		// 3 deleted
	}

	events := diffNotifySnapshots(keyedSnapshot(prev), keyedSnapshot(cur))

	byName := make(map[string]notifyTreeEvent)
	for _, ev := range events {
		byName[ev.name] = ev
	}
	if len(events) != 4 {
		t.Fatalf("diffNotifySnapshots produced %d events (%v), want 4", len(events), byName)
	}

	if ev := byName["New"]; ev.event != imap.NotifyEventMailboxName || ev.oldName != "Old" || ev.deleted {
		t.Errorf("rename event wrong: %+v", ev)
	}
	if ev := byName["Doomed"]; ev.event != imap.NotifyEventMailboxName || !ev.deleted {
		t.Errorf("delete event wrong: %+v", ev)
	}
	if ev := byName["Created"]; ev.event != imap.NotifyEventMailboxName || ev.deleted || ev.oldName != "" {
		t.Errorf("create event wrong: %+v", ev)
	}
	if ev := byName["Stable"]; ev.event != imap.NotifyEventSubscriptionChange {
		t.Errorf("subscription event wrong: %+v", ev)
	}
}

// TestDiffNotifySnapshotsAffectedNames checks which names a diff reports for
// the mailboxes created, deleted and renamed in it. RFC 5465 section 5.4: "If
// a mailbox is created or deleted, the mailbox itself and its direct parent
// (whether it is an existing mailbox or not) are considered to be affected."
// and "When a mailbox is renamed, its children are renamed too. No additional
// MailboxName events are sent for children in this case."
func TestDiffNotifySnapshotsAffectedNames(t *testing.T) {
	// want describes one expected event: its type, whether it carries
	// \NonExistent, its OLDNAME, and whether the name has children after the
	// change (\HasChildren or \HasNoChildren).
	type want struct {
		event       imap.NotifyEvent
		deleted     bool
		oldName     string
		hasChildren bool
	}
	mailboxName := imap.NotifyEventMailboxName

	tests := []struct {
		name      string
		prev, cur map[int64]notifySnapshotEntry
		want      map[string]want
	}{
		{
			// The issue's RENAME Old Attic/Old: Attic is created by the
			// rename, Old/Kid and Old/Kid/Grand are carried along with Old.
			name: "RenameCarriesChildrenSilently",
			prev: map[int64]notifySnapshotEntry{
				1: {name: "Old"}, 2: {name: "Old/Kid"}, 3: {name: "Old/Kid/Grand"},
			},
			cur: map[int64]notifySnapshotEntry{
				1: {name: "Attic/Old"}, 2: {name: "Attic/Old/Kid"}, 3: {name: "Attic/Old/Kid/Grand"},
				4: {name: "Attic"},
			},
			want: map[string]want{
				"Attic":     {event: mailboxName, hasChildren: true},
				"Attic/Old": {event: mailboxName, oldName: "Old", hasChildren: true},
			},
		},
		{
			// The database renames a child by replacing as many characters
			// of its name as the old name of the renamed mailbox has, so a
			// child stored under a differently cased prefix is carried too.
			name: "RenameCarriesDifferentlyCasedChild",
			prev: map[int64]notifySnapshotEntry{1: {name: "Old"}, 2: {name: "OLD/Kid"}},
			cur:  map[int64]notifySnapshotEntry{1: {name: "New"}, 2: {name: "New/Kid"}},
			want: map[string]want{
				"New": {event: mailboxName, oldName: "Old", hasChildren: true},
			},
		},
		{
			// A child renamed on its own in the same diff is not a child the
			// parent's rename carried along.
			name: "ChildRenamedOnItsOwnIsReported",
			prev: map[int64]notifySnapshotEntry{1: {name: "Old"}, 2: {name: "Old/Mid"}, 3: {name: "Old/Mid/Kid"}},
			cur:  map[int64]notifySnapshotEntry{1: {name: "New"}, 2: {name: "Other"}, 3: {name: "Other/Kid"}},
			want: map[string]want{
				"New":   {event: mailboxName, oldName: "Old"},
				"Other": {event: mailboxName, oldName: "Old/Mid", hasChildren: true},
			},
		},
		{
			// A carried child whose subscription changed in the same diff
			// still gets its SubscriptionChange.
			name: "CarriedChildSubscriptionChange",
			prev: map[int64]notifySnapshotEntry{1: {name: "Old"}, 2: {name: "Old/Kid"}},
			cur:  map[int64]notifySnapshotEntry{1: {name: "New"}, 2: {name: "New/Kid", subscribed: true}},
			want: map[string]want{
				"New":     {event: mailboxName, oldName: "Old", hasChildren: true},
				"New/Kid": {event: imap.NotifyEventSubscriptionChange},
			},
		},
		{
			// The issue's CREATE Parent/Child.
			name: "CreateReportsExistingParent",
			prev: map[int64]notifySnapshotEntry{1: {name: "Parent"}},
			cur:  map[int64]notifySnapshotEntry{1: {name: "Parent"}, 2: {name: "Parent/Child"}},
			want: map[string]want{
				"Parent/Child": {event: mailboxName},
				"Parent":       {event: mailboxName, hasChildren: true},
			},
		},
		{
			name: "DeleteReportsExistingParent",
			prev: map[int64]notifySnapshotEntry{1: {name: "Parent"}, 2: {name: "Parent/Child"}},
			cur:  map[int64]notifySnapshotEntry{1: {name: "Parent"}},
			want: map[string]want{
				"Parent/Child": {event: mailboxName, deleted: true},
				"Parent":       {event: mailboxName},
			},
		},
		{
			// A parent the client cannot see (no RFC 4314 'l' right) is
			// still affected, and carries \NonExistent.
			name: "CreateReportsInaccessibleParentNonExistent",
			prev: map[int64]notifySnapshotEntry{},
			cur:  map[int64]notifySnapshotEntry{2: {name: "Hidden/Child"}},
			want: map[string]want{
				"Hidden/Child": {event: mailboxName},
				"Hidden":       {event: mailboxName, deleted: true, hasChildren: true},
			},
		},
		{
			name: "ParentReportedOncePerDiff",
			prev: map[int64]notifySnapshotEntry{1: {name: "Parent", subscribed: true}, 2: {name: "Parent/Gone"}},
			cur: map[int64]notifySnapshotEntry{
				1: {name: "Parent", subscribed: true}, 3: {name: "Parent/A"}, 4: {name: "Parent/B"},
			},
			want: map[string]want{
				"Parent/Gone": {event: mailboxName, deleted: true},
				"Parent/A":    {event: mailboxName},
				"Parent/B":    {event: mailboxName},
				"Parent":      {event: mailboxName, hasChildren: true},
			},
		},
		{
			// CREATE a/b/c creating its superiors: each parent is reported
			// once, by its own creation.
			name: "ParentCreatedInSameDiffNotRepeated",
			prev: map[int64]notifySnapshotEntry{},
			cur:  map[int64]notifySnapshotEntry{1: {name: "a"}, 2: {name: "a/b"}, 3: {name: "a/b/c"}},
			want: map[string]want{
				"a":     {event: mailboxName, hasChildren: true},
				"a/b":   {event: mailboxName, hasChildren: true},
				"a/b/c": {event: mailboxName},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events := diffNotifySnapshots(keyedSnapshot(tc.prev), keyedSnapshot(tc.cur))
			got := make(map[string]want, len(events))
			for _, ev := range events {
				if _, dup := got[ev.name]; dup {
					t.Errorf("%q reported more than once: %+v", ev.name, events)
				}
				got[ev.name] = want{event: ev.event, deleted: ev.deleted, oldName: ev.oldName, hasChildren: ev.hasChildren}
			}
			for name, w := range tc.want {
				g, ok := got[name]
				if !ok {
					t.Errorf("no event for %q, want %+v (got %+v)", name, w, got)
					continue
				}
				if g != w {
					t.Errorf("event for %q = %+v, want %+v", name, g, w)
				}
			}
			for name, g := range got {
				if _, ok := tc.want[name]; !ok {
					t.Errorf("unexpected event for %q: %+v", name, g)
				}
			}
		})
	}
}

func TestNotifyStatusOptions(t *testing.T) {
	messageNew := map[imap.NotifyEvent]bool{imap.NotifyEventMessageNew: true, imap.NotifyEventMessageExpunge: true}
	flagChange := map[imap.NotifyEvent]bool{imap.NotifyEventFlagChange: true}
	treeOnly := map[imap.NotifyEvent]bool{imap.NotifyEventMailboxName: true}

	if opts := notifyStatusOptions(treeOnly, false); opts != nil {
		t.Errorf("tree-only events must not produce STATUS, got %+v", opts)
	}
	if opts := notifyStatusOptions(nil, true); opts != nil {
		t.Errorf("no events must not produce STATUS, got %+v", opts)
	}

	opts := notifyStatusOptions(messageNew, false)
	if opts == nil || !opts.NumMessages || !opts.UIDNext || !opts.UIDValidity {
		t.Errorf("MessageNew/MessageExpunge STATUS items wrong: %+v", opts)
	}
	if opts.HighestModSeq {
		t.Errorf("HIGHESTMODSEQ must not be sent to a non-CONDSTORE client: %+v", opts)
	}

	opts = notifyStatusOptions(messageNew, true)
	if opts == nil || !opts.HighestModSeq {
		t.Errorf("HIGHESTMODSEQ expected for CONDSTORE-aware clients: %+v", opts)
	}

	opts = notifyStatusOptions(flagChange, false)
	if opts == nil || !opts.UIDValidity || !opts.NumUnseen || opts.HighestModSeq {
		t.Errorf("FlagChange STATUS items without CONDSTORE wrong: %+v", opts)
	}
	opts = notifyStatusOptions(flagChange, true)
	if opts == nil || !opts.UIDValidity || !opts.HighestModSeq {
		t.Errorf("FlagChange STATUS items with CONDSTORE wrong: %+v", opts)
	}
}

// TestNotifyStatusDataHighestModSeq: a mailbox that has never held a message
// has no mailbox_stats row, so its stats row carries highest_modseq 0. NOTIFY
// must still report HIGHESTMODSEQ 1 for it, as STATUS, LIST-STATUS and SELECT
// do: 0 is reserved for a mailbox without persistent mod-sequences (RFC 7162
// section 7, status-att-val), and a client that sends it back as CHANGEDSINCE
// or a QRESYNC parameter gets BAD (those take a mod-sequence-value, >= 1).
func TestNotifyStatusDataHighestModSeq(t *testing.T) {
	options := &imap.StatusOptions{NumMessages: true, UIDNext: true, UIDValidity: true, HighestModSeq: true}

	empty := notifyStatusData("Empty", 42, db.MailboxStatsRow{MailboxID: 1}, options)
	if empty.HighestModSeq != 1 {
		t.Errorf("empty mailbox: HIGHESTMODSEQ = %d, want 1", empty.HighestModSeq)
	}
	if empty.NumMessages == nil || *empty.NumMessages != 0 || empty.UIDNext != 1 || empty.UIDValidity != 42 {
		t.Errorf("empty mailbox: unexpected STATUS data %+v", empty)
	}

	busy := notifyStatusData("INBOX", 42, db.MailboxStatsRow{MailboxID: 2, HighestModSeq: 917, MessageCount: 3, HighestUID: 5}, options)
	if busy.HighestModSeq != 917 {
		t.Errorf("non-empty mailbox: HIGHESTMODSEQ = %d, want 917", busy.HighestModSeq)
	}

	noModSeq := notifyStatusData("Empty", 42, db.MailboxStatsRow{MailboxID: 1}, &imap.StatusOptions{NumMessages: true})
	if noModSeq.HighestModSeq != 0 {
		t.Errorf("HIGHESTMODSEQ not requested: got %d, want it omitted (0)", noModSeq.HighestModSeq)
	}
}

func TestMailboxNameHasPrefix(t *testing.T) {
	tests := []struct {
		name, root string
		want       bool
	}{
		{"Lists/Lemonade", "Lists", true},
		{"lists/lemonade", "Lists", true},
		{"Lists", "Lists", false},        // the root itself is not "under" the root
		{"ListsArchive", "Lists", false}, // sibling sharing a name prefix
		{"Li", "Lists", false},
		{"Lists/", "Lists", false}, // no child name after the delimiter
	}
	for _, tc := range tests {
		if got := mailboxNameHasPrefix(tc.name, tc.root); got != tc.want {
			t.Errorf("mailboxNameHasPrefix(%q, %q) = %v, want %v", tc.name, tc.root, got, tc.want)
		}
	}
}

func TestUIDRangeExcept(t *testing.T) {
	set := func(ranges ...imap.UIDRange) imap.UIDSet {
		var s imap.UIDSet
		for _, r := range ranges {
			s.AddRange(r.Start, r.Stop)
		}
		return s
	}
	tests := []struct {
		name        string
		first, last imap.UID
		except      imap.UIDSet
		want        string
	}{
		{"nothing excepted", 5, 9, nil, "5:9"},
		{"all excepted", 5, 9, set(imap.UIDRange{Start: 1, Stop: 20}), ""},
		{"exactly the range", 5, 9, set(imap.UIDRange{Start: 5, Stop: 9}), ""},
		{"head", 5, 9, set(imap.UIDRange{Start: 3, Stop: 6}), "7:9"},
		{"tail", 5, 9, set(imap.UIDRange{Start: 8, Stop: 12}), "5:7"},
		{"middle", 5, 9, set(imap.UIDRange{Start: 7, Stop: 7}), "5:6,8:9"},
		{"several", 1, 10, set(imap.UIDRange{Start: 2, Stop: 3}, imap.UIDRange{Start: 6, Stop: 6}, imap.UIDRange{Start: 10, Stop: 11}), "1,4:5,7:9"},
		{"outside", 5, 9, set(imap.UIDRange{Start: 1, Stop: 4}, imap.UIDRange{Start: 10, Stop: 12}), "5:9"},
		{"single UID excepted", 5, 5, set(imap.UIDRange{Start: 5, Stop: 5}), ""},
		{"top UID", 4294967294, 4294967295, set(imap.UIDRange{Start: 4294967295, Stop: 4294967295}), "4294967294"},
	}
	for _, tc := range tests {
		if got := uidRangeExcept(tc.first, tc.last, tc.except).String(); got != tc.want {
			t.Errorf("%s: uidRangeExcept(%d, %d, %v) = %q, want %q", tc.name, tc.first, tc.last, tc.except, got, tc.want)
		}
	}
}

// TestOwnMessages: the pump sees the own UIDs of the mailbox it treats as
// selected from nextFetchUID on, forgets the rest, and holds back while an own
// write is in flight.
func TestOwnMessages(t *testing.T) {
	s := &IMAPSession{}
	watch := &notifyWatch{selectedMailboxID: 7, nextFetchUID: 5}
	watch.own.mailboxID = 7
	watch.own.uids.AddNum(2, 3, 5, 9)

	uids, busy := s.ownMessages(watch)
	if got := uids.String(); got != "5,9" || busy {
		t.Fatalf("ownMessages = %q, busy %v; want \"5,9\", not busy", got, busy)
	}
	if got := watch.own.uids.String(); got != "5,9" {
		t.Errorf("after ownMessages the watch keeps %q, want the passed UIDs forgotten: \"5,9\"", got)
	}

	watch.own.writes = 1
	if _, busy := s.ownMessages(watch); !busy {
		t.Error("ownMessages with an own write in flight: busy = false, want true")
	}
	watch.own.writes = 0

	watch.selectedMailboxID = 8 // the client selected another mailbox
	if uids, _ := s.ownMessages(watch); len(uids) != 0 || watch.own.mailboxID != 8 {
		t.Errorf("after a mailbox switch ownMessages = %q for mailbox %d, want none for mailbox 8", uids.String(), watch.own.mailboxID)
	}
}
