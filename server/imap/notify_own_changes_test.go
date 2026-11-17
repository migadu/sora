package imap

import (
	"context"
	"slices"
	"testing"

	"github.com/migadu/sora/db"
)

func TestNotifyOwnRenamedNonOwnerSubscription(t *testing.T) {
	base := func() map[int64]notifySnapshotEntry {
		return testSnapshotKeys(map[int64]notifySnapshotEntry{
			1: {name: "Shared/Team/Old", subscribed: true},
			2: {name: "Shared/Team/Old/Kid", subscribed: true},
			3: {name: "Shared/Team/GhostSrc", subscribed: false},
		})
	}

	t.Run("non-owner rename drops unmoved subscription and adopts destination ghost subscription", func(t *testing.T) {
		watch := &notifyWatch{snapshot: base(), knownSubscriptions: map[string]bool{"shared/team/old": true, "shared/team/old/kid": true, "shared/team/ghostdst": true}}
		watch.ownRenamed([]db.MailboxNameMutation{
			{
				ID: 1, BeforeName: "Shared/Team/Old", BeforeKey: "shared/team/old",
				AfterName: "Shared/Team/New", AfterKey: "shared/team/new",
				SubscribedSet: true,
			},
			{
				ID: 2, BeforeName: "Shared/Team/Old/Kid", BeforeKey: "shared/team/old/kid",
				AfterName: "Shared/Team/New/Kid", AfterKey: "shared/team/new/kid",
				SubscribedSet: true,
			},
			{
				ID: 3, BeforeName: "Shared/Team/GhostSrc", BeforeKey: "shared/team/ghostsrc",
				AfterName: "Shared/Team/GhostDst", AfterKey: "shared/team/ghostdst",
				SubscribedSet: true,
			},
		})
		cur := testSnapshotKeys(map[int64]notifySnapshotEntry{
			1: {name: "Shared/Team/New", subscribed: false},
			2: {name: "Shared/Team/New/Kid", subscribed: false},
			3: {name: "Shared/Team/GhostDst", subscribed: true},
		})
		if got := treeEventStrings(diffNotifySnapshots(watch.snapshot, cur)); len(got) != 0 {
			t.Fatalf("diffNotifySnapshots after non-owner ownRenamed = %q, want none", got)
		}

		// A subsequent foreign SUBSCRIBE on Shared/Team/New is still reported.
		cur[1] = notifySnapshotEntry{name: "Shared/Team/New", key: "shared/team/new", subscribed: true}
		if got := treeEventStrings(diffNotifySnapshots(watch.snapshot, cur)); !slices.Equal(got, []string{"Shared/Team/New sub=true"}) {
			t.Fatalf("foreign SUBSCRIBE after non-owner rename = %q, want [Shared/Team/New sub=true]", got)
		}
	})
}

func TestChainModSeqWindowInterleavings(t *testing.T) {
	t.Run("contiguous strips extend parent window", func(t *testing.T) {
		parent := &db.ModSeqWindow{MailboxID: 7, Before: 10, After: 12, Measured: true}
		ctx := db.WithModSeqWindow(context.Background(), parent)

		_, chain1 := db.ChainModSeqWindow(ctx, 7)
		// Simulate unmeasured no-op strip first (e.g. flag already absent): parent stays [10, 12].
		chain1()
		if parent.Before != 10 || parent.After != 12 {
			t.Fatalf("after unmeasured strip: parent = [%d, %d], want [10, 12]", parent.Before, parent.After)
		}

		parent.Chain(&db.ModSeqWindow{MailboxID: 7, Before: 12, After: 14, Measured: true})
		parent.Chain(&db.ModSeqWindow{MailboxID: 7, Before: 14, After: 15, Measured: true})
		if parent.Before != 10 || parent.After != 15 {
			t.Fatalf("after contiguous strips: parent = [%d, %d], want [10, 15]", parent.Before, parent.After)
		}

		s := &IMAPSession{}
		watch := &notifyWatch{statusMarks: map[int64]uint64{7: 10}}
		watch.ownStatus.record(parent, 1)
		changes := s.withoutOwnStatusChanges(watch, []notifyStatusChange{{
			row:  db.MailboxStatsRow{MailboxID: 7, HighestModSeq: 15},
			from: 10,
		}})
		if len(changes) != 0 || watch.statusMarks[7] != 15 {
			t.Fatalf("contiguous copy+strip reported = %d (mark %d), want 0 (mark 15)", len(changes), watch.statusMarks[7])
		}
	})

	t.Run("interleaved foreign write between copy and strip stays unchained and reported", func(t *testing.T) {
		parent := &db.ModSeqWindow{MailboxID: 7, Before: 10, After: 12, Measured: true}
		// Foreign write advances mailbox 7 from 12 to 15 before strip #1 runs [15, 16] and strip #2 runs [16, 17].
		parent.Chain(&db.ModSeqWindow{MailboxID: 7, Before: 15, After: 16, Measured: true})
		parent.Chain(&db.ModSeqWindow{MailboxID: 7, Before: 16, After: 17, Measured: true})
		if parent.Before != 10 || parent.After != 12 {
			t.Fatalf("interleaved foreign write must leave parent unchained at [10, 12], got [%d, %d]", parent.Before, parent.After)
		}

		s := &IMAPSession{}
		watch := &notifyWatch{statusMarks: map[int64]uint64{7: 10}}
		watch.ownStatus.record(parent, 1)
		changes := s.withoutOwnStatusChanges(watch, []notifyStatusChange{{
			row:  db.MailboxStatsRow{MailboxID: 7, HighestModSeq: 17},
			from: 10,
		}})
		if len(changes) != 1 {
			t.Fatalf("interleaved foreign write must still be reported, got %d changes", len(changes))
		}
	})
}
