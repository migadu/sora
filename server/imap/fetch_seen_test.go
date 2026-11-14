package imap

import (
	"slices"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
)

func TestApplyImplicitSeenUpdates(t *testing.T) {
	oldModSeq := int64(10)
	msgs := []db.Message{
		{UID: 1, BitwiseFlags: 0, CreatedModSeq: 5, UpdatedModSeq: &oldModSeq},
		{UID: 2, BitwiseFlags: db.FlagSeen, CreatedModSeq: 6},
		{UID: 3, BitwiseFlags: db.FlagFlagged, CreatedModSeq: 7},
	}

	unseen := unseenMessageUIDs(msgs)
	if !slices.Equal(unseen, []imap.UID{1, 3}) {
		t.Fatalf("unseenMessageUIDs = %v, want [1 3]", unseen)
	}

	changed := applyImplicitSeenUpdates(msgs, []db.BatchFlagUpdateResult{
		{UID: 1, Flags: []imap.Flag{imap.FlagSeen, "$Work"}, ModSeq: 21},
		{UID: 3, Flags: []imap.Flag{imap.FlagSeen, imap.FlagFlagged}, ModSeq: 22},
	})

	if !changed[1] || changed[2] || !changed[3] {
		t.Fatalf("changed = %v, want {1:true, 3:true}", changed)
	}
	if msgs[0].UpdatedModSeq == nil || *msgs[0].UpdatedModSeq != 21 {
		t.Fatalf("msg 1 UpdatedModSeq = %v, want 21", msgs[0].UpdatedModSeq)
	}
	if !db.ContainsFlag(msgs[0].BitwiseFlags, db.FlagSeen) || !slices.Equal(msgs[0].CustomFlags, []string{"$Work"}) {
		t.Fatalf("msg 1 flags = (%d, %v), want Seen + [$Work]", msgs[0].BitwiseFlags, msgs[0].CustomFlags)
	}
	if msgs[2].UpdatedModSeq == nil || *msgs[2].UpdatedModSeq != 22 {
		t.Fatalf("msg 3 UpdatedModSeq = %v, want 22", msgs[2].UpdatedModSeq)
	}
	if !db.ContainsFlag(msgs[2].BitwiseFlags, db.FlagSeen) || !db.ContainsFlag(msgs[2].BitwiseFlags, db.FlagFlagged) {
		t.Fatalf("msg 3 BitwiseFlags = %d, want Seen|Flagged", msgs[2].BitwiseFlags)
	}
}
