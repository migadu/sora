package imap

import (
	"slices"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
)

func TestApplyImplicitSeenUpdate(t *testing.T) {
	oldModSeq := int64(10)
	msg := db.Message{UID: 1, BitwiseFlags: db.FlagFlagged, CreatedModSeq: 5, UpdatedModSeq: &oldModSeq}

	// No result for the message: the update changed nothing (it was \Seen already).
	for _, results := range [][]db.BatchFlagUpdateResult{
		nil,
		{{UID: 2, Flags: []imap.Flag{imap.FlagSeen}, ModSeq: 20}},
		{{UID: 1, ModSeq: 20, PreconditionFailed: true}},
	} {
		if applyImplicitSeenUpdate(&msg, results) {
			t.Fatalf("applyImplicitSeenUpdate(%v) = true, want false", results)
		}
		if *msg.UpdatedModSeq != 10 || msg.BitwiseFlags != db.FlagFlagged {
			t.Fatalf("applyImplicitSeenUpdate(%v) changed the message: flags %d, modseq %d", results, msg.BitwiseFlags, *msg.UpdatedModSeq)
		}
	}

	if !applyImplicitSeenUpdate(&msg, []db.BatchFlagUpdateResult{
		{UID: 1, Flags: []imap.Flag{imap.FlagSeen, imap.FlagFlagged, "$Work"}, ModSeq: 21},
	}) {
		t.Fatal("applyImplicitSeenUpdate = false, want true")
	}
	if msg.UpdatedModSeq == nil || *msg.UpdatedModSeq != 21 {
		t.Fatalf("UpdatedModSeq = %v, want 21", msg.UpdatedModSeq)
	}
	if !db.ContainsFlag(msg.BitwiseFlags, db.FlagSeen) || !db.ContainsFlag(msg.BitwiseFlags, db.FlagFlagged) {
		t.Fatalf("BitwiseFlags = %d, want Seen|Flagged", msg.BitwiseFlags)
	}
	if !slices.Equal(msg.CustomFlags, []string{"$Work"}) {
		t.Fatalf("CustomFlags = %v, want [$Work]", msg.CustomFlags)
	}
}
