package imap

import (
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
)

// The table of sora #117: messages with UIDs 1, 2, 3 and mod-sequences 2, 5, 4,
// so the middle one has the highest. Message 2 reaches 5 by a flag change.
func TestReturnedModSeq(t *testing.T) {
	five := int64(5)
	msg := map[int]db.SearchMessageResult{
		1: {UID: 1, CreatedModSeq: 2},
		2: {UID: 2, CreatedModSeq: 3, UpdatedModSeq: &five},
		3: {UID: 3, CreatedModSeq: 4},
	}
	// The orders Search, Sort ascending and Sort descending see, with the index of
	// the MIN and MAX message in each.
	search, minS, maxS := []db.SearchMessageResult{msg[3], msg[2], msg[1]}, 2, 0
	asc, minA, maxA := []db.SearchMessageResult{msg[1], msg[2], msg[3]}, 0, 2
	desc, minD, maxD := []db.SearchMessageResult{msg[3], msg[2], msg[1]}, 0, 2

	for _, tc := range []struct {
		name                   string
		options                *imap.SearchOptions
		search, sortAsc, sortD uint64
	}{
		{"plain", nil, 5, 5, 5},
		{"ALL", &imap.SearchOptions{ReturnAll: true}, 5, 5, 5},
		{"MIN", &imap.SearchOptions{ReturnMin: true}, 2, 2, 4},
		{"MAX", &imap.SearchOptions{ReturnMax: true}, 4, 4, 2},
		{"MIN MAX", &imap.SearchOptions{ReturnMin: true, ReturnMax: true}, 4, 4, 4},
		{"COUNT", &imap.SearchOptions{ReturnCount: true}, 5, 5, 5},
		{"MIN COUNT", &imap.SearchOptions{ReturnMin: true, ReturnCount: true}, 5, 5, 5},
		{"MAX COUNT", &imap.SearchOptions{ReturnMax: true, ReturnCount: true}, 5, 5, 5},
		{"MIN ALL", &imap.SearchOptions{ReturnMin: true, ReturnAll: true}, 5, 5, 5},
		{"MAX ALL", &imap.SearchOptions{ReturnMax: true, ReturnAll: true}, 5, 5, 5},
		{"SAVE only", &imap.SearchOptions{ReturnSave: true}, 5, 5, 5},
	} {
		if got := returnedModSeq(search, minS, maxS, tc.options); got != tc.search {
			t.Errorf("%s: SEARCH MODSEQ %d, want %d", tc.name, got, tc.search)
		}
		if got := returnedModSeq(asc, minA, maxA, tc.options); got != tc.sortAsc {
			t.Errorf("%s: SORT ascending MODSEQ %d, want %d", tc.name, got, tc.sortAsc)
		}
		if got := returnedModSeq(desc, minD, maxD, tc.options); got != tc.sortD {
			t.Errorf("%s: SORT descending MODSEQ %d, want %d", tc.name, got, tc.sortD)
		}
	}

	// UIDs 1 and 3 only: the highest of those returned, not of the mailbox.
	subset := []db.SearchMessageResult{msg[3], msg[1]}
	for _, options := range []*imap.SearchOptions{nil, {ReturnAll: true}, {ReturnCount: true}} {
		if got := returnedModSeq(subset, 1, 0, options); got != 4 {
			t.Errorf("subset %+v: MODSEQ %d, want 4", options, got)
		}
	}

	for _, options := range []*imap.SearchOptions{nil, {ReturnMin: true}, {ReturnMin: true, ReturnMax: true}} {
		if got := returnedModSeq(nil, -1, 0, options); got != 0 {
			t.Errorf("empty result %+v: MODSEQ %d, want 0", options, got)
		}
	}
}

// A message's mod-sequence is the highest of its creation, flag change and
// expunge, as FETCH MODSEQ reports it.
func TestMessageModSeq(t *testing.T) {
	updated, expunged := int64(7), int64(9)
	for _, tc := range []struct {
		msg  db.SearchMessageResult
		want uint64
	}{
		{db.SearchMessageResult{CreatedModSeq: 3}, 3},
		{db.SearchMessageResult{CreatedModSeq: 3, UpdatedModSeq: &updated}, 7},
		{db.SearchMessageResult{CreatedModSeq: 3, UpdatedModSeq: &updated, ExpungedModSeq: &expunged}, 9},
		{db.SearchMessageResult{CreatedModSeq: 8, UpdatedModSeq: &updated}, 8},
	} {
		if got := messageModSeq(&tc.msg); got != tc.want {
			t.Errorf("messageModSeq(%+v) = %d, want %d", tc.msg, got, tc.want)
		}
	}
}
