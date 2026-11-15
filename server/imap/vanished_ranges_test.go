package imap

import (
	"reflect"
	"testing"

	"github.com/migadu/go-imap"
)

// TestConvertUIDsToRanges: VANISHED for a long run of consecutive UIDs is one range,
// and the result must not reserve room for half the input (#1354): it allocated
// len(uids)/2+1 ranges whatever the result.
func TestConvertUIDsToRanges(t *testing.T) {
	got := convertUIDsToRanges([]imap.UID{1, 2, 3, 5, 7, 8})
	want := imap.UIDSet{{Start: 1, Stop: 3}, {Start: 5, Stop: 5}, {Start: 7, Stop: 8}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("convertUIDsToRanges(1 2 3 5 7 8) = %v, want %v", got, want)
	}

	uids := make([]imap.UID, 0, 1_000_000)
	for uid := imap.UID(2); len(uids) < cap(uids); uid++ {
		uids = append(uids, uid)
	}
	got = convertUIDsToRanges(uids)
	want = imap.UIDSet{{Start: 2, Stop: 1_000_001}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("convertUIDsToRanges(2..1000001) = %v, want %v", got, want)
	}
	if cap(got) != len(got) {
		t.Errorf("convertUIDsToRanges(2..1000001) reserved %d ranges for %d", cap(got), len(got))
	}
}
