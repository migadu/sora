package imap

import (
	"reflect"
	"strconv"
	"strings"
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

// TestKnownUIDsGaps: the VANISHED (EARLIER) answer for a QRESYNC known-uids is every
// UID of the set below UIDNEXT that is not active, as ranges (#1354).
func TestKnownUIDsGaps(t *testing.T) {
	num := func(s string) imap.UID {
		t.Helper()
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return imap.UID(n)
	}
	set := func(s string) imap.UIDSet {
		t.Helper()
		if s == "" {
			return nil
		}
		var uids imap.UIDSet
		for _, r := range strings.Split(s, ",") {
			start, stop, ok := strings.Cut(r, ":")
			if !ok {
				stop = start
			}
			uids = append(uids, imap.UIDRange{Start: num(start), Stop: num(stop)})
		}
		return uids
	}
	for _, tc := range []struct {
		known   string
		active  []imap.UID
		uidNext imap.UID
		want    string
	}{
		{"1:10", nil, 11, "1:10"},
		{"1:10", []imap.UID{1, 10}, 11, "2:9"},
		{"1:10", []imap.UID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 11, ""},
		{"1:10", []imap.UID{3, 4, 8}, 11, "1:2,5:7,9:10"},
		{"1:10", []imap.UID{1, 10}, 6, "2:5"},             // clamped to UIDNEXT-1
		{"20:30", []imap.UID{1, 10}, 11, ""},              // all at or above UIDNEXT
		{"1:3,5,7:9", []imap.UID{2, 8}, 100, "1,3,5,7,9"}, // gaps of separate ranges
		{"1:3,5:6", nil, 100, "1:3,5:6"},                  // not merged across a known hole
		{"2,4,6", []imap.UID{1, 2, 3, 4, 5, 6}, 100, ""},  // active outside the set ignored
		{"1:5000000", []imap.UID{1, 4999999}, 5000000, "2:4999998"},
		{"1:4294967294", []imap.UID{4294967294}, 4294967295, "1:4294967293"},
		{"4294967295", nil, 0, "4294967295"}, // no UIDNEXT: no clamp, no overflow
		{"4294967295", []imap.UID{4294967295}, 0, ""},
	} {
		got := knownUIDsGaps(set(tc.known), tc.active, tc.uidNext)
		if want := set(tc.want); !reflect.DeepEqual(got, want) {
			t.Errorf("knownUIDsGaps(%s, %v, UIDNEXT %d) = %v, want %v", tc.known, tc.active, tc.uidNext, got, want)
		}
	}

	// "*" cannot reach here (RFC 7162 §7); a dynamic range contributes nothing.
	for _, known := range []imap.UIDSet{{{Start: 0, Stop: 0}}, {{Start: 5, Stop: 0}}} {
		if got := knownUIDsGaps(known, nil, 100); len(got) != 0 {
			t.Errorf("knownUIDsGaps(%v) = %v, want nothing", known, got)
		}
	}
}
