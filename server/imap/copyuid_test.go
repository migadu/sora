package imap

import (
	"reflect"
	"testing"

	"github.com/emersion/go-imap/v2"
)

func TestCopyUIDMapping(t *testing.T) {
	pair := func(srcStart, srcStop, dstStart, dstStop imap.UID) imap.UIDPairRange {
		return imap.UIDPairRange{
			Source: imap.UIDRange{Start: srcStart, Stop: srcStop},
			Dest:   imap.UIDRange{Start: dstStart, Stop: dstStop},
		}
	}

	tests := []struct {
		name   string
		uidMap map[imap.UID]imap.UID
		want   imap.UIDMapping
	}{
		{name: "empty", uidMap: nil, want: nil},
		{
			name:   "consecutive pairs merge into one range",
			uidMap: map[imap.UID]imap.UID{1: 10, 2: 11, 3: 12},
			want:   imap.UIDMapping{pair(1, 3, 10, 12)},
		},
		{
			name:   "gaps on the source side split the ranges",
			uidMap: map[imap.UID]imap.UID{1: 10, 3: 11, 5: 12},
			want:   imap.UIDMapping{pair(1, 1, 10, 10), pair(3, 3, 11, 11), pair(5, 5, 12, 12)},
		},
		{
			// Sorting each side on its own would answer 1:4 101:102,110:111 and
			// pair 1 with 101. The pairs must survive.
			name:   "destination order differs from source order",
			uidMap: map[imap.UID]imap.UID{4: 101, 1: 102, 2: 110, 3: 111},
			want:   imap.UIDMapping{pair(1, 1, 102, 102), pair(2, 3, 110, 111), pair(4, 4, 101, 101)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := copyUIDMapping(tt.uidMap)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("copyUIDMapping(%v) = %v, want %v", tt.uidMap, got, tt.want)
			}
			if len(tt.uidMap) == 0 {
				return
			}
			if err := got.Validate(); err != nil {
				t.Fatalf("mapping does not validate: %v", err)
			}
			for sourceUID, destUID := range got.All() {
				if tt.uidMap[sourceUID] != destUID {
					t.Errorf("pair %d -> %d, want %d -> %d", sourceUID, destUID, sourceUID, tt.uidMap[sourceUID])
				}
			}
		})
	}
}
