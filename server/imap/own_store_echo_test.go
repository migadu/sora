package imap

import (
	"maps"
	"testing"

	"github.com/migadu/go-imap"
)

// Poll forgets the own-STORE rows it has passed, and drops the map once it is
// empty: Go never shrinks a map, so keeping an emptied one would hold the
// buckets of a STORE over a large mailbox for as long as it stays selected.
func TestPruneOwnStoreEchoReleasesEmptiedMap(t *testing.T) {
	s := &IMAPSession{}
	s.ownStoreEchoMailboxID = 7
	s.ownStoreEcho = map[imap.UID]uint64{1: 10, 2: 11, 3: 12}

	s.pruneOwnStoreEchoLocked(7, 11)
	if want := map[imap.UID]uint64{3: 12}; !maps.Equal(s.ownStoreEcho, want) {
		t.Fatalf("after cursor 11: got %v, want %v", s.ownStoreEcho, want)
	}

	s.pruneOwnStoreEchoLocked(7, 12)
	if s.ownStoreEcho != nil {
		t.Fatalf("emptied map kept (len %d)", len(s.ownStoreEcho))
	}

	// Rows recorded in another mailbox are all forgotten, whatever the cursor.
	s.ownStoreEcho = map[imap.UID]uint64{1: 20}
	s.pruneOwnStoreEchoLocked(8, 0)
	if s.ownStoreEcho != nil {
		t.Fatalf("rows of mailbox 7 kept after polling mailbox 8: %v", s.ownStoreEcho)
	}
}
