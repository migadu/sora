package imap

import (
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server/uploader"
)

// A cross-account COPY or MOVE of a body that is still staged stages it a second time,
// under the destination owner, for the owner's own pending upload. The monitor refresh
// counts that staging (one pending row per account and body) and the owner's upload
// subtracts it when it removes the file, so the staging itself must add it too:
// otherwise the max_staging_size guard counts one body short per such staging until
// the next refresh, and admits that much more than fits (issue #1174).
func TestStageCrossAccountBodyCountsAgainstStagingLimit(t *testing.T) {
	const (
		limit     = 2000
		srcID     = int64(1)
		destID    = int64(2)
		otherSize = 600 // staged bodies the COPY does not touch
		bodySize  = 300
	)
	up, err := uploader.NewWithS3Interface(t.TempDir(), 1, 1, 1, time.Second, limit, "test", nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &IMAPSession{server: &IMAPServer{uploader: up}}

	if _, err := up.StoreLocally(strings.Repeat("0", 64), srcID, make([]byte, otherSize)); err != nil {
		t.Fatalf("StoreLocally: %v", err)
	}
	hash := strings.Repeat("ab", 32)
	if _, err := up.StoreLocally(hash, srcID, make([]byte, bodySize)); err != nil {
		t.Fatalf("StoreLocally: %v", err)
	}

	// The second COPY of the same body finds it staged for the owner already.
	for range 2 {
		staged, ierr := s.stageCrossAccountBody("copy", hash, srcID, destID)
		if ierr != nil || !staged {
			t.Fatalf("stageCrossAccountBody = %v, %v; want the body staged for the owner", staged, ierr)
		}
	}

	// Staged now: 600 + 300 for the source + 300 for the owner = 1200.
	if room := int64(limit - otherSize - 2*bodySize); !up.IsStagingLimitExceeded(room + 1) {
		t.Errorf("IsStagingLimitExceeded(%d) = false with %d bytes staged against a %d byte limit: "+
			"the owner's staging of the %d byte body is not counted", room+1, otherSize+2*bodySize, limit, bodySize)
	}

	// Both uploads finish and remove their files: the count is back where it started.
	for _, accountID := range []int64{srcID, destID} {
		if err := up.RemoveLocalFile(up.FilePath(hash, accountID)); err != nil {
			t.Fatalf("RemoveLocalFile: %v", err)
		}
	}
	if room := int64(limit - otherSize); up.IsStagingLimitExceeded(room) || !up.IsStagingLimitExceeded(room+1) {
		t.Fatalf("after both uploads of the body removed their files, IsStagingLimitExceeded(%d) = %v and (%d) = %v, "+
			"want false and true: %d bytes are still staged, and removing the owner's file subtracted bytes its staging never added",
			room, up.IsStagingLimitExceeded(room), room+1, up.IsStagingLimitExceeded(room+1), otherSize)
	}
}
