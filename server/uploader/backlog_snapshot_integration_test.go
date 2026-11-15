//go:build integration

package uploader

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

// TestPendingUploadBacklogAnswersChangedBodiesFromItsSnapshot runs the staging refresh's
// measurement against PostgreSQL. Rows that change once the totals are read (an
// upload's row dropped, a delivery's row committed) must be answered for as the totals
// counted them: the refresh relies on Included to tell which changes the totals hold.
func TestPendingUploadBacklogAnswersChangedBodiesFromItsSnapshot(t *testing.T) {
	ctx := context.Background()
	dbName := os.Getenv("SORA_TEST_DB_NAME")
	if dbName == "" {
		dbName = "sora_test_db"
	}
	rdb, err := resilient.NewResilientDatabase(ctx, &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: dbName},
	}, false, true)
	if err != nil {
		t.Fatalf("Failed to set up test database: %v", err)
	}
	t.Cleanup(rdb.Close)
	pool := rdb.GetDatabase().GetWritePool()

	var accountID int64
	if err := pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&accountID); err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() {
		// pending_uploads rows go with the account (ON DELETE CASCADE).
		if _, err := pool.Exec(context.Background(), `DELETE FROM accounts WHERE id = $1`, accountID); err != nil {
			t.Errorf("delete account: %v", err)
		}
	})

	instance := fmt.Sprintf("backlog-snapshot-%016x", rand.Uint64())
	const maxAttempts = 3
	insert := func(instanceID, contentHash string, size, attempts int) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO pending_uploads (account_id, instance_id, content_hash, size, attempts)
			VALUES ($1, $2, $3, $4, $5)
		`, accountID, instanceID, contentHash, size, attempts); err != nil {
			t.Fatalf("insert pending upload %s: %v", contentHash[:8], err)
		}
	}

	kept := stagingHash("a")      // queued before and after
	finished := stagingHash("b")  // its upload finalizes after the totals are read
	delivered := stagingHash("c") // its delivery commits after the totals are read
	exhausted := stagingHash("d") // out of attempts: not part of the backlog
	elsewhere := stagingHash("e") // another instance's upload
	insert(instance, kept, 500, 0)
	insert(instance, finished, 600, 1)
	insert(instance, exhausted, 800, maxAttempts)
	insert(instance+"-peer", elsewhere, 900, 0)

	body := func(contentHash string) StagedBody {
		return StagedBody{AccountID: accountID, ContentHash: contentHash}
	}
	calls := 0
	backlog, err := resilientUploaderDB{rdb}.PendingUploadBacklog(ctx, instance, maxAttempts, func() []StagedBody {
		calls++
		if _, err := pool.Exec(ctx, `DELETE FROM pending_uploads WHERE account_id = $1 AND content_hash = $2`, accountID, finished); err != nil {
			t.Fatalf("finish upload: %v", err)
		}
		insert(instance, delivered, 700, 0)
		return []StagedBody{body(kept), body(finished), body(delivered), body(exhausted), body(elsewhere)}
	})
	if err != nil {
		t.Fatalf("PendingUploadBacklog: %v", err)
	}

	if calls != 1 {
		t.Errorf("changed was called %d times, want once", calls)
	}
	if backlog.Count != 2 || backlog.Bytes != 1100 {
		t.Errorf("backlog = %d uploads, %d bytes; want 2 uploads, 1100 bytes", backlog.Count, backlog.Bytes)
	}
	for b, size := range map[StagedBody]int64{body(kept): 500, body(finished): 600} {
		if got, ok := backlog.Included[b]; !ok || got != size {
			t.Errorf("Included[%s] = %d (present %v), want %d: the answer must come from the totals' snapshot",
				b.ContentHash[:8], got, ok, size)
		}
	}
	for _, b := range []StagedBody{body(delivered), body(exhausted), body(elsewhere)} {
		if got, ok := backlog.Included[b]; ok {
			t.Errorf("Included[%s] = %d, want no entry: the totals do not count it", b.ContentHash[:8], got)
		}
	}
}
