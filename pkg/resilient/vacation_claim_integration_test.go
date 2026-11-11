//go:build integration

package resilient

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// A COMMIT that persisted but lost its acknowledgement must never authorize a
// reply or retry the history insert. A later healthy claim sees the committed
// period and also loses, keeping the ambiguous delivery fail-closed.
func TestVacationClaim_AmbiguousCommitFailsClosed(t *testing.T) {
	ctx := context.Background()
	cfg := testDatabaseConfig()
	plain := newTestPool(t, cfg, nil)
	var accountID int64
	if err := plain.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&accountID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { plain.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, accountID) })
	var armed, fired atomic.Bool
	faulty := newTestResilientDatabase(cfg, newFaultyPool(t, cfg, &armed, &fired))
	armed.Store(true)
	claimed, err := faulty.ClaimVacationResponseWithRetry(ctx, accountID, "sender@example.net", "response", time.Hour)
	if !fired.Load() {
		t.Fatal("COMMIT acknowledgement fault was not injected")
	}
	if claimed || !errors.Is(err, ErrCommitOutcomeUnknown) {
		t.Fatalf("ambiguous claim authorized=%v error=%v, want false and ErrCommitOutcomeUnknown", claimed, err)
	}
	var records int
	if err := plain.QueryRow(ctx, `SELECT count(*) FROM vacation_responses WHERE account_id = $1`, accountID).Scan(&records); err != nil {
		t.Fatal(err)
	}
	if records != 1 {
		t.Fatalf("ambiguous COMMIT wrote %d records, want one with no retry", records)
	}
	healthy := newTestResilientDatabase(cfg, plain)
	if claimed, err := healthy.ClaimVacationResponseWithRetry(ctx, accountID, "sender@example.net", "response", time.Hour); err != nil || claimed {
		t.Fatalf("claim after ambiguous committed response authorized=%v error=%v, want false and nil", claimed, err)
	}
}
