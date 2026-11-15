//go:build integration

package resilient

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/db"
)

// newSieveTestWithLaggingReplica returns a ResilientDatabase whose read pool is a
// replica that has replayed none of the account's sieve_scripts writes, the replica
// itself (to seed stale rows into), the primary, and a fresh account.
func newSieveTestWithLaggingReplica(t *testing.T) (rd *ResilientDatabase, replica, primary *pgxpool.Pool, accountID int64) {
	t.Helper()
	cfg := testDatabaseConfig()
	primary = newTestPool(t, cfg, nil)
	rd = newTestResilientDatabase(cfg, primary)
	replica = newLaggingReplicaPool(t, cfg, primary)
	replicaPool := &DatabasePool{database: &db.Database{WritePool: primary, ReadPool: replica}, host: "replica"}
	replicaPool.isHealthy.Store(true)
	rd.failoverManager.readPools = []*DatabasePool{replicaPool}
	return rd, replica, primary, newSieveTestAccount(t, primary)
}

// primaryScriptState reports whether the account has a script called name on the
// primary and whether it is active.
func primaryScriptState(t *testing.T, primary *pgxpool.Pool, accountID int64, name string) (exists, active bool) {
	t.Helper()
	err := primary.QueryRow(context.Background(),
		`SELECT count(*) > 0, coalesce(bool_or(active), false) FROM sieve_scripts WHERE account_id = $1 AND name = $2`,
		accountID, name).Scan(&exists, &active)
	if err != nil {
		t.Fatalf("read stored script: %v", err)
	}
	return exists, active
}

// The User API stores a filter with PUT and deletes it with DELETE. When the DELETE
// follows before the read replica has replayed the create, the name was looked up on
// the replica, the lookup missed, and the DELETE answered 404 for a script that exists.
func TestDeleteScript_ReplicaHasNotReplayedCreate(t *testing.T) {
	ctx := context.Background()
	rd, _, primary, accountID := newSieveTestWithLaggingReplica(t)

	if _, _, err := rd.CreateOrUpdateScriptWithRetry(ctx, accountID, "filters", "keep;"); err != nil {
		t.Fatalf("PUT: %v", err)
	}
	if err := rd.DeleteScriptWithRetry(ctx, "filters", accountID); err != nil {
		t.Fatalf("DELETE of a script the replica has not replayed yet: %v", err)
	}
	if exists, _ := primaryScriptState(t, primary, accountID, "filters"); exists {
		t.Fatal("the script is still stored after its DELETE")
	}
}

// A script deleted and created again under the same name within the replica lag: the
// replica still holds the old row, so the lookup returned its ID, the delete by ID
// removed nothing, and the DELETE answered success while the script was still there.
func TestDeleteScript_ReplicaHoldsReplacedScript(t *testing.T) {
	ctx := context.Background()
	rd, replica, primary, accountID := newSieveTestWithLaggingReplica(t)

	if _, _, err := rd.CreateOrUpdateScriptWithRetry(ctx, accountID, "filters", "keep;"); err != nil {
		t.Fatalf("first PUT: %v", err)
	}
	if _, err := replica.Exec(ctx, `INSERT INTO sieve_scripts SELECT * FROM public.sieve_scripts WHERE account_id = $1`, accountID); err != nil {
		t.Fatalf("replay the first PUT on the replica: %v", err)
	}
	if _, err := primary.Exec(ctx, `DELETE FROM sieve_scripts WHERE account_id = $1`, accountID); err != nil {
		t.Fatalf("delete on the primary: %v", err)
	}
	if _, _, err := rd.CreateOrUpdateScriptWithRetry(ctx, accountID, "filters", "discard;"); err != nil {
		t.Fatalf("second PUT: %v", err)
	}

	if err := rd.DeleteScriptWithRetry(ctx, "filters", accountID); err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	if exists, _ := primaryScriptState(t, primary, accountID, "filters"); exists {
		t.Fatal("DELETE succeeded but the script is still stored")
	}
}

// Activating or deactivating a script by name resolves the name the same way.
func TestSetScriptActiveByName_ReplicaHasNotReplayedCreate(t *testing.T) {
	t.Run("activate", func(t *testing.T) {
		ctx := context.Background()
		rd, _, primary, accountID := newSieveTestWithLaggingReplica(t)
		if _, _, err := rd.CreateOrUpdateScriptWithRetry(ctx, accountID, "filters", "keep;"); err != nil {
			t.Fatalf("PUT: %v", err)
		}

		if err := rd.ActivateScriptWithRetry(ctx, "filters", accountID); err != nil {
			t.Fatalf("activate a script the replica has not replayed yet: %v", err)
		}
		if _, active := primaryScriptState(t, primary, accountID, "filters"); !active {
			t.Fatal("the script is not active after its activation")
		}
	})

	t.Run("deactivate", func(t *testing.T) {
		ctx := context.Background()
		rd, _, primary, accountID := newSieveTestWithLaggingReplica(t)
		stored, _, err := rd.CreateOrUpdateScriptWithRetry(ctx, accountID, "filters", "keep;")
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		if err := rd.SetScriptActiveWithRetry(ctx, stored.ID, accountID, true); err != nil {
			t.Fatalf("activate: %v", err)
		}

		if err := rd.DeactivateScriptWithRetry(ctx, "filters", accountID); err != nil {
			t.Fatalf("deactivate a script the replica has not replayed yet: %v", err)
		}
		if _, active := primaryScriptState(t, primary, accountID, "filters"); active {
			t.Fatal("the script is still active after its deactivation")
		}
	})
}
