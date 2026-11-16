//go:build integration

package resilient

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

func newSieveTestAccount(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()
	var accountID int64
	if err := pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&accountID); err != nil {
		t.Fatalf("create account: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM accounts WHERE id = $1`, accountID) })
	return accountID
}

// newLaggingReplicaPool returns a pool that reads sieve_scripts from an empty copy
// of the table, as a replica that has not yet replayed the primary's recent creates.
func newLaggingReplicaPool(t *testing.T, cfg *config.DatabaseConfig, primary *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	schema := fmt.Sprintf("lagging_replica_%d", time.Now().UnixNano())
	if _, err := primary.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create replica schema: %v", err)
	}
	t.Cleanup(func() { primary.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	if _, err := primary.Exec(ctx, "CREATE TABLE "+schema+".sieve_scripts (LIKE public.sieve_scripts)"); err != nil {
		t.Fatalf("create replica table: %v", err)
	}

	endpoint := cfg.Write
	poolCfg, err := pgxpool.ParseConfig(fmt.Sprintf("postgres://%s@%s:%s/%s?sslmode=disable",
		endpoint.User, endpoint.Hosts[0], endpoint.Port, endpoint.Name))
	if err != nil {
		t.Fatalf("parse replica pool config: %v", err)
	}
	poolCfg.ConnConfig.RuntimeParams["search_path"] = schema
	replica, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		t.Fatalf("create replica pool: %v", err)
	}
	t.Cleanup(replica.Close)
	return replica
}

func requireStoredScript(t *testing.T, pool *pgxpool.Pool, accountID int64, name, want string) {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT script FROM sieve_scripts WHERE account_id = $1 AND name = $2`, accountID, name)
	if err != nil {
		t.Fatalf("read stored scripts: %v", err)
	}
	defer rows.Close()
	var stored []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan stored script: %v", err)
		}
		stored = append(stored, s)
	}
	if len(stored) != 1 || stored[0] != want {
		t.Fatalf("stored scripts named %q: %q, want one with %q", name, stored, want)
	}
}

// A PUT of a script name the account already has replaces the script, even when the
// read replica has not yet replayed the create from moments before. The name was
// looked up on the read pool, the lookup missed, and the create that followed failed
// on the UNIQUE (account_id, name) constraint (the User API answered 500).
func TestCreateOrUpdateScript_ReplicaHasNotReplayedCreate(t *testing.T) {
	ctx := context.Background()
	cfg := testDatabaseConfig()
	primary := newTestPool(t, cfg, nil)
	rd := newTestResilientDatabase(cfg, primary)
	replica := &DatabasePool{database: &db.Database{WritePool: primary, ReadPool: newLaggingReplicaPool(t, cfg, primary)}, host: "replica"}
	replica.isHealthy.Store(true)
	rd.failoverManager.readPools = []*DatabasePool{replica}
	accountID := newSieveTestAccount(t, primary)

	if _, updated, err := rd.CreateOrUpdateScriptWithRetry(ctx, accountID, "filters", "keep;"); err != nil || updated {
		t.Fatalf("first PUT: updated=%v err=%v, want a create", updated, err)
	}
	if _, err := rd.GetScriptByNameWithRetry(ctx, "filters", accountID); !errors.Is(err, consts.ErrDBNotFound) {
		t.Fatalf("setup: the replica must not have the script yet, lookup got %v", err)
	}

	if _, updated, err := rd.CreateOrUpdateScriptWithRetry(ctx, accountID, "filters", "discard;"); err != nil || !updated {
		t.Fatalf("second PUT of the same name: updated=%v err=%v, want an update", updated, err)
	}
	requireStoredScript(t, primary, accountID, "filters", "discard;")
}

// Two PUTs of the same new script name at the same time: the one that waits for the
// other's create replaces the script instead of failing on the unique constraint.
func TestCreateOrUpdateScript_ConcurrentCreateOfSameName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg := testDatabaseConfig()
	pool := newTestPool(t, cfg, nil)
	rd := newTestResilientDatabase(cfg, pool)
	accountID := newSieveTestAccount(t, pool)

	// The other create, not yet committed.
	other, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer other.Rollback(context.Background())
	if _, err := (&db.Database{WritePool: pool, ReadPool: pool}).CreateScript(ctx, other, accountID, "filters", "keep;"); err != nil {
		t.Fatalf("other create: %v", err)
	}
	var otherPID uint32
	if err := other.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&otherPID); err != nil {
		t.Fatalf("backend pid: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, updated, err := rd.CreateOrUpdateScriptWithRetry(ctx, accountID, "filters", "discard;")
		if err == nil && !updated {
			err = errors.New("reported a create, want an update")
		}
		done <- err
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid))", otherPID).Scan(&waiting); err != nil {
			t.Fatalf("poll lock waiters: %v", err)
		}
		if waiting > 0 {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("PUT finished without waiting for the other create of the name: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("PUT never waited for the other create of the name")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := other.Commit(ctx); err != nil {
		t.Fatalf("commit other create: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("PUT of a name another session just created: %v", err)
	}
	requireStoredScript(t, pool, accountID, "filters", "discard;")
}
