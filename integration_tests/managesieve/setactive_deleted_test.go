//go:build integration

package managesieve

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// setActiveFixture stores scripts "a" (active) and "b" (inactive) for the account.
func setActiveFixture(t *testing.T) (server *common.TestServer, account common.TestAccount, database *db.Database, accountID int64) {
	t.Helper()
	common.SkipIfDatabaseUnavailable(t)
	server, account = common.SetupManageSieveServer(t)
	t.Cleanup(server.Close)

	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("account ID: %v", err)
	}
	database = server.ResilientDB.GetOperationalDatabase()
	putScript(t, server, account, "a")
	putScript(t, server, account, "b")
	if _, err := database.GetWritePool().Exec(context.Background(),
		"UPDATE sieve_scripts SET active = true WHERE account_id = $1 AND name = 'a'", accountID); err != nil {
		t.Fatalf("activate a: %v", err)
	}
	return server, account, database, accountID
}

// readFromSnapshot points the server's read pool at a copy of sieve_scripts as it is
// now: a replica that replays none of the writes that follow.
func readFromSnapshot(t *testing.T, database *db.Database) {
	t.Helper()
	ctx := context.Background()
	pool := database.GetWritePool()
	schema := fmt.Sprintf("sieve_replica_%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create replica schema: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	if _, err := pool.Exec(ctx, fmt.Sprintf("CREATE TABLE %s.sieve_scripts AS TABLE public.sieve_scripts", schema)); err != nil {
		t.Fatalf("snapshot sieve_scripts: %v", err)
	}
	poolCfg := database.ReadPool.Config().Copy()
	poolCfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	lagging, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		t.Fatalf("replica pool: %v", err)
	}
	t.Cleanup(lagging.Close)
	original := database.ReadPool
	database.ReadPool = lagging
	t.Cleanup(func() { database.ReadPool = original })
}

// sendSetActive sends SETACTIVE "name" on a new session and returns the response.
func sendSetActive(t *testing.T, server *common.TestServer, account common.TestAccount, name string) string {
	t.Helper()
	conn, r, w := msConnectAndAuth(t, server, account)
	defer conn.Close()
	fmt.Fprintf(w, "SETACTIVE %q\r\n", name)
	w.Flush()
	return msReadResp(t, conn, r)
}

// RFC 5804 section 2.8: "If the script does not exist on the server, then the server
// MUST reply with a NO response". SETACTIVE looked the script up, then activated it by
// ID in a later transaction. When another session deleted the script in between, the
// activation deactivated "a", activated nothing and answered OK.
func TestSetActive_DeletedConcurrently(t *testing.T) {
	server, account, database, accountID := setActiveFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := database.GetWritePool()

	// Hold the active script's row so SETACTIVE "b" stops after its lookup, at the
	// deactivation that precedes the activation.
	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer holder.Rollback(context.Background())
	if _, err := holder.Exec(ctx, "SELECT 1 FROM sieve_scripts WHERE account_id = $1 AND name = 'a' FOR UPDATE", accountID); err != nil {
		t.Fatalf("lock a: %v", err)
	}
	var holderPID uint32
	if err := holder.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&holderPID); err != nil {
		t.Fatalf("backend pid: %v", err)
	}

	conn, r, w := msConnectAndAuth(t, server, account)
	defer conn.Close()
	fmt.Fprint(w, "SETACTIVE \"b\"\r\n")
	w.Flush()

	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid))", holderPID).Scan(&waiting); err != nil {
			t.Fatalf("poll lock waiters: %v", err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("SETACTIVE never waited for the active script's row")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Another session's DELETESCRIPT "b" commits.
	if _, err := pool.Exec(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1 AND name = 'b'", accountID); err != nil {
		t.Fatalf("delete b: %v", err)
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatalf("release a: %v", err)
	}

	if resp := msReadResp(t, conn, r); !strings.HasPrefix(resp, "NO (NONEXISTENT)") {
		t.Errorf("SETACTIVE of a script deleted concurrently: got %q, want NO (NONEXISTENT)", resp)
	}
	requireActiveScriptStored(t, pool, accountID, "a")
}

// A script deleted elsewhere (the User API, another ManageSieve session) whose delete
// the read replica has not replayed yet: a new session's SETACTIVE found it on the
// replica, deactivated "a", activated nothing and answered OK.
func TestSetActive_DeletedOnPrimaryNotOnReplica(t *testing.T) {
	server, account, database, accountID := setActiveFixture(t)
	pool := database.GetWritePool()
	readFromSnapshot(t, database)
	if _, err := pool.Exec(context.Background(), "DELETE FROM sieve_scripts WHERE account_id = $1 AND name = 'b'", accountID); err != nil {
		t.Fatalf("delete b on the primary: %v", err)
	}

	if resp := sendSetActive(t, server, account, "b"); !strings.HasPrefix(resp, "NO (NONEXISTENT)") {
		t.Errorf("SETACTIVE of a script deleted on the primary: got %q, want NO (NONEXISTENT)", resp)
	}
	requireActiveScriptStored(t, pool, accountID, "a")
}

// SETACTIVE validates the script before it activates it. It validated the content the
// read replica held, so a script replaced on the primary by content delivery cannot
// run was activated.
func TestSetActive_ValidatesPrimaryContent(t *testing.T) {
	server, account, database, accountID := setActiveFixture(t)
	pool := database.GetWritePool()
	readFromSnapshot(t, database)
	if _, err := pool.Exec(context.Background(),
		`UPDATE sieve_scripts SET script = 'require ["enclose"]; keep;' WHERE account_id = $1 AND name = 'b'`, accountID); err != nil {
		t.Fatalf("replace b on the primary: %v", err)
	}

	if resp := sendSetActive(t, server, account, "b"); !strings.HasPrefix(resp, "NO") {
		t.Errorf("SETACTIVE of a script the server cannot run: got %q, want NO", resp)
	}
	requireActiveScriptStored(t, pool, accountID, "a")
}
