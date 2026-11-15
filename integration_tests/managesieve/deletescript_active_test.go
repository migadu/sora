//go:build integration

package managesieve

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/integration_tests/common"
)

// putScript stores a script over conn and fails the test unless the server answers OK.
func putScript(t *testing.T, server *common.TestServer, account common.TestAccount, name string) {
	t.Helper()
	conn, r, w := msConnectAndAuth(t, server, account)
	defer conn.Close()
	script := "keep;\r\n"
	fmt.Fprintf(w, "PUTSCRIPT %q {%d+}\r\n%s\r\n", name, len(script), script)
	w.Flush()
	if resp := msReadResp(t, conn, r); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("PUTSCRIPT %q: got %q, want OK", name, resp)
	}
}

// requireActiveScriptStored fails the test unless the account's script called name is
// stored on the primary and active.
func requireActiveScriptStored(t *testing.T, pool *pgxpool.Pool, accountID int64, name string) {
	t.Helper()
	var active bool
	err := pool.QueryRow(context.Background(),
		"SELECT active FROM sieve_scripts WHERE account_id = $1 AND name = $2", accountID, name).Scan(&active)
	if err != nil {
		t.Fatalf("the active script %q was deleted: %v", name, err)
	}
	if !active {
		t.Fatalf("script %q is no longer active", name)
	}
}

// RFC 5804 section 2.10: "The server MUST NOT allow the client to delete an active
// script, so the server MUST reply with a NO response if attempted." DELETESCRIPT
// checked a lookup made before its write transaction; a SETACTIVE of the script by
// another session that committed between that lookup and the delete left the account
// with no script at all, so its filtering stopped.
func TestDeleteScript_ActivatedConcurrently(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account ID: %v", err)
	}
	database := server.ResilientDB.GetOperationalDatabase()
	pool := database.GetWritePool()

	putScript(t, server, account, "filters")
	var scriptID int64
	if err := pool.QueryRow(ctx, "SELECT id FROM sieve_scripts WHERE account_id = $1 AND name = 'filters'", accountID).Scan(&scriptID); err != nil {
		t.Fatalf("script ID: %v", err)
	}

	// The other session's SETACTIVE, not yet committed.
	other, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer other.Rollback(context.Background())
	if err := database.SetScriptActive(ctx, other, scriptID, accountID, true); err != nil {
		t.Fatalf("other SETACTIVE: %v", err)
	}
	var otherPID uint32
	if err := other.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&otherPID); err != nil {
		t.Fatalf("backend pid: %v", err)
	}

	conn, r, w := msConnectAndAuth(t, server, account)
	defer conn.Close()
	fmt.Fprint(w, "DELETESCRIPT \"filters\"\r\n")
	w.Flush()

	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid))", otherPID).Scan(&waiting); err != nil {
			t.Fatalf("poll lock waiters: %v", err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DELETESCRIPT never waited for the other session's SETACTIVE")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := other.Commit(ctx); err != nil {
		t.Fatalf("commit other SETACTIVE: %v", err)
	}

	if resp := msReadResp(t, conn, r); !strings.HasPrefix(resp, "NO (ACTIVE)") {
		t.Errorf("DELETESCRIPT of a script another session just activated: got %q, want NO (ACTIVE)", resp)
	}
	requireActiveScriptStored(t, pool, accountID, "filters")
}

// A script activated elsewhere (the User API, another ManageSieve session) whose
// activation the read replica has not replayed yet: a new session's DELETESCRIPT read
// the script as inactive from the replica and deleted the active script.
func TestDeleteScript_ActiveOnPrimaryInactiveOnReplica(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account ID: %v", err)
	}
	database := server.ResilientDB.GetOperationalDatabase()
	pool := database.GetWritePool()

	putScript(t, server, account, "filters")

	// The replica has replayed the create but not the activation that follows.
	schema := fmt.Sprintf("sieve_replica_%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create replica schema: %v", err)
	}
	defer pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	if _, err := pool.Exec(ctx, fmt.Sprintf("CREATE TABLE %s.sieve_scripts AS TABLE public.sieve_scripts", schema)); err != nil {
		t.Fatalf("snapshot sieve_scripts: %v", err)
	}
	poolCfg := database.ReadPool.Config().Copy()
	poolCfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	lagging, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		t.Fatalf("replica pool: %v", err)
	}
	defer lagging.Close()
	original := database.ReadPool
	database.ReadPool = lagging
	defer func() { database.ReadPool = original }()

	if _, err := pool.Exec(ctx, "UPDATE sieve_scripts SET active = true WHERE account_id = $1 AND name = 'filters'", accountID); err != nil {
		t.Fatalf("activate on the primary: %v", err)
	}

	conn, r, w := msConnectAndAuth(t, server, account)
	defer conn.Close()
	fmt.Fprint(w, "DELETESCRIPT \"filters\"\r\n")
	w.Flush()
	if resp := msReadResp(t, conn, r); !strings.HasPrefix(resp, "NO (ACTIVE)") {
		t.Errorf("DELETESCRIPT of the active script: got %q, want NO (ACTIVE)", resp)
	}
	requireActiveScriptStored(t, pool, accountID, "filters")
}
