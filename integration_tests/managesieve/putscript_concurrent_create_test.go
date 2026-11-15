//go:build integration

package managesieve

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// PUTSCRIPT of a name that another session is creating at the same moment replaces
// that script (RFC 5804 section 2.6: "If the script already exists, upon success the
// old script will be overwritten."). PUTSCRIPT looked the name up before its write
// transaction, missed the uncommitted create, and its own create then failed on the
// UNIQUE (account_id, name) constraint: NO (TRYLATER), a temporary server failure.
func TestPutScript_ConcurrentCreateOfSameName(t *testing.T) {
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

	conn, r, w := msConnectAndAuth(t, server, account)
	defer conn.Close()

	// The other session's create, not yet committed.
	other, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer other.Rollback(context.Background())
	if _, err := database.CreateScript(ctx, other, accountID, "filters", "keep;\r\n"); err != nil {
		t.Fatalf("other create: %v", err)
	}
	var otherPID uint32
	if err := other.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&otherPID); err != nil {
		t.Fatalf("backend pid: %v", err)
	}

	script := "discard;\r\n"
	fmt.Fprintf(w, "PUTSCRIPT \"filters\" {%d+}\r\n%s\r\n", len(script), script)
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
			t.Fatal("PUTSCRIPT never waited for the other create of the name")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := other.Commit(ctx); err != nil {
		t.Fatalf("commit other create: %v", err)
	}

	if resp := msReadResp(t, conn, r); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("PUTSCRIPT of a name another session just created: got %q, want OK", resp)
	}
	fmt.Fprint(w, "GETSCRIPT \"filters\"\r\n")
	w.Flush()
	if resp := msReadResp(t, conn, r); !strings.Contains(resp, "discard;") {
		t.Fatalf("GETSCRIPT after PUTSCRIPT: got %q, want the uploaded script", resp)
	}
}
