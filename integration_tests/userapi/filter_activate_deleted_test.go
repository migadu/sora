//go:build integration

package userapi

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// POST /user/filters/{name}/activate looks the script up, then activates it by ID in
// a later transaction. When the script was deleted in between (a DELETE of the filter,
// a ManageSieve DELETESCRIPT), the activation deactivated the active script, activated
// nothing and answered 200, so the account's filtering stopped.
func TestActivateFilter_DeletedConcurrently(t *testing.T) {
	tc := setupTestServer(t)
	tc.JWTToken = tc.loginFor(t, tc.TestUser.Email, tc.TestUser.Password)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accountID := tc.accountID(t)
	pool := tc.RDB.GetOperationalDatabase().GetWritePool()

	active, err := tc.RDB.CreateScriptWithRetry(ctx, accountID, "a", "keep;")
	if err != nil {
		t.Fatalf("create a: %v", err)
	}
	if err := tc.RDB.SetScriptActiveWithRetry(ctx, active.ID, accountID, true); err != nil {
		t.Fatalf("activate a: %v", err)
	}
	if _, err := tc.RDB.CreateScriptWithRetry(ctx, accountID, "b", "keep;"); err != nil {
		t.Fatalf("create b: %v", err)
	}

	// Hold the active script's row so the activation of "b" stops after its lookup,
	// at the deactivation that precedes the activation.
	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer holder.Rollback(context.Background())
	if _, err := holder.Exec(ctx, "SELECT 1 FROM sieve_scripts WHERE id = $1 FOR UPDATE", active.ID); err != nil {
		t.Fatalf("lock a: %v", err)
	}
	var holderPID uint32
	if err := holder.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&holderPID); err != nil {
		t.Fatalf("backend pid: %v", err)
	}

	status := make(chan int, 1)
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tc.Server.URL+"/user/filters/b/activate", nil)
		if err != nil {
			status <- 0
			return
		}
		req.Header.Set("Authorization", "Bearer "+tc.JWTToken)
		resp, err := tc.HTTPClient.Do(req)
		if err != nil {
			status <- 0
			return
		}
		resp.Body.Close()
		status <- resp.StatusCode
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid))", holderPID).Scan(&waiting); err != nil {
			t.Fatalf("poll lock waiters: %v", err)
		}
		if waiting > 0 {
			break
		}
		select {
		case code := <-status:
			t.Fatalf("activation answered %d without waiting for the active script's row", code)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("activation never waited for the active script's row")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The DELETE of filter "b" commits.
	if _, err := pool.Exec(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1 AND name = 'b'", accountID); err != nil {
		t.Fatalf("delete b: %v", err)
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatalf("release a: %v", err)
	}

	if code := <-status; code != http.StatusNotFound {
		t.Errorf("activation of a filter deleted concurrently: got %d, want %d", code, http.StatusNotFound)
	}
	var isActive bool
	if err := pool.QueryRow(ctx, "SELECT active FROM sieve_scripts WHERE id = $1", active.ID).Scan(&isActive); err != nil {
		t.Fatalf("read a: %v", err)
	}
	if !isActive {
		t.Error("the active filter was deactivated by the activation of a deleted one")
	}
}
