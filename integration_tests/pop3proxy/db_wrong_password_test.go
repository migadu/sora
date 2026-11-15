//go:build integration

package pop3proxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// TestPOP3ProxyDBWrongPasswordCachedForEveryHashScheme covers #342: when the proxy
// falls back to PostgreSQL, a wrong password is logged as invalid_password and cached
// as a negative lookup-cache entry whatever scheme the stored hash uses. An SSHA512 or
// SHA512 mismatch used to be taken for a transient database error: logged as
// transient_error and never cached, so every retry went to the database again.
func TestPOP3ProxyDBWrongPasswordCachedForEveryHashScheme(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)

	for _, hashType := range []string{"bcrypt", "ssha512", "sha512"} {
		t.Run(hashType, func(t *testing.T) {
			email := fmt.Sprintf("wrong-pw-%s-%d@example.com", hashType, time.Now().UnixNano())
			req := db.CreateAccountRequest{Email: email, Password: "right-password", HashType: hashType, IsPrimary: true}
			if hashType == "sha512" {
				// New passwords are no longer hashed with unsalted SHA-512 (#446): a
				// legacy credential arrives pre-computed.
				req = db.CreateAccountRequest{Email: email, PasswordHash: db.GenerateSHA512Hash("right-password"), IsPrimary: true}
			}
			if _, err := rdb.CreateAccountWithRetry(context.Background(), req); err != nil {
				t.Fatalf("Failed to create %s account: %v", hashType, err)
			}

			// The remote lookup knows nobody, so every login that gets past the lookup
			// cache asks it once and then falls back to the database.
			var lookups atomic.Int32
			lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				lookups.Add(1)
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"error": "user not found"})
			}))
			defer lookup.Close()

			logs := common.CaptureLogs(t)
			proxyAddress := common.GetRandomAddress(t)
			// No login gets past authentication, so the backend is never dialed.
			proxy := setupPOP3ProxyWithFallback(t, rdb, proxyAddress, []string{"127.0.0.1:1"}, lookup.URL, true)
			defer proxy.Close()

			for attempt := 1; attempt <= 2; attempt++ {
				if reply := pop3Login(t, proxyAddress, common.TestAccount{Email: email, Password: "wrong-password"}); !strings.HasPrefix(reply, "-ERR") {
					t.Fatalf("attempt %d: PASS with a wrong password answered %q, want -ERR", attempt, reply)
				}
			}

			line := logs.WaitForLine(t, "authentication failed", "method=main_db")
			if !strings.Contains(line, "reason=invalid_password") {
				t.Errorf("wrong password logged as %q, want reason=invalid_password", line)
			}
			if got := lookups.Load(); got != 1 {
				t.Errorf("two logins with the same wrong password made %d remote lookups, want 1: the second was not answered from the lookup cache", got)
			}
		})
	}
}
