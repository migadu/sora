//go:build integration

package managesieveproxy_test

import (
	"context"
	"encoding/base64"
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

// TestManageSieveProxyDBWrongPasswordCachedForEveryHashScheme covers #342: when the
// proxy falls back to PostgreSQL, a wrong password is logged as invalid_password and
// cached as a negative lookup-cache entry whatever scheme the stored hash uses. An
// SSHA512 or SHA512 mismatch used to be taken for a transient database error: logged
// as transient_error and never cached, so every retry went to the database again.
func TestManageSieveProxyDBWrongPasswordCachedForEveryHashScheme(t *testing.T) {
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
			proxy := setupManageSieveProxyWithFallback(t, rdb, proxyAddress, []string{"127.0.0.1:1"}, lookup.URL, true)
			defer proxy.Close()

			plain := base64.StdEncoding.EncodeToString([]byte("\x00" + email + "\x00wrong-password"))
			for attempt := 1; attempt <= 2; attempt++ {
				client, err := NewManageSieveClient(proxyAddress)
				if err != nil {
					t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
				}
				if err := client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", plain)); err != nil {
					t.Fatalf("Failed to send AUTHENTICATE: %v", err)
				}
				reply, err := client.ReadResponse()
				client.Close()
				if err != nil {
					t.Fatalf("Failed to read AUTHENTICATE reply: %v", err)
				}
				if !strings.HasPrefix(reply, "NO") {
					t.Fatalf("attempt %d: AUTHENTICATE with a wrong password answered %q, want NO", attempt, reply)
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
