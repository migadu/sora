package lmtpproxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server"
)

// TestLMTPRefusedRecipientNeverFallsBackToTheDatabase: 401/403 are the lookup contract's
// way to refuse an account, and lookup_local_users applies to 404/3xx only
// (config.toml.example). A refused recipient must not be looked up in the local database
// and delivered there. The proxy here has no database, so a fallback shows as its
// "database not available" error. The refusal gets the reply a remote "not found" gets
// without fallback (user_not_found_response), fresh and from the cache alike.
func TestLMTPRefusedRecipientNeverFallsBackToTheDatabase(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		for _, localUsers := range []bool{true, false} {
			for _, tc := range []struct {
				response string
				want     error
			}{
				{"reject", server.ErrUserNotFound},
				{"tempfail", server.ErrUserNotFoundTempFail},
			} {
				name := fmt.Sprintf("%d/lookup_local_users=%v/%s", status, localUsers, tc.response)
				t.Run(name, func(t *testing.T) {
					var lookups atomic.Int32
					lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						lookups.Add(1)
						http.Error(w, `{"error": "account refused"}`, status)
					}))
					t.Cleanup(lookup.Close)
					srv, err := New(context.Background(), nil, "test-host", ServerOptions{
						Name: "refusal", RemoteAddrs: []string{"127.0.0.1:1"}, RemotePort: 24, ConnectTimeout: time.Second,
						RemoteLookup: &config.RemoteLookupConfig{
							Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "1s",
							LookupLocalUsers: localUsers, UserNotFoundResponse: tc.response,
						},
					})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { srv.Stop() })

					fresh := recipientError(t, srv, "refused@example.com")
					if !errors.Is(fresh, tc.want) {
						t.Fatalf("lookup answered %d: got %v, want %v (no database fallback)", status, fresh, tc.want)
					}
					cached := recipientError(t, srv, "refused@example.com")
					if n := lookups.Load(); n != 1 {
						t.Fatalf("remote lookup asked %d times, want 1 (the second recipient must be a cache hit)", n)
					}
					if !errors.Is(cached, tc.want) {
						t.Errorf("cache hit: got %v, want %v (the reply the fresh answer got)", cached, tc.want)
					}
				})
			}
		}
	}
}
