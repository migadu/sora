//go:build integration

package userapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/userapi"
)

// newSharedUserAPITestServer stands up a User API server with the given
// [shared_mailboxes] settings.
func newSharedUserAPITestServer(t *testing.T, rdb *resilient.ResilientDatabase, shared config.SharedMailboxesConfig) *httptest.Server {
	t.Helper()
	apiSrv, err := userapi.New(rdb, userapi.ServerOptions{
		Name:            "test-userapi-shared",
		Addr:            "127.0.0.1:0",
		JWTSecret:       "test-secret-key-for-testing-only",
		TokenDuration:   time.Hour,
		TokenIssuer:     "test-issuer",
		AllowedOrigins:  []string{"*"},
		SharedMailboxes: shared,
	})
	if err != nil {
		t.Fatalf("userapi.New: %v", err)
	}
	ts := httptest.NewServer(apiSrv.SetupRoutes())
	t.Cleanup(ts.Close)
	return ts
}

// namespaceMailboxes returns the account's live mailboxes named like the shared
// namespace ("Shared" or "Shared/..." in any case), each with its is_shared.
func namespaceMailboxes(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64) map[string]bool {
	t.Helper()
	rows, err := rdb.GetOperationalDatabase().WritePool.Query(context.Background(), `
		SELECT name, COALESCE(is_shared, FALSE) FROM mailboxes
		WHERE account_id = $1 AND (LOWER(name) = 'shared' OR LOWER(name) LIKE 'shared/%') AND deleted_at IS NULL`,
		accountID)
	if err != nil {
		t.Fatalf("query mailboxes: %v", err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var name string
		var shared bool
		if err := rows.Scan(&name, &shared); err != nil {
			t.Fatalf("scan mailbox: %v", err)
		}
		got[name] = shared
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read mailboxes: %v", err)
	}
	return got
}

// With [shared_mailboxes] enabled, POST /user/mailboxes refuses a name in the shared
// namespace, the namespace root included, with 403 whatever allow_user_create says:
// the User API does not create shared mailboxes. It created them as personal
// mailboxes (is_shared = false), the state RENAME refuses to make (#160), and
// allow_user_create = false did not stop it (#1230). Names outside the namespace are
// created as before, and with sharing off a name under the prefix is an ordinary
// personal folder.
func TestUserAPI_CreateMailbox_SharedNamespace(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name   string
		shared config.SharedMailboxesConfig
	}{
		{"allow_user_create off", config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/", DefaultRights: "lrswipkxtea"}},
		{"allow_user_create on", config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/", DefaultRights: "lrswipkxtea", AllowUserCreate: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := common.CreateTestAccount(t, rdb)
			accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
			if err != nil {
				t.Fatalf("account id: %v", err)
			}
			ts := newSharedUserAPITestServer(t, rdb, tc.shared)
			client := ts.Client()
			token := h2Login(t, ts, client, account.Email, account.Password)

			for _, name := range []string{"Shared/Team", "Shared", "Shared/", "shared/Lower", "Shared/Deep/Er"} {
				code, body := apiDo(t, ts, client, token, "POST", "/user/mailboxes", map[string]string{"name": name})
				if code != http.StatusForbidden {
					t.Errorf("POST %q: %d (%s), want 403", name, code, body)
				}
			}
			if got := namespaceMailboxes(t, rdb, accountID); len(got) != 0 {
				t.Errorf("refused creates left mailboxes in the shared namespace (name -> is_shared): %v", got)
			}

			for _, name := range []string{"SharedNotes", "Projects/Shared"} {
				if code, body := apiDo(t, ts, client, token, "POST", "/user/mailboxes", map[string]string{"name": name}); code != http.StatusCreated {
					t.Errorf("POST %q outside the shared namespace: %d (%s), want 201", name, code, body)
				}
			}
		})
	}

	t.Run("sharing off", func(t *testing.T) {
		account := common.CreateTestAccount(t, rdb)
		accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
		if err != nil {
			t.Fatalf("account id: %v", err)
		}
		ts := newSharedUserAPITestServer(t, rdb, config.SharedMailboxesConfig{NamespacePrefix: "Shared/"})
		client := ts.Client()
		token := h2Login(t, ts, client, account.Email, account.Password)

		if code, body := apiDo(t, ts, client, token, "POST", "/user/mailboxes", map[string]string{"name": "Shared/Team"}); code != http.StatusCreated {
			t.Fatalf("POST Shared/Team with sharing off: %d (%s), want 201", code, body)
		}
		got := namespaceMailboxes(t, rdb, accountID)
		if len(got) != 2 || got["Shared"] || got["Shared/Team"] {
			t.Errorf("with sharing off Shared/Team and its parent are personal folders; got (name -> is_shared) %v", got)
		}
	})
}
