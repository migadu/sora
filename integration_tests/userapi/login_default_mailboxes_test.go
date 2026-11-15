//go:build integration

package userapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/userapi"
)

// TestUserAPILoginCreatesDefaultMailboxes is issue #601: account creation makes no
// mailboxes, and IMAP, POP3 and LMTP create the defaults on the first login or
// delivery. The User API login did not, so an account that had never logged in over
// IMAP or POP3 nor received mail had no mailboxes at all here: GET /user/mailboxes
// answered an empty list and GET /user/mailboxes/INBOX/messages 404.
//
// The login creates them on the writer. A read replica that has not replayed that
// yet still holds the account and its credentials but none of the mailboxes, so the
// reads that follow the login must find them on the writer.
func TestUserAPILoginCreatesDefaultMailboxes(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	t.Run("database", func(t *testing.T) {
		rdb := common.SetupTestDatabase(t)
		api := startDefaultMailboxesAPI(t, rdb, nil)
		_, email, password := createAccountWithoutMailboxes(t, rdb)

		api.JWTToken = api.loginFor(t, email, password)
		api.requireDefaultMailboxes(t)
	})

	// A login answered from the lookup cache runs no credential query, and must
	// create the mailboxes too.
	t.Run("lookup cache", func(t *testing.T) {
		rdb := common.SetupTestDatabase(t)
		lookupCache := config.DefaultLookupCacheConfig()
		api := startDefaultMailboxesAPI(t, rdb, &lookupCache)
		accountID, email, password := createAccountWithoutMailboxes(t, rdb)

		api.JWTToken = api.loginFor(t, email, password) // from the database; caches the login
		dropMailboxes(t, rdb, accountID)
		// Only the cache still knows this password, so the next login's 200 shows
		// it came from the cache.
		otherHash, err := db.GenerateBcryptHash("an0ther-p4ssword")
		if err != nil {
			t.Fatalf("hash another password: %v", err)
		}
		if err := rdb.UpdatePasswordWithRetry(context.Background(), email, otherHash); err != nil {
			t.Fatalf("change the stored password: %v", err)
		}

		api.JWTToken = api.loginFor(t, email, password)
		api.requireDefaultMailboxes(t)
	})

	t.Run("lagging read replica", func(t *testing.T) {
		rdb := common.SetupTestDatabase(t)
		api := startDefaultMailboxesAPI(t, rdb, nil)
		accountID, email, password := createAccountWithoutMailboxes(t, rdb)
		restore := installLaggingReplica(t, rdb, accountID)
		defer restore()

		api.JWTToken = api.loginFor(t, email, password)
		api.requireDefaultMailboxes(t)

		// Without this the subtest would pass on a read pool that sees the writer's rows.
		ctx := context.Background()
		replica, err := rdb.GetMailboxesForUserWithRetry(ctx, accountID, false)
		if err != nil {
			t.Fatalf("list the mailboxes on the replica: %v", err)
		}
		writer, err := rdb.GetMailboxesForUserWithRetry(context.WithValue(ctx, consts.UseMasterDBKey, true), accountID, false)
		if err != nil {
			t.Fatalf("list the mailboxes on the writer: %v", err)
		}
		if len(replica) != 0 || len(writer) != len(consts.DefaultMailboxes) {
			t.Fatalf("replica has %d mailboxes and the writer %d, want 0 and %d", len(replica), len(writer), len(consts.DefaultMailboxes))
		}
	})

	// Only a read that finds no INBOX asks the writer: an account that has its
	// mailboxes keeps reading the read pool, which does not show a mailbox created
	// on the writer after its snapshot.
	t.Run("existing account keeps reading the replica", func(t *testing.T) {
		rdb := common.SetupTestDatabase(t)
		api := startDefaultMailboxesAPI(t, rdb, nil)
		accountID, email, password := createAccountWithoutMailboxes(t, rdb)
		api.JWTToken = api.loginFor(t, email, password) // creates the default mailboxes
		restore := installLaggingReplica(t, rdb, accountID)
		defer restore()
		ctx := context.Background()
		if err := rdb.CreateMailboxForUserWithRetry(ctx, accountID, "Later"); err != nil {
			t.Fatalf("create a mailbox on the writer: %v", err)
		}

		api.JWTToken = api.loginFor(t, email, password)
		listed := api.listMailboxes(t)
		if len(listed) != len(consts.DefaultMailboxes) || listed["Later"] {
			t.Fatalf("GET /user/mailboxes lists %d mailboxes (Later: %v), want the %d the replica has", len(listed), listed["Later"], len(consts.DefaultMailboxes))
		}

		// Without this the subtest would pass on a read pool that sees the writer's rows.
		writer, err := rdb.GetMailboxesForUserWithRetry(context.WithValue(ctx, consts.UseMasterDBKey, true), accountID, false)
		if err != nil {
			t.Fatalf("list the mailboxes on the writer: %v", err)
		}
		if len(writer) != len(consts.DefaultMailboxes)+1 {
			t.Fatalf("the writer has %d mailboxes, want %d", len(writer), len(consts.DefaultMailboxes)+1)
		}
	})
}

// startDefaultMailboxesAPI starts a User API on rdb, with the lookup cache when
// lookupCache is not nil.
func startDefaultMailboxesAPI(t *testing.T, rdb *resilient.ResilientDatabase, lookupCache *config.LookupCacheConfig) *TestContext {
	t.Helper()

	srv, err := userapi.New(rdb, userapi.ServerOptions{
		Name:          fmt.Sprintf("test-userapi-default-mailboxes-%d", time.Now().UnixNano()),
		Addr:          "127.0.0.1:0",
		JWTSecret:     "test-secret-key-for-testing-only",
		TokenDuration: time.Hour,
		TokenIssuer:   "test-issuer",
		LookupCache:   lookupCache,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	testServer := httptest.NewServer(srv.SetupRoutes())
	t.Cleanup(testServer.Close)
	return &TestContext{Server: testServer, RDB: rdb, HTTPClient: testServer.Client()}
}

// requireDefaultMailboxes checks, with tc.JWTToken, that every default mailbox is
// listed and that INBOX lists and searches as empty.
func (tc *TestContext) requireDefaultMailboxes(t *testing.T) {
	t.Helper()

	listed := tc.listMailboxes(t)
	for _, name := range consts.DefaultMailboxes {
		if !listed[name] {
			t.Errorf("GET /user/mailboxes does not list the default mailbox %q (listed %d mailboxes)", name, len(listed))
		}
	}

	resp := tc.makeRequest(t, http.MethodGet, "/user/mailboxes/INBOX/messages", nil)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("GET /user/mailboxes/INBOX/messages: status %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var messages userapi.MessageListResponse
	parseJSON(t, resp, &messages)
	if messages.Total != 0 || len(messages.Messages) != 0 {
		t.Errorf("INBOX lists %d of %d messages, want an empty INBOX", len(messages.Messages), messages.Total)
	}

	resp = tc.makeRequest(t, http.MethodGet, "/user/mailboxes/INBOX/search?q=test", nil)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("GET /user/mailboxes/INBOX/search: status %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var found struct {
		Total int `json:"total"`
	}
	parseJSON(t, resp, &found)
	if found.Total != 0 {
		t.Errorf("a search of INBOX found %d messages, want none", found.Total)
	}
}

// listMailboxes returns the names GET /user/mailboxes lists with tc.JWTToken.
func (tc *TestContext) listMailboxes(t *testing.T) map[string]bool {
	t.Helper()

	resp := tc.makeRequest(t, http.MethodGet, "/user/mailboxes", nil)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("GET /user/mailboxes: status %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var list struct {
		Mailboxes []userapi.MailboxInfo `json:"mailboxes"`
	}
	parseJSON(t, resp, &list)
	listed := make(map[string]bool, len(list.Mailboxes))
	for _, mb := range list.Mailboxes {
		listed[mb.Name] = true
	}
	return listed
}

// createAccountWithoutMailboxes creates an account the way account creation does,
// with no mailboxes, unlike common.CreateTestAccount. It fails the test if the
// account already has a mailbox, since every check after the login would then pass
// without the login having created anything.
func createAccountWithoutMailboxes(t *testing.T, rdb *resilient.ResilientDatabase) (accountID int64, email, password string) {
	t.Helper()

	email = fmt.Sprintf("fresh-%d@example.com", time.Now().UnixNano())
	password = "s3cur3p4ss!"
	accountID, err := rdb.CreateAccountWithRetry(context.Background(), db.CreateAccountRequest{
		Email:     email,
		Password:  password,
		HashType:  "bcrypt",
		IsPrimary: true,
	})
	if err != nil {
		t.Fatalf("Failed to create test account: %v", err)
	}
	mailboxes, err := rdb.GetMailboxesWithRetry(context.Background(), accountID, false)
	if err != nil {
		t.Fatalf("Failed to list the new account's mailboxes: %v", err)
	}
	if len(mailboxes) != 0 {
		t.Fatalf("the new account already has %d mailboxes before any login, want 0", len(mailboxes))
	}
	return accountID, email, password
}

// dropMailboxes removes the account's (empty) mailboxes and subscriptions, leaving
// it as account creation left it.
func dropMailboxes(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64) {
	t.Helper()

	ctx := context.Background()
	writer := rdb.GetOperationalDatabase().WritePool
	for _, table := range []string{"subscriptions", "mailboxes"} {
		if _, err := writer.Exec(ctx, "DELETE FROM "+table+" WHERE account_id = $1", accountID); err != nil {
			t.Fatalf("delete the account's %s: %v", table, err)
		}
	}
	mailboxes, err := rdb.GetMailboxesWithRetry(ctx, accountID, false)
	if err != nil || len(mailboxes) != 0 {
		t.Fatalf("after dropping them the account has %d mailboxes (err %v), want 0", len(mailboxes), err)
	}
}

// installLaggingReplica swaps rdb's read pool for a second pool on the same
// database whose search_path starts with a schema holding copies of the account's
// mailboxes and subscriptions as they are now: a replica that has replayed the
// account, its credentials and its mailboxes up to this call and none written after
// it. The returned function restores the read pool.
func installLaggingReplica(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64) (restore func()) {
	t.Helper()

	ctx := context.Background()
	database := rdb.GetOperationalDatabase()
	schema := fmt.Sprintf("userapi_replica_%d", time.Now().UnixNano())
	if _, err := database.WritePool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create the replica schema: %v", err)
	}
	for _, table := range []string{"mailboxes", "subscriptions"} {
		if _, err := database.WritePool.Exec(ctx, fmt.Sprintf("CREATE TABLE %s.%s AS SELECT * FROM public.%s WHERE account_id = %d", schema, table, table, accountID)); err != nil {
			t.Fatalf("create the replica's %s: %v", table, err)
		}
	}
	poolCfg := database.ReadPool.Config().Copy()
	poolCfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	lagging, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		t.Fatalf("open the replica pool: %v", err)
	}
	original := database.ReadPool
	database.ReadPool = lagging
	return func() {
		database.ReadPool = original
		lagging.Close()
		_, _ = database.WritePool.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	}
}
