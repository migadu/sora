//go:build integration

package userapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	imap "github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// TestUserAPIMailboxWritesAgainstLaggingReplica verifies that User API mailbox
// writes (subscribe, unsubscribe, delete) and post-write message flag responses
// resolve state on the writer rather than failing with 404 or returning stale
// flags when the read replica has not yet replayed recent writes.
func TestUserAPIMailboxWritesAgainstLaggingReplica(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	t.Run("default mailboxes created on login", func(t *testing.T) {
		rdb := common.SetupTestDatabase(t)
		api := startDefaultMailboxesAPI(t, rdb, nil)
		accountID, email, password := createAccountWithoutMailboxes(t, rdb)
		restore := installLaggingReplica(t, rdb, accountID)
		defer restore()

		api.JWTToken = api.loginFor(t, email, password)

		// Control: replica still has 0 mailboxes while writer holds the defaults.
		ctx := context.Background()
		replica, err := rdb.GetMailboxesForUserWithRetry(ctx, accountID, false)
		if err != nil {
			t.Fatalf("list mailboxes on replica: %v", err)
		}
		if len(replica) != 0 {
			t.Fatalf("replica has %d mailboxes, want 0", len(replica))
		}

		for _, endpoint := range []struct {
			method string
			path   string
		}{
			{http.MethodPost, "/user/mailboxes/Archive/unsubscribe"},
			{http.MethodPost, "/user/mailboxes/Archive/subscribe"},
			{http.MethodDelete, "/user/mailboxes/Archive"},
		} {
			resp := api.makeRequest(t, endpoint.method, endpoint.path, nil)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s %s: status %d, want %d (body: %s)", endpoint.method, endpoint.path, resp.StatusCode, http.StatusOK, string(body))
			}
		}

		listed := api.listMailboxes(t)
		if listed["Archive"] {
			t.Fatalf("GET /user/mailboxes still lists Archive after DELETE")
		}
		if len(listed) != len(consts.DefaultMailboxes)-1 {
			t.Fatalf("GET /user/mailboxes lists %d mailboxes, want %d", len(listed), len(consts.DefaultMailboxes)-1)
		}
	})

	t.Run("mailbox created via API on existing account", func(t *testing.T) {
		rdb := common.SetupTestDatabase(t)
		api := startDefaultMailboxesAPI(t, rdb, nil)
		accountID, email, password := createAccountWithoutMailboxes(t, rdb)

		// Provision the default mailboxes before taking the replica snapshot so
		// this account already has INBOX on the replica.
		api.JWTToken = api.loginFor(t, email, password)
		restore := installLaggingReplica(t, rdb, accountID)
		defer restore()

		resp := api.makeRequest(t, http.MethodPost, "/user/mailboxes", map[string]string{"name": "Projects"})
		createBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("POST /user/mailboxes: status %d, want %d (body: %s)", resp.StatusCode, http.StatusCreated, string(createBody))
		}

		ctx := context.Background()
		writerCtx := context.WithValue(ctx, consts.UseMasterDBKey, true)
		if _, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "Projects"); !errors.Is(err, consts.ErrMailboxNotFound) {
			t.Fatalf("replica lookup for Projects got err=%v, want ErrMailboxNotFound", err)
		}

		resp = api.makeRequest(t, http.MethodPost, "/user/mailboxes/Projects/subscribe", nil)
		subBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /user/mailboxes/Projects/subscribe: status %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, string(subBody))
		}
		subs, err := rdb.GetSubscribedMailboxNamesWithRetry(writerCtx, accountID)
		if err != nil {
			t.Fatalf("list writer subscriptions: %v", err)
		}
		if !slices.ContainsFunc(subs, func(n string) bool { return strings.EqualFold(n, "Projects") }) {
			t.Fatalf("writer subscriptions %v do not contain Projects after subscribe", subs)
		}

		resp = api.makeRequest(t, http.MethodPost, "/user/mailboxes/Projects/unsubscribe", nil)
		unsubBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /user/mailboxes/Projects/unsubscribe: status %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, string(unsubBody))
		}
		subs, err = rdb.GetSubscribedMailboxNamesWithRetry(writerCtx, accountID)
		if err != nil {
			t.Fatalf("list writer subscriptions: %v", err)
		}
		if slices.ContainsFunc(subs, func(n string) bool { return strings.EqualFold(n, "Projects") }) {
			t.Fatalf("writer subscriptions %v still contain Projects after unsubscribe", subs)
		}

		resp = api.makeRequest(t, http.MethodDelete, "/user/mailboxes/Projects", nil)
		delBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("DELETE /user/mailboxes/Projects: status %d, want %d (body: %s)", resp.StatusCode, http.StatusOK, string(delBody))
		}
		if _, err := rdb.GetMailboxByNameWithRetry(writerCtx, accountID, "Projects"); !errors.Is(err, consts.ErrMailboxNotFound) {
			t.Fatalf("writer lookup for Projects after DELETE got err=%v, want ErrMailboxNotFound", err)
		}
	})

	t.Run("patch message flags reads updated message from writer", func(t *testing.T) {
		rdb := common.SetupTestDatabase(t)
		api := startDefaultMailboxesAPI(t, rdb, nil)
		accountID, email, password := createAccountWithoutMailboxes(t, rdb)
		api.JWTToken = api.loginFor(t, email, password)

		ctx := context.Background()
		inbox, err := rdb.GetMailboxByNameWithRetry(context.WithValue(ctx, consts.UseMasterDBKey, true), accountID, "INBOX")
		if err != nil {
			t.Fatalf("lookup INBOX on writer: %v", err)
		}

		now := time.Now()
		hash := fmt.Sprintf("%064x", now.UnixNano())
		msgID, _, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID: accountID, MailboxID: inbox.ID, MailboxName: "INBOX",
			S3Domain: "example.com", S3Localpart: "user", ContentHash: hash,
			MessageID: fmt.Sprintf("<%s@example.com>", hash[:16]), Flags: []imap.Flag{},
			InternalDate: now, Size: 16, Subject: "replica lag flags", PlaintextBody: "x", SentDate: now,
		}, db.PendingUpload{AccountID: accountID, ContentHash: hash, InstanceID: "test-node", Size: 16, CreatedAt: now, UpdatedAt: now})
		if err != nil {
			t.Fatalf("insert test message: %v", err)
		}

		// Snapshot mailboxes, messages and message_state before the PATCH so the
		// replica still holds the pre-PATCH flags.
		database := rdb.GetOperationalDatabase()
		schema := fmt.Sprintf("userapi_msg_replica_%d", time.Now().UnixNano())
		if _, err := database.WritePool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
			t.Fatalf("create replica schema: %v", err)
		}
		defer database.WritePool.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
		for _, stmt := range []string{
			fmt.Sprintf("CREATE TABLE %s.mailboxes AS SELECT * FROM public.mailboxes WHERE account_id = %d", schema, accountID),
			fmt.Sprintf("CREATE TABLE %s.messages AS SELECT * FROM public.messages WHERE account_id = %d", schema, accountID),
			fmt.Sprintf("CREATE TABLE %s.message_state AS SELECT ms.* FROM public.message_state ms JOIN public.messages m ON m.id = ms.message_id WHERE m.account_id = %d", schema, accountID),
		} {
			if _, err := database.WritePool.Exec(ctx, stmt); err != nil {
				t.Fatalf("populate replica schema: %v", err)
			}
		}
		poolCfg := database.ReadPool.Config().Copy()
		poolCfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
		lagging, err := pgxpool.NewWithConfig(ctx, poolCfg)
		if err != nil {
			t.Fatalf("open lagging pool: %v", err)
		}
		original := database.ReadPool
		database.ReadPool = lagging
		defer func() {
			database.ReadPool = original
			lagging.Close()
		}()

		resp := api.makeRequest(t, http.MethodPatch, fmt.Sprintf("/user/messages/%d", msgID), map[string]any{
			"add_flags": []string{"\\Seen", "\\Flagged", "Work"},
		})
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("PATCH /user/messages/%d: status %d, want 200 (body: %s)", msgID, resp.StatusCode, string(body))
		}
		var patchResp struct {
			Data *db.DBMessage `json:"data"`
		}
		parseJSON(t, resp, &patchResp)
		if patchResp.Data == nil {
			t.Fatalf("PATCH /user/messages/%d returned no data", msgID)
		}
		if !slices.Contains(patchResp.Data.Flags, "\\Seen") || !slices.Contains(patchResp.Data.Flags, "\\Flagged") {
			t.Fatalf("PATCH response flags = %v, want \\Seen and \\Flagged", patchResp.Data.Flags)
		}
		if !slices.Contains(patchResp.Data.CustomFlags, "Work") {
			t.Fatalf("PATCH response custom_flags = %v, want Work", patchResp.Data.CustomFlags)
		}
	})
}
