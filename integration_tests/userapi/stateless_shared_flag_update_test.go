//go:build integration

package userapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// TestUserAPI_SharedMailbox_StatelessMessageFlagUpdateWithoutWriteRight proves that
// PATCH /user/messages/{id} (e.g. 'lrs' marking \Seen) and DELETE /user/messages/{id}
// (e.g. 'lrst' marking \Deleted) on a historical shared-mailbox message missing its
// message_state row answer 200 OK instead of HTTP 500 (PostgreSQL SQLSTATE 22023 on
// max_custom_flags_check from marshaling nil storedCustomFlags as 'null'::jsonb), seed
// message_state with custom_flags = '[]'::jsonb, and keep mailbox unseen counts accurate.
func TestUserAPI_SharedMailbox_StatelessMessageFlagUpdateWithoutWriteRight(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	owner := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	sharedCtx := context.WithValue(ctx, consts.ConfigContextKey, &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/"},
	})

	ownerID, err := rdb.GetAccountIDByAddressWithRetry(ctx, owner.Email)
	if err != nil {
		t.Fatalf("owner id: %v", err)
	}

	domain := strings.Split(owner.Email, "@")[1]
	granteeEmail := fmt.Sprintf("grantee-stateless-%d@%s", common.GetTimestamp(), domain)
	const granteePassword = "grantee-pass-123"
	if _, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email: granteeEmail, Password: granteePassword, HashType: "bcrypt", IsPrimary: true,
	}); err != nil {
		t.Fatalf("create grantee: %v", err)
	}

	sharedName := fmt.Sprintf("Shared/Stateless-%d", common.GetTimestamp())
	if err := rdb.CreateMailboxWithRetry(sharedCtx, ownerID, sharedName, nil); err != nil {
		t.Fatalf("create shared mailbox: %v", err)
	}
	mbox, err := rdb.GetMailboxByNameWithRetry(sharedCtx, ownerID, sharedName)
	if err != nil {
		t.Fatalf("get shared mailbox: %v", err)
	}

	pool := rdb.GetOperationalDatabase().GetWritePool()
	seq := 0
	insertStateless := func(t *testing.T, subject string) int64 {
		t.Helper()
		seq++
		now := time.Now()
		hash := fmt.Sprintf("%064x", now.UnixNano()+int64(seq))
		id, _, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID: ownerID, MailboxID: mbox.ID, MailboxName: sharedName,
			S3Domain: domain, S3Localpart: "owner", ContentHash: hash,
			MessageID: fmt.Sprintf("<%s-%d@%s>", subject, seq, domain),
			Flags:     []imap.Flag{}, InternalDate: now, Size: 128,
			Subject: subject, PlaintextBody: "body", SentDate: now,
		}, db.PendingUpload{
			AccountID: ownerID, ContentHash: hash, InstanceID: "test-node",
			Size: 128, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			t.Fatalf("insert message: %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM message_state WHERE message_id = $1`, id); err != nil {
			t.Fatalf("delete message_state: %v", err)
		}
		return id
	}

	ts := newUserAPITestServer(t, rdb)
	client := ts.Client()
	token := h2Login(t, ts, client, granteeEmail, granteePassword)

	t.Run("PATCH Seen with lrs seeds state and returns 200", func(t *testing.T) {
		if err := rdb.GrantMailboxAccessByIdentifierWithRetry(sharedCtx, ownerID, granteeEmail, sharedName, "lrs"); err != nil {
			t.Fatalf("grant 'lrs': %v", err)
		}
		msgID := insertStateless(t, "stateless-seen")
		path := fmt.Sprintf("/user/messages/%d", msgID)

		code, body := apiDo(t, ts, client, token, "PATCH", path, map[string]any{
			"add_flags": []string{`\Seen`, "$label1"},
		})
		if code != http.StatusOK {
			t.Fatalf("PATCH %s with 'lrs': got %d (%s), want 200", path, code, body)
		}

		code, getBody := h2Get(t, ts, client, token, path)
		if code != http.StatusOK {
			t.Fatalf("GET %s: got %d (%s), want 200", path, code, getBody)
		}
		var m apiMessage
		if err := json.Unmarshal([]byte(getBody), &m); err != nil {
			t.Fatalf("decode message: %v (%s)", err, getBody)
		}
		if !slices.Contains(m.Flags, `\Seen`) {
			t.Errorf("flags = %v, want \\Seen", m.Flags)
		}
		if len(m.CustomFlags) != 0 {
			t.Errorf("custom_flags = %v, want empty (no 'w' right)", m.CustomFlags)
		}

		mb, found := h2MailboxEntry(t, ts, client, token, sharedName)
		if !found || mb.Total != 1 || mb.Unseen != 0 {
			t.Errorf("mailbox entry after PATCH \\Seen: found=%v total=%d unseen=%d, want true, 1, 0",
				found, mb.Total, mb.Unseen)
		}
	})

	t.Run("DELETE with lrst seeds state, sets Deleted, and keeps unseen accurate", func(t *testing.T) {
		if err := rdb.GrantMailboxAccessByIdentifierWithRetry(sharedCtx, ownerID, granteeEmail, sharedName, "lrst"); err != nil {
			t.Fatalf("grant 'lrst': %v", err)
		}
		msgID := insertStateless(t, "stateless-delete")
		path := fmt.Sprintf("/user/messages/%d", msgID)

		code, body := apiDo(t, ts, client, token, "DELETE", path, nil)
		if code != http.StatusOK {
			t.Fatalf("DELETE %s with 'lrst': got %d (%s), want 200", path, code, body)
		}

		code, getBody := h2Get(t, ts, client, token, path)
		if code != http.StatusOK {
			t.Fatalf("GET %s: got %d (%s), want 200", path, code, getBody)
		}
		var m apiMessage
		if err := json.Unmarshal([]byte(getBody), &m); err != nil {
			t.Fatalf("decode message: %v (%s)", err, getBody)
		}
		if !slices.Contains(m.Flags, `\Deleted`) {
			t.Errorf("flags = %v, want \\Deleted", m.Flags)
		}
		if len(m.CustomFlags) != 0 {
			t.Errorf("custom_flags = %v, want empty", m.CustomFlags)
		}

		mb, found := h2MailboxEntry(t, ts, client, token, sharedName)
		if !found || mb.Total != 2 || mb.Unseen != 1 {
			t.Errorf("mailbox entry after DELETE: found=%v total=%d unseen=%d, want true, 2, 1",
				found, mb.Total, mb.Unseen)
		}
	})
}
