//go:build integration

package userapi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/server/userapi"
	"github.com/migadu/sora/storage"
)

// The User API must tell the three states of a message body apart the way IMAP and
// POP3 do: available (200), on its way (503 + Retry-After), gone (410). It once
// answered every miss with 500, so a message delivered seconds ago on another node was
// indistinguishable from permanent loss.

type bodyStateHarness struct {
	tc        *TestContext
	rdb       *resilient.ResilientDatabase
	s3        *storage.S3Storage
	up        *uploader.UploadWorker
	accountID int64
	inbox     *db.DBMailbox
}

func newBodyStateHarness(t *testing.T) *bodyStateHarness {
	t.Helper()
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	_, s3 := common.NewFakeS3Storage(t)

	// This node's uploader, never started: it lends its spool path and max_attempts.
	errCh := make(chan error, 8)
	up, err := uploader.New(ctx, t.TempDir(), 10, 1, 3, time.Second, 0, "this-node", rdb, s3, nil, errCh)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := userapi.New(rdb, userapi.ServerOptions{
		Name: "body-state", Addr: "127.0.0.1:0", JWTSecret: "test-secret-key-for-testing-only",
		TokenDuration: time.Hour, TokenIssuer: "test-issuer", AllowedOrigins: []string{"*"},
		Storage: s3, Cache: nil, Uploader: up, TLS: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.SetupRoutes())
	t.Cleanup(ts.Close)
	tc := &TestContext{Server: ts, RDB: rdb, HTTPClient: ts.Client(), TestUser: account}

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, "INBOX")
	if err != nil {
		t.Fatal(err)
	}

	resp := tc.makeRequest(t, "POST", "/user/auth/login", map[string]string{"email": account.Email, "password": account.Password})
	var login map[string]any
	parseJSON(t, resp, &login)
	tc.JWTToken, _ = login["token"].(string)
	if tc.JWTToken == "" {
		t.Fatalf("no token in login response: %v", login)
	}
	return &bodyStateHarness{tc: tc, rdb: rdb, s3: s3, up: up, accountID: accountID, inbox: inbox}
}

// insert stores a message row (uploaded=false, pending upload owned by instance) and
// returns its id and content hash.
func (h *bodyStateHarness) insert(t *testing.T, body []byte, instance string) (int64, string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	hash := fmt.Sprintf("%064x", now.UnixNano())
	id, _, err := h.rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
		AccountID: h.accountID, MailboxID: h.inbox.ID, MailboxName: "INBOX",
		S3Domain: "example.com", S3Localpart: "user", ContentHash: hash,
		MessageID: fmt.Sprintf("<%s@example.com>", hash[:16]), Flags: []imap.Flag{},
		InternalDate: now, Size: int64(len(body)), Subject: "body state", PlaintextBody: "x", SentDate: now,
	}, db.PendingUpload{AccountID: h.accountID, ContentHash: hash, InstanceID: instance, Size: int64(len(body)), CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	return id, hash
}

func (h *bodyStateHarness) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := h.rdb.GetOperationalDatabase().GetWritePool().Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func (h *bodyStateHarness) getRaw(t *testing.T, id int64) (int, string, []byte) {
	t.Helper()
	resp := h.tc.makeRequest(t, "GET", fmt.Sprintf("/user/messages/%d/raw", id), nil)
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Retry-After"), data
}

func TestUserAPI_BodyStates(t *testing.T) {
	h := newBodyStateHarness(t)
	body := []byte("Subject: state\r\n\r\nhello\r\n")

	t.Run("pending on another node → 503 with Retry-After", func(t *testing.T) {
		id, _ := h.insert(t, body, "other-node")
		code, retry, _ := h.getRaw(t, id)
		if code != http.StatusServiceUnavailable || retry == "" {
			t.Fatalf("got %d Retry-After=%q, want 503 with Retry-After", code, retry)
		}
	})

	t.Run("staged in this node's spool → 200 before the upload", func(t *testing.T) {
		id, hash := h.insert(t, body, "this-node")
		if _, err := h.up.StoreLocally(hash, h.accountID, body); err != nil {
			t.Fatal(err)
		}
		code, _, got := h.getRaw(t, id)
		if code != http.StatusOK || !bytes.Equal(got, body) {
			t.Fatalf("got %d %q, want 200 with the body", code, got)
		}
	})

	t.Run("uploaded and in S3 → 200", func(t *testing.T) {
		id, hash := h.insert(t, body, "other-node")
		if err := h.s3.Put(helpers.NewS3Key("example.com", "user", hash), bytes.NewReader(body), int64(len(body))); err != nil {
			t.Fatal(err)
		}
		h.exec(t, `UPDATE messages SET uploaded = TRUE WHERE id = $1`, id)
		h.exec(t, `DELETE FROM pending_uploads WHERE account_id = $1 AND content_hash = $2`, h.accountID, hash)
		code, _, got := h.getRaw(t, id)
		if code != http.StatusOK || !bytes.Equal(got, body) {
			t.Fatalf("got %d %q, want 200 with the body", code, got)
		}
	})

	t.Run("upload given up on, nothing anywhere → 410", func(t *testing.T) {
		id, hash := h.insert(t, body, "this-node")
		h.exec(t, `UPDATE pending_uploads SET attempts = 3 WHERE account_id = $1 AND content_hash = $2`, h.accountID, hash)
		code, _, _ := h.getRaw(t, id)
		if code != http.StatusGone {
			t.Fatalf("got %d, want 410 for a body the uploader has given up on", code)
		}
	})

	t.Run("marked uploaded but object missing → 410, not 500", func(t *testing.T) {
		id, hash := h.insert(t, body, "other-node")
		h.exec(t, `UPDATE messages SET uploaded = TRUE WHERE id = $1`, id)
		h.exec(t, `DELETE FROM pending_uploads WHERE account_id = $1 AND content_hash = $2`, h.accountID, hash)
		code, _, _ := h.getRaw(t, id)
		if code != http.StatusGone {
			t.Fatalf("got %d, want 410 for a NoSuchKey on an uploaded row", code)
		}
	})
}
