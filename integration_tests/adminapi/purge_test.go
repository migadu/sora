//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/adminapi"
	"github.com/migadu/sora/storage"
)

// DELETE /admin/accounts/{email}?purge=true removes an account and everything it holds at
// once. These tests run it against a real database and an in-memory S3, and pin the two
// halves of its contract: on success nothing of the account is left anywhere; on failure
// the account is out of service but still there, with its address, so a retry (or the
// cleaner, after its grace period) can finish the job.

type purgeStack struct {
	*accountLoginsStack
	rdb *resilient.ResilientDatabase
	s3  *common.FakeS3
	st  *storage.S3Storage
}

func setupPurgeStack(t *testing.T) *purgeStack {
	t.Helper()
	common.SkipIfDatabaseUnavailable(t)
	fake, st := common.NewFakeS3Storage(t)
	stack := setupAccountLoginsStack(t, func(o *adminapi.ServerOptions) { o.Storage = st })
	return &purgeStack{accountLoginsStack: stack, rdb: stack.api.rdb, s3: fake, st: st}
}

// purge issues the purge and returns the status and decoded body. It fails the test if the
// request does not come back in time: a purge must end, one way or the other.
func (s *purgeStack) purge(t *testing.T, email string) (int, map[string]any) {
	t.Helper()
	type result struct {
		resp *http.Response
		body []byte
	}
	done := make(chan result, 1)
	go func() {
		resp, body := s.api.makeRequest(t, "DELETE", "/admin/accounts/"+email+"?purge=true", nil)
		done <- result{resp, body}
	}()
	select {
	case r := <-done:
		var decoded map[string]any
		_ = json.Unmarshal(r.body, &decoded)
		return r.resp.StatusCode, decoded
	case <-time.After(90 * time.Second):
		t.Fatalf("purge of %s did not return", email)
		return 0, nil
	}
}

// newMailAccount creates an account with its default mailboxes.
func (s *purgeStack) newMailAccount(t *testing.T, tag, password string) (string, int64) {
	t.Helper()
	email := s.createAccount(t, tag, password)
	ctx := context.Background()
	accountID, err := s.rdb.GetAccountIDByEmailWithRetry(ctx, email)
	if err != nil {
		t.Fatalf("resolve %s: %v", email, err)
	}
	if _, err := s.rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX"); err != nil {
		if err := s.rdb.CreateDefaultMailboxesWithRetry(ctx, accountID); err != nil {
			t.Fatalf("create mailboxes for %s: %v", email, err)
		}
	}
	return email, accountID
}

// addMessage stores one INBOX message. uploaded=true puts its body in S3 and marks the row
// uploaded, as the uploader would; uploaded=false leaves it queued, as delivery does. It
// returns the body's S3 key.
func (s *purgeStack) addMessage(t *testing.T, accountID int64, email, tag string, uploaded bool) string {
	t.Helper()
	ctx := context.Background()
	mailbox, err := s.rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	if err != nil {
		t.Fatalf("INBOX of %s: %v", email, err)
	}
	local, domain, _ := strings.Cut(email, "@")
	body := []byte(fmt.Sprintf("Subject: %s\r\n\r\nbody of %s", tag, tag))
	hash := fmt.Sprintf("purge-%d-%s", accountID, tag)
	key := domain + "/" + local + "/" + hash
	if uploaded {
		if err := s.st.Put(key, bytes.NewReader(body), int64(len(body))); err != nil {
			t.Fatalf("put %s: %v", key, err)
		}
	}
	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
	hostname, _ := os.Hostname()
	id, _, err := s.rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
		AccountID: accountID, MailboxID: mailbox.ID, MailboxName: "INBOX",
		S3Domain: domain, S3Localpart: local, ContentHash: hash,
		MessageID: fmt.Sprintf("<%s-%d@example.com>", tag, accountID), InternalDate: time.Now(),
		Size: int64(len(body)), PlaintextBody: "body of " + tag, BodyStructure: &bs,
	}, db.PendingUpload{InstanceID: hostname, ContentHash: hash, Size: int64(len(body)), AccountID: accountID})
	if err != nil {
		t.Fatalf("insert %s: %v", tag, err)
	}
	if uploaded {
		if _, err := s.rdb.ExecWithRetry(ctx, `UPDATE messages SET uploaded = TRUE WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := s.rdb.ExecWithRetry(ctx, `DELETE FROM pending_uploads WHERE account_id = $1 AND content_hash = $2`, accountID, hash); err != nil {
			t.Fatal(err)
		}
	}
	return key
}

func (s *purgeStack) count(t *testing.T, table string, accountID int64) int {
	t.Helper()
	column := "account_id"
	if table == "accounts" {
		column = "id"
	}
	var n int
	if err := s.rdb.QueryRowWithRetry(context.Background(), `SELECT count(*) FROM `+table+` WHERE `+column+` = $1`, accountID).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// requireGone asserts that nothing of the account is left, in the database or in S3.
func (s *purgeStack) requireGone(t *testing.T, accountID int64, email string) {
	t.Helper()
	for _, table := range []string{"accounts", "credentials", "messages", "mailboxes", "pending_uploads", "sieve_scripts", "messages_fts_v2"} {
		if n := s.count(t, table, accountID); n != 0 {
			t.Errorf("%d %s rows left for the purged account", n, table)
		}
	}
	local, domain, _ := strings.Cut(email, "@")
	if keys := s.s3.Keys(domain + "/" + local + "/"); len(keys) != 0 {
		t.Errorf("S3 objects left for the purged account: %v", keys)
	}
}

// requireRetryable asserts the state a failed purge must leave: the account is out of
// service, and still has its address, so the purge can be run again.
func (s *purgeStack) requireRetryable(t *testing.T, accountID int64, email string) {
	t.Helper()
	id, err := s.rdb.GetAccountIDByEmailWithRetry(context.Background(), email)
	if err != nil || id != accountID {
		t.Fatalf("after a failed purge the account must still resolve by its address: id=%d err=%v", id, err)
	}
	var deleted bool
	if err := s.rdb.QueryRowWithRetry(context.Background(), `SELECT deleted_at IS NOT NULL FROM accounts WHERE id = $1`, accountID).Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("after a failed purge the account must be out of service (soft-deleted)")
	}
}

func TestAdminAPI_PurgeAccount_RemovesEverything(t *testing.T) {
	s := setupPurgeStack(t)
	const password = "purge-pass-1"
	email, accountID := s.newMailAccount(t, "purge", password)
	for i := 0; i < 3; i++ {
		s.addMessage(t, accountID, email, fmt.Sprintf("up%d", i), true)
	}
	s.addMessage(t, accountID, email, "queued", false) // body not in S3 yet
	open := s.mustLogin(t, email, password)

	status, body := s.purge(t, email)
	if status != http.StatusOK {
		t.Fatalf("purge: %d %v", status, body)
	}
	if got, _ := body["s3_objects_deleted"].(float64); got < 3 {
		t.Errorf("s3_objects_deleted = %v, want at least 3", body["s3_objects_deleted"])
	}
	if got, _ := body["messages_deleted"].(float64); got != 4 {
		t.Errorf("messages_deleted = %v, want 4", body["messages_deleted"])
	}

	s.requireGone(t, accountID, email)
	waitClosed(t, open, "a purged account's open session")
	if _, err := s.login(t, email, password); err == nil {
		t.Error("a purged account can still sign in")
	}
	if resp, _ := s.api.makeRequest(t, "POST", "/admin/accounts/"+email+"/restore", nil); resp.StatusCode == http.StatusOK {
		t.Error("a purged account was restored")
	}
}

// A soft-deleted account is purged the same way: a purge is how an operator skips the
// grace period of an earlier delete.
func TestAdminAPI_PurgeAccount_AlreadySoftDeleted(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "purge-soft", "purge-pass-2")
	s.addMessage(t, accountID, email, "m", true)
	s.request(t, "DELETE", "/admin/accounts/"+email, nil, http.StatusOK)

	if status, body := s.purge(t, email); status != http.StatusOK {
		t.Fatalf("purge of a soft-deleted account: %d %v", status, body)
	}
	s.requireGone(t, accountID, email)
}

func TestAdminAPI_PurgeAccount_UnknownAccount(t *testing.T) {
	s := setupPurgeStack(t)
	if status, body := s.purge(t, fmt.Sprintf("nobody-%d@example.com", time.Now().UnixNano())); status != http.StatusNotFound {
		t.Fatalf("purge of an unknown account: %d %v, want 404", status, body)
	}
}

// Without object storage the bodies cannot be removed, so the purge is refused before it
// touches the account at all.
func TestAdminAPI_PurgeAccount_NoStorage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	stack := setupAccountLoginsStack(t)
	s := &purgeStack{accountLoginsStack: stack, rdb: stack.api.rdb}
	email, accountID := s.newMailAccount(t, "purge-nostorage", "purge-pass-3")

	if status, body := s.purge(t, email); status != http.StatusServiceUnavailable {
		t.Fatalf("purge without storage: %d %v, want 503", status, body)
	}
	var deleted bool
	if err := s.rdb.QueryRowWithRetry(context.Background(), `SELECT deleted_at IS NOT NULL FROM accounts WHERE id = $1`, accountID).Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	if deleted {
		t.Error("a refused purge took the account out of service")
	}
}

// A plain DELETE keeps its meaning: soft delete, restorable.
func TestAdminAPI_DeleteAccount_WithoutPurgeIsRestorable(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "softonly", "purge-pass-4")
	s.addMessage(t, accountID, email, "kept", true)

	s.request(t, "DELETE", "/admin/accounts/"+email, nil, http.StatusOK)
	s.request(t, "POST", "/admin/accounts/"+email+"/restore", nil, http.StatusOK)
	if n := s.count(t, "messages", accountID); n != 1 {
		t.Fatalf("a soft delete removed messages: %d left, want 1", n)
	}
}

// When S3 refuses the deletes, the purge fails instead of retrying forever, and leaves the
// account soft-deleted and findable; once S3 is back, the same request finishes the job.
func TestAdminAPI_PurgeAccount_S3FailureIsRetryable(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "purge-s3fail", "purge-pass-5")
	keys := []string{s.addMessage(t, accountID, email, "a", true), s.addMessage(t, accountID, email, "b", true)}

	s.s3.FailDeletes(true)
	if status, body := s.purge(t, email); status != http.StatusInternalServerError {
		t.Fatalf("purge with S3 refusing deletes: %d %v, want 500", status, body)
	}
	s.requireRetryable(t, accountID, email)
	local, domain, _ := strings.Cut(email, "@")
	if left := s.s3.Keys(domain + "/" + local + "/"); len(left) != len(keys) {
		t.Fatalf("S3 refused every delete, yet objects changed: %v", left)
	}

	s.s3.FailDeletes(false)
	if status, body := s.purge(t, email); status != http.StatusOK {
		t.Fatalf("retried purge: %d %v", status, body)
	}
	s.requireGone(t, accountID, email)
}

// An upload in flight holds the body's advisory lock (the uploader takes it across its PUT
// and the row update). The purge must not delete that body under it, and must not wait
// for it forever either: it gives up after a bounded wait and a retry completes.
func TestAdminAPI_PurgeAccount_UploadInFlightIsRetryable(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "purge-locked", "purge-pass-6")
	s.addMessage(t, accountID, email, "free", true)
	lockedKey := s.addMessage(t, accountID, email, "busy", true)
	hash := lockedKey[strings.LastIndex(lockedKey, "/")+1:]

	ctx := context.Background()
	tx, err := s.rdb.BeginTxWithRetry(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, db.GetS3ObjectLockID(accountID, hash)); err != nil {
		t.Fatal(err)
	}

	status, body := s.purge(t, email)
	if status != http.StatusInternalServerError {
		_ = tx.Rollback(ctx)
		t.Fatalf("purge while an upload holds a body's lock: %d %v, want 500", status, body)
	}
	if len(s.s3.Keys(lockedKey)) != 1 {
		t.Error("the purge deleted a body while its upload held the lock")
	}
	s.requireRetryable(t, accountID, email)

	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if status, body := s.purge(t, email); status != http.StatusOK {
		t.Fatalf("retried purge: %d %v", status, body)
	}
	s.requireGone(t, accountID, email)
}

// A message that lands in the account while the purge runs (a delivery that passed its
// recipient check just before the account went out of service) is purged too: it neither
// survives the purge nor keeps the purge going forever.
func TestAdminAPI_PurgeAccount_MessageArrivingMidPurge(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "purge-late", "purge-pass-7")
	s.addMessage(t, accountID, email, "early", true)

	arrived := false
	s.s3.OnDelete(func([]string) {
		if arrived {
			return
		}
		arrived = true
		s.addLiveDetachedMessage(t, accountID, email, "late")
	})
	defer s.s3.OnDelete(nil)

	if status, body := s.purge(t, email); status != http.StatusOK {
		t.Fatalf("purge with a message arriving midway: %d %v", status, body)
	}
	if !arrived {
		t.Fatal("test bug: the late message was never added")
	}
	s.requireGone(t, accountID, email)
}

// Mail that keeps arriving cannot keep a purge running: it stops after a bounded number of
// passes, without deleting the body of a message that is still live, and leaves the
// account retryable.
func TestAdminAPI_PurgeAccount_MessagesKeepArriving(t *testing.T) {
	s := setupPurgeStack(t)
	email, accountID := s.newMailAccount(t, "purge-stream", "purge-pass-8")
	s.addMessage(t, accountID, email, "first", true)

	n := 0
	s.s3.OnDelete(func([]string) {
		n++
		s.addLiveDetachedMessage(t, accountID, email, fmt.Sprintf("stream%d", n))
	})

	status, body := s.purge(t, email)
	s.s3.OnDelete(nil)
	if status != http.StatusInternalServerError {
		t.Fatalf("purge against a stream of new mail: %d %v, want 500", status, body)
	}
	s.requireRetryable(t, accountID, email)
	rows, err := s.rdb.QueryWithRetry(context.Background(),
		`SELECT s3_domain || '/' || s3_localpart || '/' || content_hash FROM messages WHERE account_id = $1 AND expunged_at IS NULL AND uploaded`, accountID)
	if err != nil {
		t.Fatal(err)
	}
	var live []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			t.Fatal(err)
		}
		live = append(live, key)
	}
	rows.Close()
	if len(live) == 0 {
		t.Fatal("test bug: no live message left to check")
	}
	for _, key := range live {
		if len(s.s3.Keys(key)) != 1 {
			t.Errorf("the purge deleted the body of live message %s", key)
		}
	}

	if status, body := s.purge(t, email); status != http.StatusOK {
		t.Fatalf("retried purge: %d %v", status, body)
	}
	s.requireGone(t, accountID, email)
}

// addLiveDetachedMessage adds an uploaded, unexpunged message to the account with no
// mailbox, copied from one of its rows: by the time a late write could land, the purge may
// already have removed the account's mailboxes, and messages.mailbox_id is ON DELETE SET
// NULL, so a row with no mailbox is the shape a straggler has.
func (s *purgeStack) addLiveDetachedMessage(t *testing.T, accountID int64, email, tag string) {
	t.Helper()
	ctx := context.Background()
	local, domain, _ := strings.Cut(email, "@")
	hash := fmt.Sprintf("purge-%d-%s", accountID, tag)
	body := []byte("late body " + tag)
	if err := s.st.Put(domain+"/"+local+"/"+hash, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Errorf("put late body: %v", err)
		return
	}
	_, err := s.rdb.ExecWithRetry(ctx, `
		INSERT INTO messages
		SELECT (jsonb_populate_record(NULL::messages, to_jsonb(m) || jsonb_build_object(
			'id', nextval(pg_get_serial_sequence('messages', 'id')),
			'mailbox_id', NULL, 'content_hash', $2::text, 'message_id', $3::text,
			'expunged_at', NULL, 'expunged_modseq', NULL, 'uploaded', true))).*
		FROM messages m WHERE m.account_id = $1
		ORDER BY m.id LIMIT 1`, accountID, hash, "<"+tag+"@example.com>")
	if err != nil {
		t.Errorf("insert late message: %v", err)
	}
}
