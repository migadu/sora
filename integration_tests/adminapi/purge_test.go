//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/adminapi"
	"github.com/migadu/sora/storage"
)

// Shared setup for the account purge tests: a real database, an in-memory S3, and an
// IMAP backend plus Admin API on top. The request side of a purge is covered in
// purge_queue_test.go, the purge worker in purge_worker_test.go; the helpers here pin the
// two halves of the contract: on success nothing of the account is left anywhere; on
// failure the account is out of service but still there, with its address, so a retry
// can finish the job.

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
