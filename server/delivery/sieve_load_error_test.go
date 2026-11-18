package delivery

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server"
)

// The Admin API path must not deliver with the default script alone when the user's
// active script could not be read: ExecuteSieve fails, which the caller answers as a
// transient error. An account without an active script still delivers to INBOX.
// The read is made to fail for one account only: an updated_at of 'infinity' cannot be
// scanned into a time.Time.
func TestExecuteSieve_ActiveScriptLoadErrorFails(t *testing.T) {
	rdb := setupDeliveryTestDatabase(t)
	ctx := context.Background()

	execute := func(t *testing.T, accountID int64, email string) (*SieveOutcome, error) {
		t.Helper()
		toAddr, err := server.NewAddress(email)
		if err != nil {
			t.Fatalf("NewAddress: %v", err)
		}
		raw := []byte("From: sender@example.com\r\nTo: " + email + "\r\nSubject: load error\r\n\r\nHello.\r\n")
		entity, err := server.ParseMessage(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("ParseMessage: %v", err)
		}
		exec := &StandardSieveExecutor{DeliveryCtx: &DeliveryContext{
			Ctx: ctx, RDB: rdb, Hostname: "mx.example.com", MetricsLabel: "http_delivery", Logger: nopDeliveryLogger{},
		}}
		return exec.ExecuteSieve(ctx, RecipientInfo{AccountID: accountID, Address: &toAddr, ToAddress: &toAddr}, entity, raw)
	}
	newAccount := func(t *testing.T, prefix string) (int64, string) {
		t.Helper()
		email := fmt.Sprintf("%s-%d@example.com", prefix, time.Now().UnixNano())
		accountID, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
			Email: email, Password: "testpassword123", IsPrimary: true, HashType: "bcrypt",
		})
		if err != nil {
			t.Fatalf("CreateAccountWithRetry: %v", err)
		}
		if err := rdb.CreateDefaultMailboxesWithRetry(ctx, accountID); err != nil {
			t.Fatalf("CreateDefaultMailboxesWithRetry: %v", err)
		}
		return accountID, email
	}

	t.Run("unreadable active script", func(t *testing.T) {
		accountID, email := newAccount(t, "sieve-load-error")
		sc, err := rdb.CreateScriptWithRetry(ctx, accountID, "unreadable", `require ["fileinto"]; fileinto "Elsewhere";`)
		if err != nil {
			t.Fatalf("CreateScriptWithRetry: %v", err)
		}
		if err := rdb.SetScriptActiveWithRetry(ctx, sc.ID, accountID, true); err != nil {
			t.Fatalf("SetScriptActiveWithRetry: %v", err)
		}
		if _, err := rdb.GetDatabase().GetWritePool().Exec(ctx,
			`UPDATE sieve_scripts SET updated_at = 'infinity' WHERE id = $1`, sc.ID); err != nil {
			t.Fatalf("break updated_at: %v", err)
		}
		if _, err := rdb.GetActiveScriptWithRetry(ctx, accountID); err == nil || err == consts.ErrDBNotFound {
			t.Fatalf("the active script read must fail with a database error, got %v", err)
		}

		outcome, err := execute(t, accountID, email)
		if err == nil {
			t.Fatalf("ExecuteSieve delivered with the default script only (mailbox %q); want an error", outcome.MailboxName)
		}
	})

	t.Run("no active script", func(t *testing.T) {
		accountID, email := newAccount(t, "sieve-no-script")
		outcome, err := execute(t, accountID, email)
		if err != nil {
			t.Fatalf("ExecuteSieve: %v", err)
		}
		if outcome.Discarded || outcome.MailboxName != consts.MailboxInbox {
			t.Fatalf("outcome = mailbox %q discarded %v, want INBOX", outcome.MailboxName, outcome.Discarded)
		}
	})
}
