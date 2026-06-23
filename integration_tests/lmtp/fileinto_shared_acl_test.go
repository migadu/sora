//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// TestLMTP_FileintoSharedMailbox_RequiresInsertRight verifies that a SIEVE
// `fileinto` into another account's shared mailbox is honored only when the
// recipient holds the 'i' (insert) right; with only 'l' (lookup) the message
// falls back to the recipient's INBOX rather than being written to a mailbox the
// user can merely see (RFC 4314 / audit finding L4).
func TestLMTP_FileintoSharedMailbox_RequiresInsertRight(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// IMAP server (shared mailboxes enabled) gives us rdb + the recipient account A.
	imapSrv, accountA := common.SetupIMAPServer(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	// Owner B (same domain) creates the shared mailbox via IMAP (sets is_shared).
	domain := strings.Split(accountA.Email, "@")[1]
	ownerEmail := fmt.Sprintf("owner-%d@%s", common.GetTimestamp(), domain)
	const ownerPassword = "owner-pass-123"
	if _, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email:     ownerEmail,
		Password:  ownerPassword,
		HashType:  "bcrypt",
		IsPrimary: true,
	}); err != nil {
		t.Fatalf("create owner: %v", err)
	}

	sharedMailbox := fmt.Sprintf("Shared/L4-%d", common.GetTimestamp())
	bc, err := imapclient.DialInsecure(imapSrv.Address, nil)
	if err != nil {
		t.Fatalf("owner dial: %v", err)
	}
	if err := bc.Login(ownerEmail, ownerPassword).Wait(); err != nil {
		t.Fatalf("owner login: %v", err)
	}
	if err := bc.Create(sharedMailbox, nil).Wait(); err != nil {
		t.Fatalf("create shared mailbox: %v", err)
	}
	_ = bc.Logout()

	ownerID, err := rdb.GetAccountIDByAddressWithRetry(ctx, ownerEmail)
	if err != nil {
		t.Fatalf("owner id: %v", err)
	}
	accountAID, err := rdb.GetAccountIDByAddressWithRetry(ctx, accountA.Email)
	if err != nil {
		t.Fatalf("account A id: %v", err)
	}

	// Recipient A's active SIEVE files all incoming mail into the shared mailbox.
	sieveScript := fmt.Sprintf("require [\"fileinto\"];\r\nfileinto \"%s\";\r\n", sharedMailbox)
	if _, err := rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountAID); err != nil {
		t.Fatalf("clear sieve: %v", err)
	}
	if _, err := rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())`, accountAID, "fileinto-shared", sieveScript, true); err != nil {
		t.Fatalf("insert sieve: %v", err)
	}

	lmtpAddr := startTestLMTPServer(t, rdb)

	// === Phase 1: A has only 'l' — fileinto denied, message must land in A's INBOX. ===
	if err := rdb.GrantMailboxAccessByIdentifierWithRetry(ctx, ownerID, accountA.Email, sharedMailbox, "l"); err != nil {
		t.Fatalf("grant 'l': %v", err)
	}
	deliverLMTP(t, lmtpAddr, accountA.Email, "L4-phase1")
	time.Sleep(300 * time.Millisecond)

	if n := countInMailbox(t, rdb, ownerID, sharedMailbox); n != 0 {
		t.Errorf("phase 1: shared mailbox must be empty (insert denied on 'l'), got %d", n)
	}
	if n := countInMailbox(t, rdb, accountAID, "INBOX"); n != 1 {
		t.Errorf("phase 1: recipient INBOX must hold the fallback message (1), got %d", n)
	}

	// === Phase 2: grant 'i' — fileinto into the shared mailbox now succeeds. ===
	if err := rdb.GrantMailboxAccessByIdentifierWithRetry(ctx, ownerID, accountA.Email, sharedMailbox, "li"); err != nil {
		t.Fatalf("grant 'li': %v", err)
	}
	deliverLMTP(t, lmtpAddr, accountA.Email, "L4-phase2")
	time.Sleep(300 * time.Millisecond)

	if n := countInMailbox(t, rdb, ownerID, sharedMailbox); n != 1 {
		t.Errorf("phase 2: shared mailbox must hold the filed message (1) once 'i' is granted, got %d", n)
	}
	if n := countInMailbox(t, rdb, accountAID, "INBOX"); n != 1 {
		t.Errorf("phase 2: recipient INBOX must be unchanged (1), got %d", n)
	}
}

// startTestLMTPServer starts an LMTP server backed by rdb and returns its address.
func startTestLMTPServer(t *testing.T, rdb *resilient.ResilientDatabase) string {
	t.Helper()
	up, err := uploader.NewWithS3Interface(
		t.TempDir(), 10, 2, 3, time.Second, 0, "test-instance", rdb,
		&common.NoopUploaderS3{}, &common.NoopUploaderCache{}, make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("uploader: %v", err)
	}
	addr := common.GetRandomAddress(t)
	srv, err := lmtpserver.New(context.Background(), "test-lmtp", "localhost", addr,
		&storage.S3Storage{}, rdb, up, lmtpserver.LMTPServerOptions{})
	if err != nil {
		t.Fatalf("lmtp new: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	go srv.Start(make(chan error, 1))
	time.Sleep(200 * time.Millisecond)
	return addr
}

// deliverLMTP delivers a one-line message to recipient via LMTP.
func deliverLMTP(t *testing.T, addr, recipient, subject string) {
	t.Helper()
	c, err := NewLMTPClient(addr)
	if err != nil {
		t.Fatalf("lmtp dial: %v", err)
	}
	defer c.Close()

	send := func(cmd string) {
		if err := c.SendCommand(cmd); err != nil {
			t.Fatalf("lmtp send %q: %v", cmd, err)
		}
	}
	send("LHLO test.example.com")
	if _, err := c.ReadMultilineResponse(); err != nil {
		t.Fatalf("LHLO: %v", err)
	}
	send("MAIL FROM:<sender@example.com>")
	if _, err := c.ReadResponse(); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	send(fmt.Sprintf("RCPT TO:<%s>", recipient))
	if r, err := c.ReadResponse(); err != nil || !strings.HasPrefix(r, "250") {
		t.Fatalf("RCPT TO: %v (resp %q)", err, r)
	}
	send("DATA")
	if _, err := c.ReadResponse(); err != nil {
		t.Fatalf("DATA: %v", err)
	}
	msg := strings.Join([]string{
		"From: sender@example.com",
		"To: " + recipient,
		"Subject: " + subject,
		"Date: " + time.Now().Format(time.RFC1123Z),
		fmt.Sprintf("Message-ID: <%d@example.com>", time.Now().UnixNano()),
		"",
		"body",
	}, "\r\n")
	send(msg + "\r\n.")
	resp, err := c.ReadDataResponses(1)
	if err != nil || len(resp) == 0 || !strings.HasPrefix(resp[0], "250") {
		t.Fatalf("DATA delivery not accepted: %v (resp %v)", err, resp)
	}
}

// countInMailbox returns the number of live messages in the named mailbox owned by
// ownerAccountID, queried directly (independent of the uploaded=true FETCH filter).
func countInMailbox(t *testing.T, rdb *resilient.ResilientDatabase, ownerAccountID int64, mailboxName string) int {
	t.Helper()
	var n int
	err := rdb.QueryRowWithRetry(context.Background(), `
		SELECT COUNT(*)
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE mb.account_id = $1 AND mb.name = $2 AND m.expunged_at IS NULL
	`, ownerAccountID, mailboxName).Scan(&n)
	if err != nil {
		t.Fatalf("count messages in %q: %v", mailboxName, err)
	}
	return n
}
