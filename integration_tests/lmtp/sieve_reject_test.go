//go:build integration

package lmtp_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"

	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTP_SieveRejectIsDiscard: a script that requires "reject" used to fail
// to compile, so every rule in it was skipped and the message went to INBOX.
// reject now compiles and is delivered as a discard: LMTP answers 250 (the
// MTA in front never bounces) and nothing is stored, while the script's other
// rules run as written.
func TestLMTP_SieveRejectIsDiscard(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	script := `require ["fileinto", "reject"];
if header :contains "subject" "reject-me" { reject "No thanks"; stop; }
if header :contains "subject" "junk-me" { fileinto "Junk"; }
`
	_, _ = rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountID)
	if _, err := rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
		VALUES ($1, $2, $3, true, NOW(), NOW())
	`, accountID, "test-reject", script); err != nil {
		t.Fatalf("Failed to insert Sieve script: %v", err)
	}

	spoolDir := t.TempDir()
	sharedUploader, err := uploader.NewWithS3Interface(spoolDir, 10, 2, 3, time.Second, 0,
		"test-instance", rdb, &common.NoopUploaderS3{}, &common.NoopUploaderCache{}, make(chan error, 1))
	if err != nil {
		t.Fatalf("Failed to create uploader: %v", err)
	}

	lmtpAddr := common.GetRandomAddress(t)
	lmtpSrv, err := lmtpserver.New(ctx, "test-lmtp", "localhost", lmtpAddr, &storage.S3Storage{},
		rdb, sharedUploader, lmtpserver.LMTPServerOptions{})
	if err != nil {
		t.Fatalf("Failed to create LMTP server: %v", err)
	}
	defer lmtpSrv.Close()
	lmtpErrChan := make(chan error, 1)
	go lmtpSrv.Start(lmtpErrChan)
	waitForLMTPListener(t, lmtpAddr, lmtpErrChan)

	client, err := NewLMTPClient(lmtpAddr)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP server: %v", err)
	}
	defer client.Close()
	if err := client.SendCommand("LHLO test.example.com"); err != nil {
		t.Fatalf("LHLO: %v", err)
	}
	if _, err := client.ReadMultilineResponse(); err != nil {
		t.Fatalf("LHLO response: %v", err)
	}

	stamp := time.Now().UnixNano()
	cases := []struct {
		subject string
		mailbox string // "" = not stored
	}{
		{fmt.Sprintf("reject-me %d", stamp), ""},
		{fmt.Sprintf("junk-me %d", stamp), "Junk"},
		{fmt.Sprintf("plain %d", stamp), "INBOX"},
	}

	for i, tc := range cases {
		expectLine := func(cmd, prefix string) {
			t.Helper()
			if err := client.SendCommand(cmd); err != nil {
				t.Fatalf("%q: %v", cmd, err)
			}
			resp, err := client.ReadResponse()
			if err != nil || !strings.HasPrefix(resp, prefix) {
				t.Fatalf("%q: got %q (%v), want %s", cmd, resp, err, prefix)
			}
		}
		expectLine("MAIL FROM:<sender@example.com>", "250")
		expectLine(fmt.Sprintf("RCPT TO:<%s>", account.Email), "250")
		expectLine("DATA", "354")

		body := strings.Join([]string{
			"From: sender@example.com",
			"To: " + account.Email,
			"Subject: " + tc.subject,
			"Date: " + time.Now().Format(time.RFC1123Z),
			fmt.Sprintf("Message-ID: <sieve-reject-%d-%d@example.com>", stamp, i),
			"",
			"Body.",
		}, "\r\n")
		if err := client.SendCommand(body + "\r\n."); err != nil {
			t.Fatalf("send message: %v", err)
		}
		replies, err := client.ReadDataResponses(1)
		if err != nil {
			t.Fatalf("DATA replies: %v", err)
		}
		if !strings.HasPrefix(replies[0], "250") {
			t.Fatalf("%q: DATA reply %q, want 250 (a reject must never surface as a 5xx)", tc.subject, replies[0])
		}
	}

	// A rejected message is decided before the body is staged, so nothing of it
	// reaches the upload spool (a staged-then-abandoned file would sit there until
	// the orphan sweep and count against the staging limit).
	_ = filepath.WalkDir(spoolDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if b, rerr := os.ReadFile(path); rerr == nil && strings.Contains(string(b), cases[0].subject) {
			t.Errorf("rejected message was staged in the upload spool: %s", path)
		}
		return nil
	})

	for _, tc := range cases {
		var mailbox string
		err := rdb.QueryRowWithRetry(ctx, `
			SELECT mb.name FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
			WHERE m.account_id = $1 AND m.subject = $2 AND m.expunged_at IS NULL
		`, accountID, tc.subject).Scan(&mailbox)
		switch {
		case tc.mailbox == "" && errors.Is(err, pgx.ErrNoRows):
		case tc.mailbox == "" && err == nil:
			t.Errorf("%q was stored in %s, want it discarded", tc.subject, mailbox)
		case err != nil:
			t.Errorf("%q: %v, want it in %s", tc.subject, err, tc.mailbox)
		case mailbox != tc.mailbox:
			t.Errorf("%q stored in %s, want %s", tc.subject, mailbox, tc.mailbox)
		}
	}
}
