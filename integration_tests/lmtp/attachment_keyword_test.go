//go:build integration

package lmtp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"

	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTP_AttachmentKeyword: LMTP delivery sets the RFC 9979 §4 attachment
// keyword from the message structure, replacing one a Sieve script set.
func TestLMTP_AttachmentKeyword(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	// The script claims an attachment on every message; the server decides.
	if _, err := rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountID); err != nil {
		t.Fatalf("Failed to clear sieve scripts: %v", err)
	}
	if _, err := rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
	`, accountID, "attachment-test", "require [\"imap4flags\"];\naddflag \"$hasattachment\";\nkeep;\n", true); err != nil {
		t.Fatalf("Failed to insert Sieve script: %v", err)
	}

	uploaderInstance, err := uploader.NewWithS3Interface(
		t.TempDir(), 10, 2, 3, time.Second, 0, "test-instance", rdb,
		&common.NoopUploaderS3{}, &common.NoopUploaderCache{}, make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create uploader: %v", err)
	}
	lmtpAddr := common.GetRandomAddress(t)
	lmtpSrv, err := lmtpserver.New(
		context.Background(), "test-lmtp", "localhost", lmtpAddr,
		&storage.S3Storage{}, rdb, uploaderInstance, lmtpserver.LMTPServerOptions{},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP server: %v", err)
	}
	defer lmtpSrv.Close()
	go func() { lmtpSrv.Start(make(chan error, 1)) }()
	time.Sleep(200 * time.Millisecond)

	lmtpClient, err := NewLMTPClient(lmtpAddr)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP server: %v", err)
	}
	defer lmtpClient.Close()

	mustCmd := func(cmd, wantPrefix string) {
		t.Helper()
		if err := lmtpClient.SendCommand(cmd); err != nil {
			t.Fatalf("send %q: %v", cmd, err)
		}
		resp, err := lmtpClient.ReadResponse()
		if err != nil {
			t.Fatalf("read after %q: %v", cmd, err)
		}
		if !strings.HasPrefix(resp, wantPrefix) {
			t.Fatalf("after %q: got %q, want prefix %q", cmd, resp, wantPrefix)
		}
	}
	if err := lmtpClient.SendCommand("LHLO test.example.com"); err != nil {
		t.Fatalf("LHLO: %v", err)
	}
	if _, err := lmtpClient.ReadMultilineResponse(); err != nil {
		t.Fatalf("LHLO response: %v", err)
	}

	deliver := func(subject string, contentLines ...string) {
		t.Helper()
		mustCmd("MAIL FROM:<sender@example.com>", "250")
		mustCmd(fmt.Sprintf("RCPT TO:<%s>", account.Email), "250")
		mustCmd("DATA", "354")
		lines := append([]string{
			"From: sender@example.com",
			"To: " + account.Email,
			"Subject: " + subject,
			fmt.Sprintf("Message-ID: <%s-%d@example.com>", subject, time.Now().UnixNano()),
			"Date: " + time.Now().Format(time.RFC1123Z),
		}, contentLines...)
		if err := lmtpClient.SendCommand(strings.Join(lines, "\r\n") + "\r\n."); err != nil {
			t.Fatalf("send DATA body: %v", err)
		}
		resp, err := lmtpClient.ReadDataResponses(1)
		if err != nil || !strings.HasPrefix(resp[0], "250") {
			t.Fatalf("DATA for %q: %v %v", subject, resp, err)
		}
	}
	keywordsOf := func(subject string) []string {
		t.Helper()
		var raw []byte
		if err := rdb.QueryRowWithRetry(ctx, `
			SELECT ms.custom_flags FROM messages m
			JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
			WHERE m.account_id = $1 AND m.subject = $2 AND m.expunged_at IS NULL
		`, accountID, subject).Scan(&raw); err != nil {
			t.Fatalf("read flags of %q: %v", subject, err)
		}
		var keywords []string
		if err := json.Unmarshal(raw, &keywords); err != nil {
			t.Fatalf("unmarshal custom_flags %q: %v", raw, err)
		}
		return keywords
	}

	deliver("plain", "", "no attachment here")
	deliver("attached",
		`Content-Type: multipart/mixed; boundary="b"`,
		"",
		"--b",
		"Content-Type: text/plain",
		"",
		"see attached",
		"--b",
		"Content-Type: application/pdf",
		`Content-Disposition: attachment; filename="report.pdf"`,
		"",
		"JVBERi0=",
		"--b--",
	)

	if kw := keywordsOf("plain"); !slices.Contains(kw, "$hasnoattachment") || slices.Contains(kw, "$hasattachment") {
		t.Errorf("plain message keywords = %v, want $hasnoattachment in place of the script's $hasattachment", kw)
	}
	if kw := keywordsOf("attached"); !slices.Contains(kw, "$hasattachment") || slices.Contains(kw, "$hasnoattachment") {
		t.Errorf("message with a PDF keywords = %v, want $hasattachment", kw)
	}
}
