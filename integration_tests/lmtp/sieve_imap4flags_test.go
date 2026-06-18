//go:build integration

package lmtp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"

	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTP_SieveImap4Flags verifies that flags set by a Sieve script via the
// imap4flags extension (RFC 5232: setflag/addflag) are actually applied to the
// stored message at LMTP delivery. Sora advertises imap4flags in its ManageSieve
// capabilities, so it must honour it — previously result.Flags was computed and
// then silently dropped at delivery.
func TestLMTP_SieveImap4Flags(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	// setflag establishes \Seen; addflag adds two custom keywords (one $-keyword,
	// one plain). All must end up on the delivered message.
	sieveScript := `require ["imap4flags"];
setflag "\\Seen";
addflag "$label1";
addflag "Work";
keep;
`
	if _, err := rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountID); err != nil {
		t.Fatalf("Failed to clear sieve scripts: %v", err)
	}
	if _, err := rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
	`, accountID, "imap4flags-test", sieveScript, true); err != nil {
		t.Fatalf("Failed to insert Sieve script: %v", err)
	}

	// LMTP server (default extensions include imap4flags).
	tempDir := t.TempDir()
	uploaderInstance, err := uploader.NewWithS3Interface(
		tempDir, 10, 2, 3, time.Second, 0, "test-instance", rdb,
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

	// Deliver one message.
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
		if wantPrefix != "" && !strings.HasPrefix(resp, wantPrefix) {
			t.Fatalf("after %q: got %q, want prefix %q", cmd, resp, wantPrefix)
		}
	}

	if err := lmtpClient.SendCommand("LHLO test.example.com"); err != nil {
		t.Fatalf("LHLO: %v", err)
	}
	if _, err := lmtpClient.ReadMultilineResponse(); err != nil {
		t.Fatalf("LHLO response: %v", err)
	}
	mustCmd("MAIL FROM:<sender@example.com>", "250")
	mustCmd(fmt.Sprintf("RCPT TO:<%s>", account.Email), "250")
	mustCmd("DATA", "354")

	msg := strings.Join([]string{
		"From: sender@example.com",
		"To: " + account.Email,
		"Subject: imap4flags test",
		"Message-ID: <imap4flags-" + fmt.Sprintf("%d", time.Now().UnixNano()) + "@example.com>",
		"Date: " + time.Now().Format(time.RFC1123Z),
		"",
		"body",
	}, "\r\n")
	if err := lmtpClient.SendCommand(msg + "\r\n."); err != nil {
		t.Fatalf("send DATA body: %v", err)
	}
	dataResponses, err := lmtpClient.ReadDataResponses(1)
	if err != nil {
		t.Fatalf("read DATA responses: %v", err)
	}
	if !strings.HasPrefix(dataResponses[0], "250") {
		t.Fatalf("expected 250 after DATA, got: %s", dataResponses[0])
	}

	// Read the delivered message's flags straight from the database.
	var flagsBits int
	var customFlagsJSON []byte
	if err := rdb.QueryRowWithRetry(ctx, `
		SELECT ms.flags, ms.custom_flags
		FROM messages m
		JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.account_id = $1 AND m.expunged_at IS NULL
		ORDER BY m.id DESC
		LIMIT 1
	`, accountID).Scan(&flagsBits, &customFlagsJSON); err != nil {
		t.Fatalf("failed to read delivered message flags: %v", err)
	}

	// System flag \Seen must be set (setflag "\\Seen").
	seen := false
	for _, f := range db.BitwiseToFlags(flagsBits) {
		if f == imap.FlagSeen {
			seen = true
		}
	}
	if !seen {
		t.Errorf("delivered message is missing \\Seen set by sieve setflag (flags bits=%d)", flagsBits)
	}

	// Custom keywords from addflag must be present.
	var customFlags []string
	if err := json.Unmarshal(customFlagsJSON, &customFlags); err != nil {
		t.Fatalf("failed to unmarshal custom_flags %q: %v", string(customFlagsJSON), err)
	}
	// Keyword identity is case-insensitive (RFC 9051 §2.3.2); the go-sieve engine
	// happens to lower-case keywords (e.g. "Work" -> "work"), which is acceptable.
	has := func(want string) bool {
		for _, f := range customFlags {
			if strings.EqualFold(f, want) {
				return true
			}
		}
		return false
	}
	for _, kw := range []string{"$label1", "Work"} {
		if !has(kw) {
			t.Errorf("delivered message is missing keyword %q set by sieve addflag; custom_flags=%v", kw, customFlags)
		}
	}
}
