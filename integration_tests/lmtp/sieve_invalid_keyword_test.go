//go:build integration

package lmtp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"

	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTP_SieveInvalidKeywordIsDropped is the delivery-side guard for the
// production incident behind this test: a user's Sieve rule
//
//	require ["imap4flags", "editheader"];
//	addflag "НЕОБРАБОТЕНО";
//
// made their INBOX permanently unopenable. Sieve is the one flag source that
// never passes an IMAP parser, so the Cyrillic keyword was stored verbatim; the
// mailbox_stats trigger then unioned it into the mailbox's keyword registry,
// which SELECT advertises in * FLAGS (...). The encoder cannot represent a
// non-ASCII flag as an atom, so it abandoned the response mid-list and the
// client waited forever for a tagged reply. Emptying the mailbox did not help,
// because the registry is union-only and never shrinks.
//
// The keyword must therefore never reach the database. A valid keyword set by
// the same script must still be applied, so this is a filter, not a bounce: a
// delivery is never rejected over a bad keyword.
func TestLMTP_SieveInvalidKeywordIsDropped(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	// The keyword from the incident, plus keywords exercising the other
	// atom-specials a script could reach for, plus one that must survive.
	sieveScript := `require ["imap4flags"];
addflag "НЕОБРАБОТЕНО";
addflag "bad tag";
addflag "bad]bracket";
addflag "Work";
keep;
`
	if _, err := rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountID); err != nil {
		t.Fatalf("Failed to clear sieve scripts: %v", err)
	}
	if _, err := rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
	`, accountID, "invalid-keyword-test", sieveScript, true); err != nil {
		t.Fatalf("Failed to insert Sieve script: %v", err)
	}

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
		"Subject: invalid keyword test",
		"Message-ID: <invalid-kw-" + fmt.Sprintf("%d", time.Now().UnixNano()) + "@example.com>",
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
	// A keyword the server cannot store is not a reason to refuse the mail.
	if !strings.HasPrefix(dataResponses[0], "250") {
		t.Fatalf("delivery should still succeed with an invalid keyword, got: %s", dataResponses[0])
	}

	var customFlagsJSON []byte
	if err := rdb.QueryRowWithRetry(ctx, `
		SELECT ms.custom_flags
		FROM messages m
		JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.account_id = $1 AND m.expunged_at IS NULL
		ORDER BY m.id DESC
		LIMIT 1
	`, accountID).Scan(&customFlagsJSON); err != nil {
		t.Fatalf("failed to read delivered message flags: %v", err)
	}

	var customFlags []string
	if err := json.Unmarshal(customFlagsJSON, &customFlags); err != nil {
		t.Fatalf("failed to unmarshal custom_flags %q: %v", string(customFlagsJSON), err)
	}

	for _, bad := range []string{"НЕОБРАБОТЕНО", "bad tag", "bad]bracket"} {
		for _, got := range customFlags {
			if strings.EqualFold(got, bad) {
				t.Errorf("keyword %q is not a valid IMAP flag-keyword but was stored; "+
					"it would wedge SELECT of this mailbox. custom_flags=%v", bad, customFlags)
			}
		}
	}

	// The valid keyword from the same script must survive: this filters, it does
	// not discard the whole imap4flags result.
	valid := false
	for _, got := range customFlags {
		if strings.EqualFold(got, "Work") {
			valid = true
		}
	}
	if !valid {
		t.Errorf("valid keyword \"Work\" was lost alongside the invalid ones; custom_flags=%v", customFlags)
	}

	// The mailbox keyword registry, which is what SELECT advertises, must be
	// clean too -- it is union-only, so anything landing there is permanent.
	var cache []byte
	if err := rdb.QueryRowWithRetry(ctx, `
		SELECT COALESCE(mstats.custom_flags_cache, '[]'::jsonb)::text::bytea
		FROM mailbox_stats mstats
		JOIN mailboxes mb ON mb.id = mstats.mailbox_id
		WHERE mb.account_id = $1 AND lower(mb.name) = 'inbox'
	`, accountID).Scan(&cache); err != nil {
		t.Fatalf("failed to read custom_flags_cache: %v", err)
	}
	if strings.Contains(string(cache), "НЕОБРАБОТЕНО") {
		t.Errorf("invalid keyword reached the mailbox keyword registry: %s", cache)
	}
}
