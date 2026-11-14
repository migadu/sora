//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/adminapi"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// TestNodeWithoutRelay_SieveVacationAndRedirect delivers, over LMTP and through
// /admin/mail/deliver, to an account whose active Sieve script asks for a vacation reply or
// a redirect, on servers built from the options this binary builds for a node without
// [relay]. With no relay the reply is skipped and the redirected message is kept in INBOX;
// either way the delivery itself must succeed.
func TestNodeWithoutRelay_SieveVacationAndRedirect(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	ctx := context.Background()

	deps := &serverDependencies{hostname: "mx.example.com"}
	lmtpSrv, account := common.SetupLMTPServerWithOptions(t, buildLMTPServerOptions(deps, config.ServerConfig{Type: "lmtp", Name: "lmtp"}))
	defer lmtpSrv.Close()
	rdb := lmtpSrv.ResilientDB
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}

	// The Admin API of the same node, on the same database.
	upload, err := uploader.NewWithS3Interface(t.TempDir(), 10, 2, 3, time.Second, 0, deps.hostname, rdb,
		&common.NoopUploaderS3{}, &common.NoopUploaderCache{}, make(chan error, 1))
	if err != nil {
		t.Fatalf("uploader: %v", err)
	}
	deps.resilientDB, deps.uploadWorker, deps.storage = rdb, upload, &storage.S3Storage{}
	const apiKey = "test-admin-api-key-0123456789"
	adminAddr := common.GetRandomAddress(t)
	adminSrv, err := adminapi.New(rdb, buildAdminAPIServerOptions(deps, config.ServerConfig{
		Type: "http_admin_api", Name: "admin-api", Addr: adminAddr, APIKey: apiKey,
	}))
	if err != nil {
		t.Fatalf("adminapi.New: %v", err)
	}
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	adminSrv.Serve(serveCtx, make(chan error, 1))
	waitListening(t, adminAddr)

	for _, script := range []struct{ name, sieve string }{
		{"vacation", "require \"vacation\";\r\nvacation :days 1 \"I am away\";\r\n"},
		{"redirect", "redirect \"elsewhere@example.org\";\r\n"},
	} {
		// A sender per delivery: a vacation reply claimed by one delivery would suppress
		// the next one's for the :days window.
		t.Run("LMTP/"+script.name, func(t *testing.T) {
			setActiveSieve(t, rdb, accountID, script.sieve)
			sender := "lmtp-" + script.name + "@example.org"
			before := countInbox(t, rdb, accountID)
			if resp := deliverOverLMTP(t, lmtpSrv.Address, sender, account.Email, testMessage(sender, account.Email)); !strings.HasPrefix(resp, "250") {
				t.Fatalf("LMTP delivery: %s, want 250", resp)
			}
			if n := countInbox(t, rdb, accountID) - before; n != 1 {
				t.Errorf("messages added to INBOX = %d, want 1", n)
			}
		})
		t.Run("AdminAPI/"+script.name, func(t *testing.T) {
			setActiveSieve(t, rdb, accountID, script.sieve)
			sender := "adminapi-" + script.name + "@example.org"
			before := countInbox(t, rdb, accountID)
			body, _ := json.Marshal(adminapi.DeliverMailRequest{
				Recipients: []string{account.Email}, From: sender, Message: testMessage(sender, account.Email),
			})
			req, _ := http.NewRequest("POST", "http://"+adminAddr+"/admin/mail/deliver", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+apiKey)
			req.Header.Set("Content-Type", "application/json")
			resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
			if err != nil {
				t.Fatalf("POST /admin/mail/deliver: %v", err)
			}
			defer resp.Body.Close()
			out, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("POST /admin/mail/deliver: %d %s, want 200", resp.StatusCode, strings.TrimSpace(string(out)))
			}
			if n := countInbox(t, rdb, accountID) - before; n != 1 {
				t.Errorf("messages added to INBOX = %d, want 1", n)
			}
		})
	}
}

// testMessage is a personal message (the recipient is in To), so a vacation reply is due.
func testMessage(from, to string) string {
	return strings.Join([]string{
		"From: " + from,
		"To: " + to,
		"Subject: are you there",
		"Date: " + time.Now().Format(time.RFC1123Z),
		fmt.Sprintf("Message-ID: <%d@example.org>", time.Now().UnixNano()),
		"",
		"Hello.",
		"",
	}, "\r\n")
}

// deliverOverLMTP runs one LMTP transaction and returns the reply to the end of DATA.
func deliverOverLMTP(t *testing.T, addr, from, rcpt, msg string) string {
	t.Helper()
	c, err := textproto.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial LMTP: %v", err)
	}
	defer c.Close()
	if _, _, err := c.ReadResponse(220); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	step := func(expect int, format string, args ...any) {
		t.Helper()
		if err := c.PrintfLine(format, args...); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if _, _, err := c.ReadResponse(expect); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
	}
	step(250, "LHLO client.example.org")
	step(250, "MAIL FROM:<%s>", from)
	step(250, "RCPT TO:<%s>", rcpt)
	step(354, "DATA")
	w := c.DotWriter()
	if _, err := io.WriteString(w, msg); err != nil {
		t.Fatalf("write message: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("end DATA: %v", err)
	}
	code, text, err := c.ReadResponse(250)
	if code == 0 {
		return fmt.Sprintf("no reply: %v", err)
	}
	return fmt.Sprintf("%d %s", code, text)
}

func setActiveSieve(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64, script string) {
	t.Helper()
	ctx := context.Background()
	if _, err := rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountID); err != nil {
		t.Fatalf("clear sieve: %v", err)
	}
	if _, err := rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
		VALUES ($1, 'test', $2, true, NOW(), NOW())`, accountID, script); err != nil {
		t.Fatalf("insert sieve: %v", err)
	}
}

func countInbox(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64) int {
	t.Helper()
	var n int
	if err := rdb.QueryRowWithRetry(context.Background(), `
		SELECT COUNT(*) FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE mb.account_id = $1 AND mb.name = 'INBOX' AND m.expunged_at IS NULL`, accountID).Scan(&n); err != nil {
		t.Fatalf("count INBOX: %v", err)
	}
	return n
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not listening: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
