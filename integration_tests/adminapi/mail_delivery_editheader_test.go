//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/sieveengine"
)

// TestAdminAPI_DeliverMail_AppliesSieveHeaderEdits asserts that the Admin API delivery
// path applies the header edits its Sieve evaluation produced (RFC 5293 editheader), the
// way the LMTP path does.
//
// The delivery path used to compute result.HeaderEdits and drop them on the floor
// (sieveengine.ApplyHeaderEdits was called only from server/lmtp/session.go), so one
// script on one account produced two different stored messages depending on the ingress:
// LMTP filed it WITH the added header, /admin/mail/deliver filed it WITHOUT.
//
// The body is read back by the content_hash the message row carries, which also pins the
// hazard in fixing this: content_hash is the S3 object key, the cache key and the
// upload-dedup key, so applying the edits after the body was hashed and staged would
// store a body that does not match its own hash — an unreadable message.
func TestAdminAPI_DeliverMail_AppliesSieveHeaderEdits(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Premise: editheader is deliberately outside the default set, so this script only
	// compiles for a deployment that opted in via [sieve] enabled_extensions.
	for _, ext := range sieveengine.DefaultSieveExtensions {
		if ext == "editheader" {
			t.Fatalf("premise: editheader must be outside the default set")
		}
	}
	enabled := append(append([]string{}, sieveengine.DefaultSieveExtensions...), "editheader")

	server, tempDir := setupHTTPAPIServerWithUploader(t, enabled...)
	defer server.Close()

	email := fmt.Sprintf("apiedit-%d@example.com", time.Now().UnixNano())
	createDeliveryAccount(t, server, email)

	ctx := context.Background()
	accountID, err := server.rdb.GetAccountIDByAddressWithRetry(ctx, email)
	if err != nil {
		t.Fatalf("lookup account: %v", err)
	}

	marker := fmt.Sprintf("edithdr-%d", time.Now().UnixNano())
	// Unique script text so a parallel test's compiled entry cannot serve this one.
	script := fmt.Sprintf("require [\"editheader\", \"fileinto\"];\r\n# %s\r\n"+
		"addheader \"X-Spam-Flag\" \"YES\";\r\nfileinto \"Junk\";\r\n", marker)
	sc, err := server.rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
	if err != nil {
		t.Fatalf("create sieve script: %v", err)
	}
	if err := server.rdb.SetScriptActiveWithRetry(ctx, sc.ID, accountID, true); err != nil {
		t.Fatalf("activate sieve script: %v", err)
	}

	msg := "From: sender@example.com\r\nTo: " + email + "\r\nSubject: " + marker +
		"\r\nMessage-ID: <" + marker + "@example.com>\r\n\r\nBody via API.\r\n"
	resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{
		"recipients": []string{email},
		"message":    msg,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deliver: %d %s", resp.StatusCode, string(body))
	}

	time.Sleep(500 * time.Millisecond)

	var contentHash, mailboxName string
	var rowAccountID int64
	err = server.rdb.QueryRowWithRetry(ctx, `
		SELECT m.content_hash, mb.name, m.account_id
		FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE m.account_id = $1 AND m.expunged_at IS NULL
		ORDER BY m.uid DESC LIMIT 1
	`, accountID).Scan(&contentHash, &mailboxName, &rowAccountID)
	if err != nil {
		t.Fatalf("delivered message row: %v", err)
	}

	// Anchor: the script ran and compiled with the configured set (fileinto took effect).
	if mailboxName != "Junk" {
		t.Fatalf("Sieve did not file the message: mailbox=%s, want Junk", mailboxName)
	}

	// The stored body must be reachable through the hash the row carries: content_hash is
	// the S3 key, so a body stored under a different hash is a message nobody can read.
	stored, err := os.ReadFile(filepath.Join(tempDir, fmt.Sprintf("%d", rowAccountID), contentHash))
	if err != nil {
		t.Fatalf("stored body must be readable at the row's content_hash %s: %v", contentHash, err)
	}
	if got := helpers.HashContent(stored); got != contentHash {
		t.Errorf("stored body does not hash to its own content_hash: stored=%s row=%s", got, contentHash)
	}

	if !strings.Contains(string(stored), "X-Spam-Flag: YES") {
		t.Errorf("Sieve header edit was dropped by the delivery path; stored head:\n%s", adminHead(string(stored)))
	}
}

// TestAdminAPI_DeliverMail_SieveCopyUsesEditedMessage covers `fileinto :copy` alongside
// editheader: the two copies of one delivery (the filed one and the INBOX one) must be
// the same message. If the copy were saved from the pre-edit bytes it would land under a
// different content_hash — two different bodies, one of them missing the header the
// script added, and a second S3 object for what is one message.
func TestAdminAPI_DeliverMail_SieveCopyUsesEditedMessage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	enabled := append(append([]string{}, sieveengine.DefaultSieveExtensions...), "editheader")
	server, tempDir := setupHTTPAPIServerWithUploader(t, enabled...)
	defer server.Close()

	email := fmt.Sprintf("apicopy-%d@example.com", time.Now().UnixNano())
	createDeliveryAccount(t, server, email)

	ctx := context.Background()
	accountID, err := server.rdb.GetAccountIDByAddressWithRetry(ctx, email)
	if err != nil {
		t.Fatalf("lookup account: %v", err)
	}

	marker := fmt.Sprintf("editcopy-%d", time.Now().UnixNano())
	script := fmt.Sprintf("require [\"editheader\", \"fileinto\", \"copy\"];\r\n# %s\r\n"+
		"addheader \"X-Spam-Flag\" \"YES\";\r\nfileinto :copy \"Archive\";\r\n", marker)
	sc, err := server.rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
	if err != nil {
		t.Fatalf("create sieve script: %v", err)
	}
	if err := server.rdb.SetScriptActiveWithRetry(ctx, sc.ID, accountID, true); err != nil {
		t.Fatalf("activate sieve script: %v", err)
	}

	msg := "From: sender@example.com\r\nTo: " + email + "\r\nSubject: " + marker +
		"\r\nMessage-ID: <" + marker + "@example.com>\r\n\r\nBody via API.\r\n"
	resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{
		"recipients": []string{email},
		"message":    msg,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deliver: %d %s", resp.StatusCode, string(body))
	}

	time.Sleep(500 * time.Millisecond)

	rows, err := server.rdb.QueryWithRetry(ctx, `
		SELECT mb.name, m.content_hash
		FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE m.account_id = $1 AND m.expunged_at IS NULL
		ORDER BY mb.name
	`, accountID)
	if err != nil {
		t.Fatalf("query delivered rows: %v", err)
	}
	defer rows.Close()

	hashByMailbox := map[string]string{}
	for rows.Next() {
		var name, hash string
		if err := rows.Scan(&name, &hash); err != nil {
			t.Fatalf("scan row: %v", err)
		}
		hashByMailbox[name] = hash
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate rows: %v", err)
	}

	if len(hashByMailbox) != 2 || hashByMailbox["Archive"] == "" || hashByMailbox["INBOX"] == "" {
		t.Fatalf("fileinto :copy must store one copy in Archive and one in INBOX, got %v", hashByMailbox)
	}
	if hashByMailbox["Archive"] != hashByMailbox["INBOX"] {
		t.Fatalf("the two copies of one delivery differ: Archive=%s INBOX=%s",
			hashByMailbox["Archive"], hashByMailbox["INBOX"])
	}

	stored, err := os.ReadFile(filepath.Join(tempDir, fmt.Sprintf("%d", accountID), hashByMailbox["INBOX"]))
	if err != nil {
		t.Fatalf("stored body must be readable at the rows' content_hash: %v", err)
	}
	if got := helpers.HashContent(stored); got != hashByMailbox["INBOX"] {
		t.Errorf("stored body does not hash to its own content_hash: stored=%s row=%s", got, hashByMailbox["INBOX"])
	}
	if !strings.Contains(string(stored), "X-Spam-Flag: YES") {
		t.Errorf("Sieve header edit was dropped for the :copy delivery; stored head:\n%s", adminHead(string(stored)))
	}
}
