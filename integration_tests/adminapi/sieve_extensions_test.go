//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/sieveengine"
)

// deliverWithScript activates script on a fresh account of server, delivers one message to
// it through /admin/mail/deliver, and returns the mailbox the message ended up in.
func deliverWithScript(t *testing.T, server *HTTPAPITestServer, script, marker string) string {
	t.Helper()
	ctx := context.Background()

	email := fmt.Sprintf("apiext-%s@example.com", marker)
	createDeliveryAccount(t, server, email)

	accountID, err := server.rdb.GetAccountIDByAddressWithRetry(ctx, email)
	if err != nil {
		t.Fatalf("lookup account: %v", err)
	}
	sc, err := server.rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
	if err != nil {
		t.Fatalf("create sieve script: %v", err)
	}
	if err := server.rdb.SetScriptActiveWithRetry(ctx, sc.ID, accountID, true); err != nil {
		t.Fatalf("activate sieve script: %v", err)
	}

	msg := "From: sender@example.com\r\nTo: " + email + "\r\nSubject: " + marker +
		"\r\nMessage-ID: <" + marker + "@example.com>\r\n\r\nbody\r\n"
	resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{
		"recipients": []string{email},
		"message":    msg,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deliver: %d %s", resp.StatusCode, string(body))
	}

	time.Sleep(500 * time.Millisecond)

	var mailboxName string
	err = server.rdb.QueryRowWithRetry(ctx, `
		SELECT mb.name
		FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE m.account_id = $1 AND m.expunged_at IS NULL
		ORDER BY m.uid DESC LIMIT 1
	`, accountID).Scan(&mailboxName)
	if err != nil {
		t.Fatalf("delivered message row: %v", err)
	}
	return mailboxName
}

// TestAdminAPI_DeliverMail_HonoursConfiguredSieveExtensions pins the Admin API delivery
// path to the [sieve] enabled_extensions set an operator configured — the set cmd/sora
// hands to adminapi.ServerOptions, which the server hands to the delivery executor.
//
// On a deployment that opts into editheader, LMTP compiles the user's script and files the
// message; the delivery path used to compile against its own hardcoded default set, where
// the `require "editheader"` fails. That compile failure is swallowed into a plain INBOX
// keep, so the message is silently misfiled rather than filtered — the same script, the
// same user, two different outcomes depending on which ingress it arrived through.
//
// Both halves run through adminapi.Start, so every hop the option makes in production is
// executed here: dropping the pass-through in server/adminapi/server.go or in
// server/adminapi/mail_delivery.go turns the configured half into the default half.
func TestAdminAPI_DeliverMail_HonoursConfiguredSieveExtensions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Premise: editheader is deliberately outside the default set, so this script only
	// compiles for a deployment that opted in. If that ever changes, the halves below stop
	// telling the configured set apart from the default one.
	for _, ext := range sieveengine.DefaultSieveExtensions {
		if ext == "editheader" {
			t.Fatalf("premise: editheader must be outside the default set")
		}
	}

	marker := fmt.Sprintf("ext-%d", time.Now().UnixNano())
	// Unique script text so a parallel test's compiled entry cannot serve this one.
	script := fmt.Sprintf("require [\"editheader\", \"fileinto\"];\r\n# %s\r\n"+
		"addheader \"X-Sora-Filtered\" \"yes\";\r\nfileinto \"Archive\";\r\n", marker)

	// Baseline: no [sieve] enabled_extensions configured. The require fails, the failure is
	// swallowed, and the message is kept in INBOX. This is what the configured half must
	// NOT look like.
	t.Run("default set", func(t *testing.T) {
		server, _ := setupHTTPAPIServerWithUploader(t)
		defer server.Close()

		if got := deliverWithScript(t, server, script, marker+"-default"); got != "INBOX" {
			t.Fatalf("premise: without editheader the script cannot compile, so the message "+
				"should have been kept in INBOX; got %s", got)
		}
	})

	// What a deployment with `enabled_extensions = [..., "editheader"]` produces: the same
	// script compiles and files the message.
	t.Run("configured set", func(t *testing.T) {
		enabled := append(append([]string{}, sieveengine.DefaultSieveExtensions...), "editheader")
		server, _ := setupHTTPAPIServerWithUploader(t, enabled...)
		defer server.Close()

		if got := deliverWithScript(t, server, script, marker+"-configured"); got != "Archive" {
			t.Fatalf("delivery ignored the configured extension set: the editheader require "+
				"failed to compile, the failure was swallowed into a plain INBOX keep, and the "+
				"message was misfiled to %s while LMTP would have filed it to Archive", got)
		}
	})
}
