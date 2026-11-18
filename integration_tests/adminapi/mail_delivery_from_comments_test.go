//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestAdminAPI_DeliverMail_FromHeaderWithComments: a request without "from" takes the
// sender from the message's From header. RFC 5322 §3.4.1 lets comments and folding white
// space surround the "@" of an addr-spec, so
// "<user-from (comment)@ (comment) example.org>" is user-from@example.org. net/mail
// rejected that header and the delivery ran with no envelope sender, which the Sieve
// envelope test (and vacation and redirect) then saw as empty (#2037).
func TestAdminAPI_DeliverMail_FromHeaderWithComments(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := setupHTTPAPIServerWithUploader(t)
	defer server.Close()

	ctx := context.Background()
	email := fmt.Sprintf("apifromcomments-%d@example.com", time.Now().UnixNano())
	createDeliveryAccount(t, server, email)
	accountID, err := server.rdb.GetAccountIDByAddressWithRetry(ctx, email)
	if err != nil {
		t.Fatalf("lookup account: %v", err)
	}
	if _, err := server.rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, "Matched"); err != nil {
		t.Fatalf("create Matched: %v", err)
	}
	script := "# " + email + "\r\n" +
		"require [\"fileinto\", \"envelope\"];\r\n" +
		"if envelope :is \"from\" \"user-from@example.org\" { fileinto \"Matched\"; }\r\n"
	sc, err := server.rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
	if err != nil {
		t.Fatalf("create sieve script: %v", err)
	}
	if err := server.rdb.SetScriptActiveWithRetry(ctx, sc.ID, accountID, true); err != nil {
		t.Fatalf("activate sieve script: %v", err)
	}

	msg := "From: <user-from (comment)@ (comment) example.org>\r\nTo: " + email + "\r\n" +
		"Subject: from with comments\r\nMessage-ID: <" + email + ">\r\n\r\nBody via API.\r\n"
	resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{
		"recipients": []string{email},
		"message":    msg,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deliver: %d %s", resp.StatusCode, string(body))
	}
	if got, want := storedMailboxes(t, server, accountID), []string{"Matched"}; !slices.Equal(got, want) {
		t.Errorf("stored in %v, want %v: the envelope sender was not taken from the From header", got, want)
	}
}
