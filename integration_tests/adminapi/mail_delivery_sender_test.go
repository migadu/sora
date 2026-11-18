//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/adminapi"
)

// TestAdminAPI_DeliverMail_SenderReadAsReversePath is #1970: /admin/mail/deliver reads
// its "from" as LMTP reads MAIL FROM (server.NewReversePath), not as a login name. A
// local part with consecutive dots is a sender go-smtp hands on (#1907), and a second "@"
// can only come from a quoted local part, never from a master-token suffix (#1938). The
// script answers only when Sieve sees the expected envelope sender, and the vacation
// reply is addressed to it.
func TestAdminAPI_DeliverMail_SenderReadAsReversePath(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rq := &captureRelay{}
	server, _ := setupHTTPAPIServerWithOptions(t, func(o *adminapi.ServerOptions) {
		o.RelayQueue = rq
	})
	defer server.Close()
	ctx := context.Background()

	for _, tc := range []struct {
		name, from, want string
	}{
		{name: "consecutive dots", from: "first..last@example.com", want: "first..last@example.com"},
		{name: "second at sign", from: "a@b.example@example.com", want: `"a@b.example"@example.com`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker := fmt.Sprintf("sender-%d", time.Now().UnixNano())
			email := fmt.Sprintf("apisender-%s@example.com", marker)
			createDeliveryAccount(t, server, email)
			accountID, err := server.rdb.GetAccountIDByAddressWithRetry(ctx, email)
			if err != nil {
				t.Fatalf("lookup account: %v", err)
			}
			script := "require [\"envelope\", \"vacation\"];\r\n" +
				"if envelope :all :is \"from\" " + sieveString(tc.want) + " {\r\n" +
				"  vacation \"I am away.\";\r\n}\r\n"
			sc, err := server.rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
			if err != nil {
				t.Fatalf("create sieve script: %v", err)
			}
			if err := server.rdb.SetScriptActiveWithRetry(ctx, sc.ID, accountID, true); err != nil {
				t.Fatalf("activate sieve script: %v", err)
			}

			before := len(rq.snapshot())
			resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{
				"recipients": []string{email},
				"from":       tc.from,
				"message": "From: sender@example.net\r\nTo: " + email + "\r\nSubject: who sent this\r\n" +
					"Message-ID: <" + marker + "@example.net>\r\n\r\nbody\r\n",
			})
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("deliver: %d %s", resp.StatusCode, string(body))
			}

			var replies []string
			for _, it := range rq.snapshot()[before:] {
				if it.msgType == "vacation" {
					replies = append(replies, it.to)
				}
			}
			if len(replies) != 1 || replies[0] != tc.want {
				t.Errorf("from %q: vacation replies to %v, want one to %q (Sieve must see that envelope sender)", tc.from, replies, tc.want)
			}
		})
	}
}

// sieveString quotes s as a Sieve quoted string (RFC 5228 §2.4.2).
func sieveString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func (q *captureRelay) snapshot() []capturedRelayItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]capturedRelayItem(nil), q.items...)
}
