//go:build integration

package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/adminapi"
)

// TestAdminAPI_DeliverMail_GroupHeaderRecipients: a delivery without "recipients" goes to
// the To, Cc and Bcc addresses. An RFC 5322 §3.4 group contributes its members; its
// start and end markers (kept in the recipients metadata for the IMAP ENVELOPE, with an
// empty address) are not recipients, and an empty group such as "undisclosed:;" adds
// none (#2012). They used to be tried as empty recipients, failing the delivery with 207.
func TestAdminAPI_DeliverMail_GroupHeaderRecipients(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, _ := setupHTTPAPIServerWithUploader(t)
	defer server.Close()
	email := fmt.Sprintf("api-group-recipients-%d@example.com", time.Now().UnixNano())
	createDeliveryAccount(t, server, email)

	upper := strings.ToUpper(email)
	for _, tc := range []struct{ name, headers string }{
		{"To", fmt.Sprintf("To: team: %s;, undisclosed:;\r\n", email)},
		{"Cc", fmt.Sprintf("Cc: Empty:;, Team: %s;\r\n", email)},
		{"Bcc", fmt.Sprintf("Bcc: team: %s;, undisclosed:;\r\n", email)},
		// One member listed in two groups and two headers is one recipient.
		{"RepeatedMember", fmt.Sprintf("To: Empty:;, Team: %s;\r\nCc: Others: %s;, %s\r\nBcc: Hidden: %s;\r\n", email, upper, email, email)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := "From: sender@example.org\r\n" + tc.headers +
				"Subject: grouped recipients\r\n\r\nbody\r\n"
			resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{"message": msg})
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("deliver: %d %s", resp.StatusCode, body)
			}
			var result adminapi.DeliverMailResponse
			if err := json.Unmarshal(body, &result); err != nil {
				t.Fatal(err)
			}
			if !result.Success || len(result.Recipients) != 1 || result.Recipients[0].Email != email || !result.Recipients[0].Accepted {
				t.Errorf("want the one group member %s accepted, got %+v", email, result)
			}
		})
	}

	resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{
		"message": "From: sender@example.org\r\nTo: undisclosed:;\r\nCc: Nobody:;\r\nBcc: Hidden:;\r\n\r\nbody\r\n",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("only empty groups: %d %s, want 400 (no recipient)", resp.StatusCode, body)
	}
}
