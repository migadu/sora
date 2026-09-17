//go:build integration

package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// A message with no text/plain or text/html part has no body to index, and the
// plaintext extractor reports that as no text at all rather than as an error. The
// delivery path has to take that as an empty body, as LMTP and APPEND do: these
// are ordinary messages (a scanner's PDF, a forwarded file) and must be stored.
func TestAdminAPI_DeliverMail_MessageWithoutTextPart(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	cases := []struct {
		name string
		body string
	}{
		{
			name: "attachment only",
			body: "Content-Type: multipart/mixed; boundary=\"b1\"\r\n" +
				"\r\n" +
				"--b1\r\n" +
				"Content-Type: application/pdf; name=\"scan.pdf\"\r\n" +
				"Content-Disposition: attachment; filename=\"scan.pdf\"\r\n" +
				"Content-Transfer-Encoding: base64\r\n" +
				"\r\n" +
				"JVBERi0xLjQK\r\n" +
				"--b1--\r\n",
		},
		{
			name: "single non-text part",
			body: "Content-Type: application/octet-stream\r\n" +
				"Content-Transfer-Encoding: base64\r\n" +
				"\r\n" +
				"AAECAwQF\r\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, tempDir := setupHTTPAPIServerWithUploader(t)
			defer server.Close()

			email := fmt.Sprintf("apinotext-%d@example.com", time.Now().UnixNano())
			createDeliveryAccount(t, server, email)

			subject := "no text part " + tc.name
			msg := "From: sender@example.com\r\nTo: " + email + "\r\nSubject: " + subject +
				"\r\nMIME-Version: 1.0\r\n" + tc.body
			resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{
				"recipients": []string{email},
				"message":    msg,
			})
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("deliver: %d %s", resp.StatusCode, string(body))
			}

			stored := readStoredAdminMessage(t, tempDir)
			if !strings.Contains(stored, "Subject: "+subject) {
				t.Fatalf("stored message is not the one delivered:\n%s", stored)
			}
		})
	}
}
