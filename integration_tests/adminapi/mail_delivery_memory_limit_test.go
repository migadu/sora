//go:build integration

package httpapi

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/adminapi"
)

// TestAdminAPI_DeliverMail_MemoryLimit (#2111): /admin/mail/deliver charges the
// request body as it is read, the message copy it delivers from, and the base64
// copy of NUL-bearing parts to the server's delivery memory budget
// (limits.delivery_memory_limit). A delivery that does not fit gets 503 with
// Retry-After and stores nothing; one that fits is accepted afterwards.
func TestAdminAPI_DeliverMail_MemoryLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	const budget = 64 << 10
	server, _ := setupHTTPAPIServerWithOptions(t, func(o *adminapi.ServerOptions) { o.DeliveryMemoryLimit = budget })
	defer server.Close()

	email := fmt.Sprintf("apimem-%d@example.com", time.Now().UnixNano())
	createDeliveryAccount(t, server, email)

	message := func(subject, header, body string) string {
		return fmt.Sprintf("From: sender@example.com\r\nTo: %s\r\nSubject: %s\r\n%s\r\n%s", email, subject, header, body)
	}
	small := message("small", "", "hello\r\n")
	large := message("large", "", strings.Repeat("0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop\r\n", 2*budget/64))
	// Fits the budget as received; with the base64 copy of its NUL-bearing part it does not.
	nul := message("nul", "Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n",
		strings.Repeat("\x00\x01abcdefghijklmnopqrstuvwxyz\r\n", (28<<10)/30))

	raw := func(msg string) (int, string) {
		t.Helper()
		req, err := http.NewRequest("POST", server.URL+"/admin/mail/deliver?recipients="+email, bytes.NewBufferString(msg))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "message/rfc822")
		req.Header.Set("Authorization", "Bearer "+testAPIKey)
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get("Retry-After") == "" {
			t.Errorf("503 without Retry-After: %s", body)
		}
		return resp.StatusCode, string(body)
	}
	jsonDeliver := func(msg string) (int, string) {
		t.Helper()
		resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{"recipients": []string{email}, "message": msg})
		return resp.StatusCode, string(body)
	}

	for _, step := range []struct {
		name    string
		deliver func(string) (int, string)
		msg     string
		want    int
	}{
		{"raw: small message fits", raw, small, http.StatusOK},
		{"raw: message larger than the budget", raw, large, http.StatusServiceUnavailable},
		{"raw: body fits but its encoded copy does not", raw, nul, http.StatusServiceUnavailable},
		{"json: message larger than the budget", jsonDeliver, large, http.StatusServiceUnavailable},
		{"json: small message fits after the refusals", jsonDeliver, small, http.StatusOK},
	} {
		if got, body := step.deliver(step.msg); got != step.want {
			t.Errorf("%s: status %d (%s), want %d", step.name, got, body, step.want)
		}
	}
}
