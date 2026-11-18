//go:build integration

package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestAdminAPI_DeliverMail_RefusesUnparseableSender is #1995: a sender the caller names
// (JSON "from", query or form "from", X-From header) that does not parse is refused with
// a 400, as LMTP refuses it at MAIL FROM, instead of delivering with no envelope sender.
// The null sender stays allowed, and a fallback taken from the message's From: header is
// still ignored when it does not parse: the caller did not name it.
func TestAdminAPI_DeliverMail_RefusesUnparseableSender(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := setupHTTPAPIServerWithOptions(t, nil)
	defer server.Close()

	email := fmt.Sprintf("apibadsender-%d@example.com", time.Now().UnixNano())
	createDeliveryAccount(t, server, email)

	message := func(from string) string {
		return "From: " + from + "\r\nTo: " + email + "\r\nSubject: who sent this\r\n" +
			fmt.Sprintf("Message-ID: <%d@example.net>\r\n\r\nbody\r\n", time.Now().UnixNano())
	}
	jsonBody := func(fields map[string]any) (string, []byte) {
		b, err := json.Marshal(fields)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return "application/json", b
	}
	const bad = "not an address"
	// net/mail reads this From: header, NewReversePath does not: "_" cannot stand in a
	// domain name (RFC 5321 §4.1.2 sub-domain), though it is atext to RFC 5322. Were the
	// fallback checked like a named sender, this delivery would get a 400.
	badDomain := "sender@bad_domain.example"

	for _, tc := range []struct {
		name   string
		build  func() (path, contentType string, header http.Header, body []byte)
		status int
	}{
		{name: "json from", status: http.StatusBadRequest, build: func() (string, string, http.Header, []byte) {
			ct, b := jsonBody(map[string]any{"recipients": []string{email}, "from": bad, "message": message("sender@example.net")})
			return "/admin/mail/deliver", ct, nil, b
		}},
		{name: "query from", status: http.StatusBadRequest, build: func() (string, string, http.Header, []byte) {
			q := url.Values{"recipients": {email}, "from": {bad}}
			return "/admin/mail/deliver?" + q.Encode(), "message/rfc822", nil, []byte(message("sender@example.net"))
		}},
		{name: "X-From header", status: http.StatusBadRequest, build: func() (string, string, http.Header, []byte) {
			q := url.Values{"recipients": {email}}
			return "/admin/mail/deliver?" + q.Encode(), "message/rfc822", http.Header{"X-From": {bad}}, []byte(message("sender@example.net"))
		}},
		{name: "form from", status: http.StatusBadRequest, build: func() (string, string, http.Header, []byte) {
			var buf bytes.Buffer
			mw := multipart.NewWriter(&buf)
			_ = mw.WriteField("recipients", email)
			_ = mw.WriteField("from", bad)
			_ = mw.WriteField("message", message("sender@example.net"))
			_ = mw.Close()
			return "/admin/mail/deliver", mw.FormDataContentType(), nil, buf.Bytes()
		}},
		{name: "null sender", status: http.StatusOK, build: func() (string, string, http.Header, []byte) {
			ct, b := jsonBody(map[string]any{"recipients": []string{email}, "from": "<>", "message": message("sender@example.net")})
			return "/admin/mail/deliver", ct, nil, b
		}},
		{name: "unparseable From header fallback", status: http.StatusOK, build: func() (string, string, http.Header, []byte) {
			ct, b := jsonBody(map[string]any{"recipients": []string{email}, "message": message(badDomain)})
			return "/admin/mail/deliver", ct, nil, b
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, ct, header, body := tc.build()
			req, err := http.NewRequest("POST", server.URL+path, bytes.NewReader(body))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			for k, v := range header {
				req.Header[k] = v
			}
			req.Header.Set("Content-Type", ct)
			req.Header.Set("Authorization", "Bearer "+testAPIKey)
			resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
			if err != nil {
				t.Fatalf("deliver: %v", err)
			}
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != tc.status {
				t.Fatalf("deliver: status %d %s, want %d", resp.StatusCode, respBody, tc.status)
			}
			if tc.status == http.StatusBadRequest {
				var e map[string]string
				if err := json.Unmarshal(respBody, &e); err != nil || !strings.HasPrefix(e["error"], "Invalid sender") {
					t.Errorf("deliver: body %s, want an error naming the invalid sender", respBody)
				}
			}
		})
	}
}
