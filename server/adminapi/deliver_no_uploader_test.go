package adminapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A node without an upload worker (no imap, pop3 or lmtp server configured) cannot
// deliver at all. That is the node's state, not the request's fault: the answer must be
// a server-side 503 with Retry-After, so an injector retries (elsewhere) instead of
// bouncing the message as it would on a 400.
func TestDeliverMailWithoutUploaderIsServerSide(t *testing.T) {
	for _, tc := range []struct {
		name       string
		recipients string
	}{
		{"one recipient", `["user@example.com"]`},
		{"two recipients", `["user@example.com","other@example.com"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{}
			body := `{"recipients":` + tc.recipients + `,"message":"From: a@example.org\r\nSubject: t\r\n\r\nbody\r\n"}`
			req := httptest.NewRequest("POST", "/admin/mail/deliver", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			s.handleDeliverMail(rec, req)

			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
				t.Fatalf("delivery on a node without an uploader: %d, Retry-After %q, body %s; want 503 with Retry-After",
					rec.Code, rec.Header().Get("Retry-After"), strings.TrimSpace(rec.Body.String()))
			}
		})
	}
}
