package adminapi

import (
	"encoding/json"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The affinity and ACL handlers answer their errors as the others do: an
// application/json {"error": "..."} body, encoded so that request input echoed in the
// message (a quote, a backslash, a newline) still decodes to what the client sent.
func TestAffinityAndACLErrorsAreJSON(t *testing.T) {
	// Request input with every character a hand-built JSON string breaks on.
	const hostile = "a\"b\\c\nd"

	newHandler := func(am AffinityManager) http.Handler {
		s, err := New(nil, ServerOptions{
			Name:            "json-errors",
			APIKey:          rwKey,
			AffinityManager: am,
			ValidBackends:   map[string][]string{"imap": {"192.0.2.21:143"}},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return s.setupRoutes()
	}
	withAffinity := newHandler(&fakeAffinityManager{entries: map[[2]string]string{}})
	// The ACL errors under test are all answered before the database is used.
	withoutAffinity := newHandler(nil)

	jsonBody := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		return string(b)
	}
	query := func(path string, v url.Values) string { return path + "?" + v.Encode() }
	hostileUser := hostile + "@example.com"
	hostileBackend := "192.0.2.99:143" + hostile

	tests := []struct {
		name     string
		h        http.Handler
		method   string
		target   string
		body     string
		status   int
		contains string // request input the decoded message must carry verbatim
	}{
		{"affinity set: invalid JSON", withAffinity, http.MethodPost, "/admin/affinity", "{", http.StatusBadRequest, ""},
		{"affinity set: missing fields", withAffinity, http.MethodPost, "/admin/affinity", "{}", http.StatusBadRequest, ""},
		{"affinity set: bad protocol", withAffinity, http.MethodPost, "/admin/affinity",
			jsonBody(AffinitySetRequest{User: "anna@example.com", Protocol: "smtp", Backend: "192.0.2.21:143"}), http.StatusBadRequest, ""},
		{"affinity set: unknown backend", withAffinity, http.MethodPost, "/admin/affinity",
			jsonBody(AffinitySetRequest{User: hostileUser, Protocol: "imap", Backend: hostileBackend}), http.StatusBadRequest, hostileBackend},
		{"affinity set: protocol without backends", withAffinity, http.MethodPost, "/admin/affinity",
			jsonBody(AffinitySetRequest{User: "anna@example.com", Protocol: "pop3", Backend: "192.0.2.21:110"}), http.StatusBadRequest, "pop3"},
		{"affinity set: no manager", withoutAffinity, http.MethodPost, "/admin/affinity",
			jsonBody(AffinitySetRequest{User: "anna@example.com", Protocol: "imap", Backend: "192.0.2.21:143"}), http.StatusServiceUnavailable, ""},
		{"affinity get: missing parameters", withAffinity, http.MethodGet, "/admin/affinity", "", http.StatusBadRequest, ""},
		{"affinity get: not found", withAffinity, http.MethodGet,
			query("/admin/affinity", url.Values{"user": {hostileUser}, "protocol": {"imap"}}), "", http.StatusNotFound, hostileUser},
		{"affinity get: no manager", withoutAffinity, http.MethodGet,
			query("/admin/affinity", url.Values{"user": {"anna@example.com"}, "protocol": {"imap"}}), "", http.StatusServiceUnavailable, ""},
		{"affinity delete: missing parameters", withAffinity, http.MethodDelete, "/admin/affinity", "", http.StatusBadRequest, ""},
		{"affinity delete: no manager", withoutAffinity, http.MethodDelete,
			query("/admin/affinity", url.Values{"user": {"anna@example.com"}, "protocol": {"imap"}}), "", http.StatusServiceUnavailable, ""},
		{"affinity list: no manager", withoutAffinity, http.MethodGet, "/admin/affinity/list", "", http.StatusServiceUnavailable, ""},

		{"acl grant: invalid JSON", withoutAffinity, http.MethodPost, "/admin/mailboxes/acl/grant", "{", http.StatusBadRequest, ""},
		{"acl grant: missing owner", withoutAffinity, http.MethodPost, "/admin/mailboxes/acl/grant",
			jsonBody(ACLGrantRequest{Mailbox: "Shared/Sales", Identifier: "bob@example.com", Rights: "lr"}), http.StatusBadRequest, ""},
		{"acl grant: missing mailbox", withoutAffinity, http.MethodPost, "/admin/mailboxes/acl/grant",
			jsonBody(ACLGrantRequest{Owner: "anna@example.com", Identifier: "bob@example.com", Rights: "lr"}), http.StatusBadRequest, ""},
		{"acl grant: missing identifier", withoutAffinity, http.MethodPost, "/admin/mailboxes/acl/grant",
			jsonBody(ACLGrantRequest{Owner: "anna@example.com", Mailbox: "Shared/Sales", Rights: "lr"}), http.StatusBadRequest, ""},
		{"acl grant: missing rights", withoutAffinity, http.MethodPost, "/admin/mailboxes/acl/grant",
			jsonBody(ACLGrantRequest{Owner: "anna@example.com", Mailbox: "Shared/Sales", Identifier: "bob@example.com"}), http.StatusBadRequest, ""},
		{"acl revoke: invalid JSON", withoutAffinity, http.MethodPost, "/admin/mailboxes/acl/revoke", "{", http.StatusBadRequest, ""},
		{"acl revoke: missing owner", withoutAffinity, http.MethodPost, "/admin/mailboxes/acl/revoke",
			jsonBody(ACLRevokeRequest{Mailbox: "Shared/Sales", Identifier: "bob@example.com"}), http.StatusBadRequest, ""},
		{"acl revoke: missing mailbox", withoutAffinity, http.MethodPost, "/admin/mailboxes/acl/revoke",
			jsonBody(ACLRevokeRequest{Owner: "anna@example.com", Identifier: "bob@example.com"}), http.StatusBadRequest, ""},
		{"acl revoke: missing identifier", withoutAffinity, http.MethodPost, "/admin/mailboxes/acl/revoke",
			jsonBody(ACLRevokeRequest{Owner: "anna@example.com", Mailbox: "Shared/Sales"}), http.StatusBadRequest, ""},
		{"acl list: missing owner", withoutAffinity, http.MethodGet,
			query("/admin/mailboxes/acl", url.Values{"mailbox": {"Shared/Sales"}}), "", http.StatusBadRequest, ""},
		{"acl list: missing mailbox", withoutAffinity, http.MethodGet,
			query("/admin/mailboxes/acl", url.Values{"owner": {"anna@example.com"}}), "", http.StatusBadRequest, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.target, strings.NewReader(tt.body))
			r.Header.Set("Authorization", "Bearer "+rwKey)
			w := httptest.NewRecorder()
			tt.h.ServeHTTP(w, r)

			if w.Code != tt.status {
				t.Fatalf("%s %s: status %d %q, want %d", tt.method, tt.target, w.Code, w.Body, tt.status)
			}
			if ct, _, err := mime.ParseMediaType(w.Header().Get("Content-Type")); err != nil || ct != "application/json" {
				t.Errorf("%s %s: Content-Type %q, want application/json", tt.method, tt.target, w.Header().Get("Content-Type"))
			}
			var resp map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("%s %s: body %q is not a JSON object of strings: %v", tt.method, tt.target, w.Body, err)
			}
			msg, ok := resp["error"]
			if !ok || msg == "" || len(resp) != 1 {
				t.Fatalf("%s %s: body %q, want only a non-empty \"error\"", tt.method, tt.target, w.Body)
			}
			if !strings.Contains(msg, tt.contains) {
				t.Errorf("%s %s: error %q does not carry the request input %q", tt.method, tt.target, msg, tt.contains)
			}
		})
	}
}
