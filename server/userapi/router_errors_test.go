package userapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// TestRouterErrorsAreJSON covers the errors the router writes itself, before any
// handler runs: a method the endpoint does not serve and a path no endpoint has.
// docs/USER_API.md (section 4, "Requests, responses and errors") promises that every error is a JSON
// object with an "error" field, so these must be application/json like the rest.
// A 405 must also carry an Allow header listing the endpoint's methods (RFC 9110
// section 15.5.6).
func TestRouterErrorsAreJSON(t *testing.T) {
	s, err := New(nil, ServerOptions{JWTSecret: "router-errors-test-secret-at-least-32-bytes"})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := s.generateToken("user@example.com", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	handler := s.SetupRoutes()

	tests := []struct {
		method, path string
		status       int
		allow        []string // for a 405: the methods the endpoint serves
	}{
		// Methods checked by routeHandler / multiMethodHandler.
		{"GET", "/user/auth/login", http.StatusMethodNotAllowed, []string{"POST"}},
		{"GET", "/user/auth/refresh", http.StatusMethodNotAllowed, []string{"POST"}},
		{"DELETE", "/user/mailboxes", http.StatusMethodNotAllowed, []string{"GET", "POST"}},
		{"POST", "/user/filters", http.StatusMethodNotAllowed, []string{"GET"}},

		// Methods checked by the sub-routers, after authentication.
		{"GET", "/user/mailboxes/INBOX/subscribe", http.StatusMethodNotAllowed, []string{"POST"}},
		{"GET", "/user/mailboxes/INBOX/unsubscribe", http.StatusMethodNotAllowed, []string{"POST"}},
		{"POST", "/user/mailboxes/INBOX/messages", http.StatusMethodNotAllowed, []string{"GET"}},
		{"POST", "/user/mailboxes/INBOX/search", http.StatusMethodNotAllowed, []string{"GET"}},
		// /user/mailboxes/{name} exists and serves DELETE only: a GET is a method
		// the resource does not support, not a missing resource.
		{"GET", "/user/mailboxes/INBOX", http.StatusMethodNotAllowed, []string{"DELETE"}},
		{"POST", "/user/messages/1/body", http.StatusMethodNotAllowed, []string{"GET"}},
		{"POST", "/user/messages/1/raw", http.StatusMethodNotAllowed, []string{"GET"}},
		{"POST", "/user/messages/1", http.StatusMethodNotAllowed, []string{"GET", "PATCH", "DELETE"}},
		{"POST", "/user/filters/capabilities", http.StatusMethodNotAllowed, []string{"GET"}},
		{"GET", "/user/filters/vacation/activate", http.StatusMethodNotAllowed, []string{"POST"}},
		{"POST", "/user/filters/vacation", http.StatusMethodNotAllowed, []string{"GET", "PUT", "DELETE"}},

		// Paths no endpoint serves.
		{"GET", "/user/not-an-endpoint", http.StatusNotFound, nil},
		{"POST", "/user/auth", http.StatusNotFound, nil},
		{"GET", "/", http.StatusNotFound, nil},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tt.status, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want \"application/json\" (body %q)", ct, rec.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Errorf("body %q is not JSON: %v", rec.Body.String(), err)
			} else if msg, ok := body["error"].(string); !ok || msg == "" || len(body) != 1 {
				t.Errorf("body = %q, want a single non-empty \"error\" string", rec.Body.String())
			}

			allow := rec.Header().Get("Allow")
			if tt.status != http.StatusMethodNotAllowed {
				if allow != "" {
					t.Errorf("Allow = %q on a %d, want none", allow, tt.status)
				}
				return
			}
			got := strings.Split(allow, ", ")
			slices.Sort(got)
			want := slices.Clone(tt.allow)
			want = append(want, http.MethodOptions)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("Allow = %q, want the methods %v", allow, want)
			}

			// OPTIONS is served by the CORS middleware on the same endpoint,
			// so its presence in Allow reflects actual supported behavior.
			options := httptest.NewRecorder()
			handler.ServeHTTP(options, httptest.NewRequest(http.MethodOptions, tt.path, nil))
			if options.Code != http.StatusOK {
				t.Errorf("OPTIONS status = %d, want %d", options.Code, http.StatusOK)
			}
		})
	}
}
