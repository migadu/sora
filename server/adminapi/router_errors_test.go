package adminapi

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
// docs/ADMIN_API.md says errors are JSON objects with an "error" field, so these
// must be application/json like the rest. A 405 must also carry an Allow header
// listing the endpoint's methods (RFC 9110 section 15.5.6).
func TestRouterErrorsAreJSON(t *testing.T) {
	s, err := New(nil, ServerOptions{Name: "router-errors", APIKey: rwKey})
	if err != nil {
		t.Fatal(err)
	}
	handler := s.setupRoutes()

	tests := []struct {
		method, path string
		status       int
		allow        []string // for a 405: the methods the endpoint serves
	}{
		// Methods checked by routeHandler / multiMethodHandler.
		{"GET", "/admin/accounts", http.StatusMethodNotAllowed, []string{"POST"}},
		{"POST", "/admin/health/overview", http.StatusMethodNotAllowed, []string{"GET"}},
		{"DELETE", "/admin/accounts/user@example.com/restore", http.StatusMethodNotAllowed, []string{"POST"}},
		{"POST", "/admin/accounts/user@example.com", http.StatusMethodNotAllowed, []string{"GET", "PUT", "DELETE"}},
		{"PUT", "/admin/accounts/user@example.com/credentials", http.StatusMethodNotAllowed, []string{"GET", "POST"}},
		{"PUT", "/admin/affinity", http.StatusMethodNotAllowed, []string{"GET", "POST", "DELETE"}},

		// Methods checked by the domain and health sub-routers.
		{"POST", "/admin/domains/example.com/accounts", http.StatusMethodNotAllowed, []string{"GET"}},
		{"DELETE", "/admin/health/servers/node1", http.StatusMethodNotAllowed, []string{"GET"}},
		{"POST", "/admin/health/servers/node1/components/database", http.StatusMethodNotAllowed, []string{"GET"}},

		// Paths no endpoint serves.
		{"GET", "/admin/not-an-endpoint", http.StatusNotFound, nil},
		{"POST", "/admin/not-an-endpoint", http.StatusNotFound, nil},
		{"GET", "/admin/domains/example.com/aliases", http.StatusNotFound, nil},
		{"GET", "/", http.StatusNotFound, nil},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+rwKey)
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
			// The router answers OPTIONS on every endpoint, so it is one of the
			// endpoint's methods too.
			want := append(slices.Clone(tt.allow), http.MethodOptions)
			slices.Sort(want)
			got := strings.Split(allow, ", ")
			slices.Sort(got)
			if !slices.Equal(got, want) {
				t.Errorf("Allow = %q, want the methods %v", allow, want)
			}

			// The OPTIONS answer names the same methods (RFC 9110 section 9.3.7).
			opt := httptest.NewRequest(http.MethodOptions, tt.path, nil)
			opt.Header.Set("Authorization", "Bearer "+rwKey)
			optRec := httptest.NewRecorder()
			handler.ServeHTTP(optRec, opt)
			if optRec.Code != http.StatusOK {
				t.Errorf("OPTIONS status = %d, want %d", optRec.Code, http.StatusOK)
			}
			if optAllow := optRec.Header().Get("Allow"); optAllow != allow {
				t.Errorf("OPTIONS Allow = %q, want %q as on the 405", optAllow, allow)
			}
		})
	}
}
