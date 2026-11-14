//go:build integration

package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server/adminapi"
)

// TestAccountPathDecodedOnce checks that the deleted-message endpoints read the
// account address from the path decoded once, as the other account endpoints do:
// a "+" (raw or as %2B) stays a plus and does not become a space.
func TestAccountPathDecodedOnce(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	email := fmt.Sprintf("plus+tag-%d@example.com", time.Now().UnixNano())
	resp, body := server.makeRequest(t, "POST", "/admin/accounts", adminapi.CreateAccountRequest{Email: email, Password: "test-password"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create account: %d - %s", resp.StatusCode, string(body))
	}

	for _, seg := range []string{email, strings.Replace(email, "+", "%2B", 1)} {
		t.Run(seg, func(t *testing.T) {
			// Control: this endpoint already uses the path segment once.
			if resp, body := server.makeRequest(t, "GET", "/admin/accounts/"+seg, nil); resp.StatusCode != http.StatusOK {
				t.Fatalf("GET /admin/accounts/%s: %d - %s", seg, resp.StatusCode, string(body))
			}

			resp, body := server.makeRequest(t, "GET", "/admin/accounts/"+seg+"/messages/deleted", nil)
			if resp.StatusCode != http.StatusOK {
				t.Errorf("GET .../messages/deleted: %d - %s", resp.StatusCode, string(body))
			} else {
				var result map[string]any
				server.expectJSON(t, body, &result)
				if result["email"] != email {
					t.Errorf("GET .../messages/deleted: email %v, want %q", result["email"], email)
				}
			}

			resp, body = server.makeRequest(t, "POST", "/admin/accounts/"+seg+"/messages/restore", map[string]string{"mailbox": "INBOX"})
			if resp.StatusCode != http.StatusOK {
				t.Errorf("POST .../messages/restore: %d - %s", resp.StatusCode, string(body))
			}
		})
	}
}
