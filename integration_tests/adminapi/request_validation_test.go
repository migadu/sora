//go:build integration

package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server/adminapi"
)

const unparsableAddress = "not-an-address"

// TestUnparsableAddressIsBadRequest: an address that does not parse is the client's
// error on every account and credential route, answered 400 with the reason, so a
// provisioning client can tell a typo from a server failure.
func TestUnparsableAddressIsBadRequest(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	primary := fmt.Sprintf("addr-400-%d@example.com", time.Now().UnixNano())
	resp, body := server.makeRequest(t, "POST", "/admin/accounts", adminapi.CreateAccountRequest{Email: primary, Password: "pw-123456"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating %s: got %d. Body: %s", primary, resp.StatusCode, body)
	}

	tests := []struct {
		method, path string
		body         any
	}{
		{"GET", "/admin/accounts/" + unparsableAddress + "/exists", nil},
		{"GET", "/admin/accounts/" + unparsableAddress, nil},
		{"DELETE", "/admin/accounts/" + unparsableAddress, nil},
		{"DELETE", "/admin/accounts/" + unparsableAddress + "?purge=true", nil},
		{"POST", "/admin/accounts/" + unparsableAddress + "/restore", nil},
		{"GET", "/admin/accounts/" + unparsableAddress + "/credentials", nil},
		{"POST", "/admin/accounts/" + primary + "/credentials", adminapi.AddCredentialRequest{Email: unparsableAddress, Password: "pw-123456"}},
		{"DELETE", "/admin/credentials/" + unparsableAddress, nil},
	}
	for _, tt := range tests {
		resp, body := server.makeRequest(t, tt.method, tt.path, tt.body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s %s: got %d, want 400. Body: %s", tt.method, tt.path, resp.StatusCode, body)
			continue
		}
		if !strings.Contains(string(body), "address missing @") {
			t.Errorf("%s %s: the reason is missing from the body: %s", tt.method, tt.path, body)
		}
	}
}

// TestUnparsableAddressesKeepWritesAvailable: a rejected address is not a database
// failure, so a run of them cannot open the write circuit breaker and refuse every
// write on the node.
func TestUnparsableAddressesKeepWritesAvailable(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	for i := 0; i < 3; i++ {
		resp, body := server.makeRequest(t, "DELETE", "/admin/credentials/"+unparsableAddress, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("DELETE /admin/credentials/%s: got %d, want 400. Body: %s", unparsableAddress, resp.StatusCode, body)
		}
	}

	email := fmt.Sprintf("after-bad-addresses-%d@example.com", time.Now().UnixNano())
	resp, body := server.makeRequest(t, "POST", "/admin/accounts", adminapi.CreateAccountRequest{Email: email, Password: "pw-123456"})
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("valid create after rejected addresses: got %d, want 201. Body: %s", resp.StatusCode, body)
	}
}

// TestCredentialsArrayHashTypes: the credentials array hashes new passwords with the
// same schemes as sora-admin, bcrypt and ssha512. Unsalted sha512 is still verified
// for legacy credentials but is refused for new ones.
func TestCredentialsArrayHashTypes(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	create := func(hashType string) (string, *http.Response, []byte) {
		email := fmt.Sprintf("hash-%s-%d@example.com", hashType, time.Now().UnixNano())
		resp, body := server.makeRequest(t, "POST", "/admin/accounts", adminapi.CreateAccountRequest{
			Credentials: []adminapi.CreateCredentialSpec{{Email: email, Password: "pw-123456", IsPrimary: true, HashType: hashType}},
		})
		return email, resp, body
	}
	exists := func(email string) bool {
		resp, body := server.makeRequest(t, "GET", "/admin/accounts/"+email+"/exists", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("exists %s: got %d. Body: %s", email, resp.StatusCode, body)
		}
		var result struct {
			Exists bool `json:"exists"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("exists %s: %v", email, err)
		}
		return result.Exists
	}

	email, resp, body := create("sha512")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("hash_type sha512: got %d, want 400. Body: %s", resp.StatusCode, body)
	}
	if exists(email) {
		t.Errorf("hash_type sha512: account %s was created", email)
	}

	for _, hashType := range []string{"bcrypt", "ssha512"} {
		email, resp, body := create(hashType)
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("hash_type %s: got %d, want 201. Body: %s", hashType, resp.StatusCode, body)
			continue
		}
		if !exists(email) {
			t.Errorf("hash_type %s: account %s was not created", hashType, email)
		}
	}
}
