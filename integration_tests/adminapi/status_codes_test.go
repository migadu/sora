//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server/adminapi"
)

// A provisioning client tells "fix your request" (4xx) from "retry later" (5xx) by the
// status alone, so account writes must not answer a request error as a server error.
func TestAccountWriteStatusCodes(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	unique := func(prefix string) string {
		return fmt.Sprintf("%s-%d@example.com", prefix, time.Now().UnixNano())
	}
	create := func(t *testing.T, email string) {
		t.Helper()
		resp, body := server.makeRequest(t, "POST", "/admin/accounts", adminapi.CreateAccountRequest{Email: email, Password: "pw-123456"})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %s: %d %s", email, resp.StatusCode, body)
		}
	}
	expect := func(t *testing.T, method, path string, req any, want int) {
		t.Helper()
		resp, body := server.makeRequest(t, method, path, req)
		if resp.StatusCode != want {
			t.Errorf("%s %s: got %d, want %d. Body: %s", method, path, resp.StatusCode, want, body)
		}
	}

	t.Run("create existing address is 409", func(t *testing.T) {
		email := unique("existing")
		create(t, email)
		expect(t, "POST", "/admin/accounts", adminapi.CreateAccountRequest{Email: email, Password: "pw-123456"}, http.StatusConflict)
	})

	t.Run("create address in deletion grace period is 409", func(t *testing.T) {
		email := unique("grace")
		create(t, email)
		if err := server.rdb.DeleteAccountWithRetry(context.Background(), email); err != nil {
			t.Fatalf("soft-delete: %v", err)
		}
		expect(t, "POST", "/admin/accounts", adminapi.CreateAccountRequest{Email: email, Password: "pw-123456"}, http.StatusConflict)
	})

	t.Run("create invalid address is 400", func(t *testing.T) {
		expect(t, "POST", "/admin/accounts", adminapi.CreateAccountRequest{Email: "not-an-address", Password: "pw-123456"}, http.StatusBadRequest)
	})

	cred := func(email string, primary bool) adminapi.CreateCredentialSpec {
		return adminapi.CreateCredentialSpec{Email: email, Password: "pw-123456", IsPrimary: primary}
	}
	createWith := func(creds ...adminapi.CreateCredentialSpec) adminapi.CreateAccountRequest {
		return adminapi.CreateAccountRequest{Credentials: creds}
	}

	t.Run("credentials with an existing address is 409", func(t *testing.T) {
		existing := unique("cred-existing")
		create(t, existing)
		expect(t, "POST", "/admin/accounts", createWith(cred(unique("cred-new"), true), cred(existing, false)), http.StatusConflict)
	})

	t.Run("credentials without a primary is 400", func(t *testing.T) {
		expect(t, "POST", "/admin/accounts", createWith(cred(unique("noprimary-a"), false), cred(unique("noprimary-b"), false)), http.StatusBadRequest)
	})

	t.Run("credentials with two primaries is 400", func(t *testing.T) {
		expect(t, "POST", "/admin/accounts", createWith(cred(unique("twoprimary-a"), true), cred(unique("twoprimary-b"), true)), http.StatusBadRequest)
	})

	t.Run("credentials naming one address twice is 400", func(t *testing.T) {
		email := unique("twice")
		expect(t, "POST", "/admin/accounts", createWith(cred(email, true), cred(email, false)), http.StatusBadRequest)
	})

	t.Run("credentials with an invalid address is 400", func(t *testing.T) {
		expect(t, "POST", "/admin/accounts", createWith(cred(unique("valid"), true), cred("not-an-address", false)), http.StatusBadRequest)
	})

	t.Run("credentials with an unknown hash_type is 400", func(t *testing.T) {
		c := cred(unique("hashtype"), true)
		c.HashType = "no-such-hash"
		expect(t, "POST", "/admin/accounts", createWith(c), http.StatusBadRequest)
	})

	t.Run("update unknown account is 404", func(t *testing.T) {
		expect(t, "PUT", "/admin/accounts/"+unique("nobody"), adminapi.UpdateAccountRequest{Password: "pw-123456"}, http.StatusNotFound)
	})

	t.Run("update invalid address is 400", func(t *testing.T) {
		expect(t, "PUT", "/admin/accounts/not-an-address", adminapi.UpdateAccountRequest{Password: "pw-123456"}, http.StatusBadRequest)
	})

	// bcrypt hashes at most 72 bytes, so a longer password is one the client must change.
	tooLong := strings.Repeat("p", 73)

	t.Run("create with a password over 72 bytes is 400", func(t *testing.T) {
		expect(t, "POST", "/admin/accounts", adminapi.CreateAccountRequest{Email: unique("longpw-create"), Password: tooLong}, http.StatusBadRequest)
	})

	t.Run("credentials with a password over 72 bytes is 400", func(t *testing.T) {
		c := cred(unique("longpw-cred"), true)
		c.Password = tooLong
		expect(t, "POST", "/admin/accounts", createWith(c), http.StatusBadRequest)
	})

	t.Run("update with a password over 72 bytes is 400", func(t *testing.T) {
		email := unique("longpw-update")
		create(t, email)
		expect(t, "PUT", "/admin/accounts/"+email, adminapi.UpdateAccountRequest{Password: tooLong}, http.StatusBadRequest)
	})
}

// GET /admin/health/servers/{hostname}/components/{component}: 404 only when there is no
// such component, 200 with the status when there is, and a server error (not 404) when
// the database cannot be asked.
func TestHealthComponentStatusCodes(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()

	hostname := fmt.Sprintf("health-codes-%d.example.com", time.Now().UnixNano())

	t.Run("unknown component is 404", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/health/servers/"+hostname+"/components/no_such_component", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("got %d, want 404. Body: %s", resp.StatusCode, body)
		}
	})

	t.Run("stored component is 200", func(t *testing.T) {
		if err := server.rdb.StoreHealthStatusWithRetry(context.Background(), hostname, "database", db.StatusHealthy, nil, 1, 0, nil); err != nil {
			t.Fatalf("store health status: %v", err)
		}
		resp, body := server.makeRequest(t, "GET", "/admin/health/servers/"+hostname+"/components/database", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("got %d, want 200. Body: %s", resp.StatusCode, body)
		}
		var status map[string]any
		server.expectJSON(t, body, &status)
		if status["component_name"] != "database" {
			t.Errorf("body does not describe the component: %s", body)
		}
	})

	t.Run("database failure is 500", func(t *testing.T) {
		broken := setupHTTPAPIServer(t)
		defer broken.Close()
		broken.rdb.Close()

		resp, body := broken.makeRequest(t, "GET", "/admin/health/servers/"+hostname+"/components/database", nil)
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("got %d, want 500. Body: %s", resp.StatusCode, body)
		}
	})
}

// A request error is the client's, not a database failure: a run of them must not open
// the node's database write circuit breaker, which would refuse every write on the node
// (deliveries included) until it closes again.
func TestBadAccountRequestsKeepWritesAvailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  func(i int) adminapi.CreateAccountRequest
	}{
		{"invalid address", func(int) adminapi.CreateAccountRequest {
			return adminapi.CreateAccountRequest{Email: "not-an-address", Password: "pw-123456"}
		}},
		{"password over 72 bytes", func(i int) adminapi.CreateAccountRequest {
			email := fmt.Sprintf("longpw-%d-%d@example.com", i, time.Now().UnixNano())
			return adminapi.CreateAccountRequest{Email: email, Password: strings.Repeat("p", 73)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A server of its own: a fresh database handle, so a fresh write breaker.
			server := setupHTTPAPIServer(t)
			defer server.Close()

			for i := 0; i < 4; i++ {
				resp, body := server.makeRequest(t, "POST", "/admin/accounts", tc.bad(i))
				if resp.StatusCode < 400 {
					t.Fatalf("bad request accepted: %d %s", resp.StatusCode, body)
				}
			}

			email := fmt.Sprintf("after-bad-requests-%d@example.com", time.Now().UnixNano())
			resp, body := server.makeRequest(t, "POST", "/admin/accounts", adminapi.CreateAccountRequest{Email: email, Password: "pw-123456"})
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("valid create after bad ones: got %d, want 201. Body: %s", resp.StatusCode, body)
			}
		})
	}
}
