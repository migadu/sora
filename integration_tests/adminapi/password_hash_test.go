//go:build integration

package httpapi

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/server/adminapi"
)

// TestUnverifiablePasswordHashIsBadRequest: every route that takes a password_hash
// refuses one sora cannot verify (here a password pasted into the field) with 400 and
// stores nothing. It used to answer 201/200, and the credential could never sign in.
// A Dovecot spelling sora verifies ({ssha512.hex}, lower case) is stored and signs in.
func TestUnverifiablePasswordHashIsBadRequest(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()
	ctx := context.Background()
	stamp := time.Now().UnixNano()

	const password = "pw-123456"
	const unverifiable = "Secret-2026"
	salt := []byte("saltsalt")
	digest := sha512.Sum512(append([]byte(password), salt...))
	dovecot := "{ssha512.hex}" + hex.EncodeToString(append(digest[:], salt...))

	primary := fmt.Sprintf("hash-api-%d@example.com", stamp)
	if resp, body := server.makeRequest(t, "POST", "/admin/accounts", adminapi.CreateAccountRequest{Email: primary, Password: password}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create %s: got %d. Body: %s", primary, resp.StatusCode, body)
	}

	n := 0
	newAddress := func() string {
		n++
		return fmt.Sprintf("hash-api-%d-%d@example.com", n, stamp)
	}
	routes := []struct {
		name    string
		method  string
		path    func(address string) string
		body    func(address, hash string) any
		address func() string // the address the hash is stored for
	}{
		{"POST /admin/accounts", "POST",
			func(string) string { return "/admin/accounts" },
			func(address, hash string) any {
				return adminapi.CreateAccountRequest{Email: address, PasswordHash: hash}
			}, newAddress},
		{"POST /admin/accounts (credentials array)", "POST",
			func(string) string { return "/admin/accounts" },
			func(address, hash string) any {
				return adminapi.CreateAccountRequest{Credentials: []adminapi.CreateCredentialSpec{{Email: address, PasswordHash: hash, IsPrimary: true}}}
			}, newAddress},
		{"POST /admin/accounts/{email}/credentials", "POST",
			func(string) string { return "/admin/accounts/" + primary + "/credentials" },
			func(address, hash string) any {
				return adminapi.AddCredentialRequest{Email: address, PasswordHash: hash}
			},
			newAddress},
		{"PUT /admin/accounts/{email}", "PUT",
			func(address string) string { return "/admin/accounts/" + address },
			func(_, hash string) any { return adminapi.UpdateAccountRequest{PasswordHash: hash} },
			func() string { return primary }},
	}

	for _, r := range routes {
		t.Run(r.name, func(t *testing.T) {
			address := r.address()
			resp, body := server.makeRequest(t, r.method, r.path(address), r.body(address, unverifiable))
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("password_hash %q: got %d, want 400. Body: %s", unverifiable, resp.StatusCode, body)
			}
			if address == primary {
				// The refused update left the password as it was.
				if _, err := server.rdb.AuthenticateWithRetry(ctx, primary, password); err != nil {
					t.Errorf("%s no longer signs in with its password after a refused update: %v", primary, err)
				}
			} else if _, err := server.rdb.AuthenticateWithRetry(ctx, address, unverifiable); !errors.Is(err, consts.ErrUserNotFound) {
				t.Errorf("a credential was stored for %s: sign-in = %v, want user not found", address, err)
			}

			address = r.address()
			resp, body = server.makeRequest(t, r.method, r.path(address), r.body(address, dovecot))
			if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
				t.Fatalf("password_hash %q: got %d, want 201 or 200. Body: %s", dovecot, resp.StatusCode, body)
			}
			if _, err := server.rdb.AuthenticateWithRetry(ctx, address, password); err != nil {
				t.Errorf("%s does not sign in with the password of %q: %v", address, dovecot, err)
			}
		})
	}
}
