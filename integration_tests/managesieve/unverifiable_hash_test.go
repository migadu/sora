//go:build integration

package managesieve

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestManageSieveLoginWithUnverifiableStoredHash: a stored hash sora cannot check
// says nothing about the submitted password, and only an administrator can repair it.
// The backend answers NO (TRYLATER) (RFC 5804 section 1.3), as the proxies do, logs
// the reason unverifiable_hash in the line that names the address, and does not count
// the login in the auth rate limiter: the user logs in as soon as the hash is
// repaired. AUTHENTICATE and LOGIN authenticate in separate functions, so both are
// probed.
func TestManageSieveLoginWithUnverifiableStoredHash(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := startManageSieveWithMasterSASL(t, rdb, common.DBOutageAuthRateLimit(), "", "")
	logs := common.CaptureLogs(t)

	repair := common.StoreUnverifiableHash(t, rdb, account.Email, account.Password)
	for _, verb := range masterUsernameVerbs {
		for i := 1; i <= 2; i++ {
			if reply := verb.probe(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "NO (TRYLATER)") {
				t.Errorf("%s %d against an unverifiable stored hash: %q, want NO (TRYLATER) ...", verb.name, i, reply)
			}
		}
	}
	repair()

	for _, verb := range masterUsernameVerbs {
		if reply := verb.probe(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "OK") {
			t.Errorf("%s after the hash was repaired: %q, want OK (the unverifiable hash was counted as failed logins)", verb.name, reply)
		}
	}
	logs.WaitForLine(t, "authentication unavailable", account.Email, "reason=unverifiable_hash")
}

// TestManageSieveUnverifiableStoredHashDropsCachedLogin: a login in the backend's
// lookup cache was verified against the hash stored before. A guess that misses it
// goes to the database, which gives no verdict, so the guess is not counted. The
// cached login must be dropped then, or every later guess is checked against the
// cached password, uncounted, until the entry is older than
// positive_revalidation_window.
func TestManageSieveUnverifiableStoredHashDropsCachedLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := startManageSieveWithMasterSASL(t, rdb, common.DBOutageAuthRateLimit(), "", "")

	if reply := msAuthPlain(t, address, "", account.Email, account.Password); !strings.HasPrefix(reply, "OK") {
		t.Fatalf("AUTHENTICATE with a valid stored hash: %q, want OK", reply)
	}
	common.StoreUnverifiableHash(t, rdb, account.Email, account.Password)

	for i := 1; i <= 3; i++ {
		if reply := msAuthPlain(t, address, "", account.Email, fmt.Sprintf("guess-%d", i)); !strings.HasPrefix(reply, "NO (TRYLATER)") {
			t.Errorf("AUTHENTICATE with guess %d against an unverifiable stored hash: %q, want NO (TRYLATER) ...", i, reply)
		}
	}
	if reply := msAuthPlain(t, address, "", account.Email, account.Password); !strings.HasPrefix(reply, "NO (TRYLATER)") {
		t.Errorf("AUTHENTICATE with the cached password after the guesses: %q, want NO (TRYLATER) (the uncounted guesses were checked against the cached login)", reply)
	}
}
