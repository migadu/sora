//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// imapLoginCommands are the two commands a client logs in with. Each returns the
// reply without its tag.
var imapLoginCommands = []struct {
	name  string
	login func(t *testing.T, address, username, password string) string
}{
	{"LOGIN", func(t *testing.T, address, username, password string) string {
		t.Helper()
		return strings.TrimPrefix(imapLoginReply(t, address, username, password), "a1 ")
	}},
	{"AUTHENTICATE PLAIN", func(t *testing.T, address, username, password string) string {
		t.Helper()
		return strings.TrimPrefix(imapAuthPlain(t, address, "", username, password), "A001 ")
	}},
}

// TestIMAPLoginWithUnverifiableStoredHash: a stored hash sora cannot check says
// nothing about the submitted password, and only an administrator can repair it. The
// backend answers NO [UNAVAILABLE] (RFC 5530 section 3), as the proxies do, logs the
// reason unverifiable_hash in the line that names the address, and does not count the
// login in the auth rate limiter: the user logs in as soon as the hash is repaired.
func TestIMAPLoginWithUnverifiableStoredHash(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := startIMAPWithMasterSASL(t, rdb, common.DBOutageAuthRateLimit(), "", "")
	logs := common.CaptureLogs(t)

	repair := common.StoreUnverifiableHash(t, rdb, account.Email, account.Password)
	for _, cmd := range imapLoginCommands {
		for i := 1; i <= 2; i++ {
			if reply := cmd.login(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "NO [UNAVAILABLE]") {
				t.Errorf("%s %d against an unverifiable stored hash: %q, want NO [UNAVAILABLE] ...", cmd.name, i, reply)
			}
		}
	}
	repair()

	for _, cmd := range imapLoginCommands {
		if reply := cmd.login(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "OK") {
			t.Errorf("%s after the hash was repaired: %q, want OK (the unverifiable hash was counted as failed logins)", cmd.name, reply)
		}
	}
	logs.WaitForLine(t, "authentication unavailable", account.Email, "reason=unverifiable_hash")
}

// TestIMAPUnverifiableStoredHashDropsCachedLogin: a login in the backend's lookup
// cache was verified against the hash stored before. A guess that misses it goes to
// the database, which gives no verdict, so the guess is not counted. The cached login
// must be dropped then, or every later guess is checked against the cached password,
// uncounted, until the entry is older than positive_revalidation_window.
func TestIMAPUnverifiableStoredHashDropsCachedLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := startIMAPWithMasterSASL(t, rdb, common.DBOutageAuthRateLimit(), "", "")

	if reply := imapLoginReply(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "a1 OK") {
		t.Fatalf("LOGIN with a valid stored hash: %q, want a1 OK", reply)
	}
	common.StoreUnverifiableHash(t, rdb, account.Email, account.Password)

	for i := 1; i <= 3; i++ {
		if reply := imapLoginReply(t, address, account.Email, fmt.Sprintf("guess-%d", i)); !strings.HasPrefix(reply, "a1 NO [UNAVAILABLE]") {
			t.Errorf("LOGIN with guess %d against an unverifiable stored hash: %q, want a1 NO [UNAVAILABLE] ...", i, reply)
		}
	}
	if reply := imapLoginReply(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "a1 NO [UNAVAILABLE]") {
		t.Errorf("LOGIN with the cached password after the guesses: %q, want a1 NO [UNAVAILABLE] (the uncounted guesses were checked against the cached login)", reply)
	}
}
