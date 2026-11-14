//go:build integration

package pop3_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// pop3LoginCommands are the two ways a client logs in.
var pop3LoginCommands = []struct {
	name  string
	login func(t *testing.T, address, username, password string) string
}{
	{"USER/PASS", pop3UserPass},
	{"AUTH PLAIN", func(t *testing.T, address, username, password string) string {
		t.Helper()
		return pop3AuthPlain(t, address, "", username, password)
	}},
}

// TestPOP3LoginWithUnverifiableStoredHash: a stored hash sora cannot check says
// nothing about the submitted password, and only an administrator can repair it. The
// backend answers -ERR [SYS/TEMP] (RFC 3206 section 4), as the proxies do, logs the
// reason unverifiable_hash in the line that names the address, and does not count the
// login in the auth rate limiter: the user logs in as soon as the hash is repaired.
func TestPOP3LoginWithUnverifiableStoredHash(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := startPOP3WithMasterSASL(t, rdb, common.DBOutageAuthRateLimit(), "", "")
	logs := common.CaptureLogs(t)

	repair := common.StoreUnverifiableHash(t, rdb, account.Email, account.Password)
	for _, cmd := range pop3LoginCommands {
		for i := 1; i <= 2; i++ {
			if reply := cmd.login(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "-ERR [SYS/TEMP]") {
				t.Errorf("%s %d against an unverifiable stored hash: %q, want -ERR [SYS/TEMP] ...", cmd.name, i, reply)
			}
		}
	}
	repair()

	for _, cmd := range pop3LoginCommands {
		if reply := cmd.login(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "+OK") {
			t.Errorf("%s after the hash was repaired: %q, want +OK (the unverifiable hash was counted as failed logins)", cmd.name, reply)
		}
	}
	logs.WaitForLine(t, "authentication unavailable", account.Email, "reason=unverifiable_hash")
}

// TestPOP3UnverifiableStoredHashDropsCachedLogin: a login in the backend's lookup
// cache was verified against the hash stored before. A guess that misses it goes to
// the database, which gives no verdict, so the guess is not counted. The cached login
// must be dropped then, or every later guess is checked against the cached password,
// uncounted, until the entry is older than positive_revalidation_window.
func TestPOP3UnverifiableStoredHashDropsCachedLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := startPOP3WithMasterSASL(t, rdb, common.DBOutageAuthRateLimit(), "", "")

	if reply := pop3UserPass(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "+OK") {
		t.Fatalf("PASS with a valid stored hash: %q, want +OK", reply)
	}
	common.StoreUnverifiableHash(t, rdb, account.Email, account.Password)

	for i := 1; i <= 3; i++ {
		if reply := pop3UserPass(t, address, account.Email, fmt.Sprintf("guess-%d", i)); !strings.HasPrefix(reply, "-ERR [SYS/TEMP]") {
			t.Errorf("PASS with guess %d against an unverifiable stored hash: %q, want -ERR [SYS/TEMP] ...", i, reply)
		}
	}
	if reply := pop3UserPass(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "-ERR [SYS/TEMP]") {
		t.Errorf("PASS with the cached password after the guesses: %q, want -ERR [SYS/TEMP] (the uncounted guesses were checked against the cached login)", reply)
	}
}
