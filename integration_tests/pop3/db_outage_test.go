//go:build integration

package pop3_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestPOP3LoginDuringDatabaseOutage: a login the database cannot answer is a temporary
// failure, -ERR [SYS/TEMP] (RFC 3206 section 4), not [AUTH], and it is not counted by
// the auth rate limiter, so the user logs in once the database is back.
func TestPOP3LoginDuringDatabaseOutage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	account := common.CreateTestAccount(t, rdb)
	address := startPOP3WithMasterSASL(t, rdb, common.DBOutageAuthRateLimit(), "", "")

	outage.Begin()
	for i := 1; i <= 3; i++ {
		if reply := pop3UserPass(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "-ERR [SYS/TEMP]") {
			t.Errorf("PASS %d during a database outage: %q, want -ERR [SYS/TEMP] ...", i, reply)
		}
	}
	outage.End()

	if reply := pop3UserPass(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "+OK") {
		t.Errorf("PASS after the outage: %q, want +OK (the outage was counted as failed logins)", reply)
	}
}

// TestPOP3DatabaseOutageDropsCachedLogin: a login in the backend's lookup cache keeps
// signing in during a database outage while it is younger than
// positive_revalidation_window (30s by default). A password that misses it goes to the
// database, which gives no verdict, so the guess is not counted. The cached login must
// be dropped then, or every later guess is checked against the cached password,
// uncounted, until the entry is older than the window. Once the database is back, the
// user logs in: the guesses were not counted.
//
// A POP3 session needs the database right after the login, so during the outage a
// cached login gets the same -ERR [SYS/TEMP] as a login the database could not
// answer, only many seconds later. The log line says where the login was answered.
func TestPOP3DatabaseOutageDropsCachedLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	account := common.CreateTestAccount(t, rdb)
	address := startPOP3WithMasterSASL(t, rdb, common.DBOutageAuthRateLimit(), "", "")

	if reply := pop3UserPass(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "+OK") {
		t.Fatalf("PASS before the outage: %q, want +OK", reply)
	}

	outage.Begin()
	for i := 1; i <= 3; i++ {
		if reply := pop3UserPass(t, address, account.Email, fmt.Sprintf("guess-%d", i)); !strings.HasPrefix(reply, "-ERR [SYS/TEMP]") {
			t.Errorf("PASS with guess %d during the outage: %q, want -ERR [SYS/TEMP] ...", i, reply)
		}
	}
	logs := common.CaptureLogs(t)
	if reply := pop3UserPass(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "-ERR [SYS/TEMP]") {
		t.Errorf("PASS with the cached password after the guesses: %q, want -ERR [SYS/TEMP]", reply)
	}
	// Asked the database, not signed in from the cache: the uncounted guesses were not
	// checked against the cached login.
	logs.WaitForLine(t, "authentication unavailable", account.Email, "method=main_db")
	outage.End()

	if reply := pop3UserPass(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "+OK") {
		t.Errorf("PASS after the outage: %q, want +OK (the guesses were counted as failed logins)", reply)
	}
}
