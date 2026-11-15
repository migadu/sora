//go:build integration

package managesieve

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestManageSieveLoginDuringDatabaseOutage: a login the database cannot answer is a
// temporary failure, NO (TRYLATER) (RFC 5804 section 1.3), not a failed
// authentication, and it is not counted by the auth rate limiter, so the user logs in
// once the database is back. AUTHENTICATE and LOGIN authenticate in separate
// functions, so both are probed.
func TestManageSieveLoginDuringDatabaseOutage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	account := common.CreateTestAccount(t, rdb)
	address := startManageSieveWithMasterSASL(t, rdb, common.DBOutageAuthRateLimit(), "", "")

	outage.Begin()
	for _, verb := range masterUsernameVerbs {
		for i := 1; i <= 2; i++ {
			if reply := verb.probe(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "NO (TRYLATER)") {
				t.Errorf("%s %d during a database outage: %q, want NO (TRYLATER) ...", verb.name, i, reply)
			}
		}
	}
	outage.End()

	for _, verb := range masterUsernameVerbs {
		if reply := verb.probe(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "OK") {
			t.Errorf("%s after the outage: %q, want OK (the outage was counted as failed logins)", verb.name, reply)
		}
	}
}

// TestManageSieveDatabaseOutageDropsCachedLogin: a login in the backend's lookup cache
// keeps signing in during a database outage while it is younger than
// positive_revalidation_window (30s by default). A password that misses it goes to the
// database, which gives no verdict, so the guess is not counted. The cached login must
// be dropped then, or every later guess is checked against the cached password,
// uncounted, until the entry is older than the window. Once the database is back, the
// user logs in: the guesses were not counted.
func TestManageSieveDatabaseOutageDropsCachedLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	account := common.CreateTestAccount(t, rdb)
	address := startManageSieveWithMasterSASL(t, rdb, common.DBOutageAuthRateLimit(), "", "")

	if reply := msAuthPlain(t, address, "", account.Email, account.Password); !strings.HasPrefix(reply, "OK") {
		t.Fatalf("AUTHENTICATE before the outage: %q, want OK", reply)
	}

	outage.Begin()
	if reply := msAuthPlain(t, address, "", account.Email, account.Password); !strings.HasPrefix(reply, "OK") {
		t.Errorf("AUTHENTICATE with the cached password during the outage, before any guess: %q, want OK (a cached login serves until a password misses it)", reply)
	}
	for i := 1; i <= 3; i++ {
		if reply := msAuthPlain(t, address, "", account.Email, fmt.Sprintf("guess-%d", i)); !strings.HasPrefix(reply, "NO (TRYLATER)") {
			t.Errorf("AUTHENTICATE with guess %d during the outage: %q, want NO (TRYLATER) ...", i, reply)
		}
	}
	if reply := msAuthPlain(t, address, "", account.Email, account.Password); !strings.HasPrefix(reply, "NO (TRYLATER)") {
		t.Errorf("AUTHENTICATE with the cached password after the guesses: %q, want NO (TRYLATER) (the uncounted guesses were checked against the cached login)", reply)
	}
	outage.End()

	if reply := msAuthPlain(t, address, "", account.Email, account.Password); !strings.HasPrefix(reply, "OK") {
		t.Errorf("AUTHENTICATE after the outage: %q, want OK (the guesses were counted as failed logins)", reply)
	}
}
