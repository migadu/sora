//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAPAuthenticationSuccessfulLogsAccountOnce covers #1168 at run time: the
// "authentication successful" line of every IMAP login form names the account once,
// in the session's own user and account_id fields. It used to be logged before the
// session took the user, with the account passed again, so the record carried
// account_id twice: 0 from the session and the account's id from the call (RFC 8259
// section 4: "The names within an object SHOULD be unique."). The source guard in
// logger/keyvalue_pairs_test.go catches the repeated key; this catches the line moving
// back above the assignment, which would log the login under account 0 again.
func TestIMAPAuthenticationSuccessfulLogsAccountOnce(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	srv, account := setupIMAPServerWithMasterAuth(t)
	defer srv.Close()
	accountID, err := srv.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	logins := []struct {
		name   string
		method string
		login  func() string
	}{
		{"LOGIN", "main_db", func() string {
			return imapLoginReply(t, srv.Address, account.Email, account.Password)
		}},
		{"LOGIN master username", "master", func() string {
			return imapLoginReply(t, srv.Address, account.Email+"@"+masterUsername, masterPassword)
		}},
		{"AUTHENTICATE PLAIN master username", "master", func() string {
			return imapAuthPlain(t, srv.Address, "", account.Email+"@"+masterUsername, masterPassword)
		}},
		{"AUTHENTICATE PLAIN master SASL", "master", func() string {
			return imapAuthPlain(t, srv.Address, account.Email, masterSASLUsername, masterSASLPassword)
		}},
	}
	for _, l := range logins {
		t.Run(l.name, func(t *testing.T) {
			logs := common.CaptureLogs(t)
			if reply := l.login(); !strings.Contains(reply, " OK") {
				t.Fatalf("%s: %q, want OK", l.name, reply)
			}
			// The session's line: IMAPServer.Authenticate also logs a regular login, with
			// no session fields.
			line := logs.WaitForLine(t, "authentication successful", " session=", "method="+l.method)
			if n := strings.Count(line, " account_id="); n != 1 {
				t.Errorf("%s logged account_id %d times:\n  %s", l.name, n, line)
			}
			if want := fmt.Sprintf(" account_id=%d ", accountID); !strings.Contains(line, want) {
				t.Errorf("%s logged as\n  %s\nwant it to name%s", l.name, line, want)
			}
			if want := " user=" + account.Email + " "; !strings.Contains(line, want) {
				t.Errorf("%s logged as\n  %s\nwant it to name%s", l.name, line, want)
			}
		})
	}
}
