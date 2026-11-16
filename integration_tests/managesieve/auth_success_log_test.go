//go:build integration

package managesieve

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestManageSieveMasterAuthenticationSuccessfulLogsAccountOnce covers #1168 at run
// time: the master login's "authentication successful" line names the account once,
// in the session's own user and account_id fields. It used to be logged before the
// session took the user, with the account passed again, so the record carried
// account_id twice: 0 from the session and the account's id from the call.
func TestManageSieveMasterAuthenticationSuccessfulLogsAccountOnce(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	srv, account := setupManageSieveServerWithMasterAuth(t)
	defer srv.Close()
	accountID, err := srv.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	logs := common.CaptureLogs(t)
	client, err := NewManageSieveClient(srv.Address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	defer client.Close()
	plain := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "@" + masterUsername + "\x00" + masterPassword))
	if err := client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", plain)); err != nil {
		t.Fatalf("Failed to send AUTHENTICATE: %v", err)
	}
	if reply, err := client.ReadResponse(); err != nil || !strings.HasPrefix(reply, "OK") {
		t.Fatalf("AUTHENTICATE PLAIN master username: %q (err: %v), want OK", reply, err)
	}

	line := logs.WaitForLine(t, "authentication successful", " session=", "method=master")
	if n := strings.Count(line, " account_id="); n != 1 {
		t.Errorf("master login logged account_id %d times:\n  %s", n, line)
	}
	if want := fmt.Sprintf(" account_id=%d ", accountID); !strings.Contains(line, want) {
		t.Errorf("master login logged as\n  %s\nwant it to name%s", line, want)
	}
	if want := " user=" + account.Email + " "; !strings.Contains(line, want) {
		t.Errorf("master login logged as\n  %s\nwant it to name%s", line, want)
	}
}
