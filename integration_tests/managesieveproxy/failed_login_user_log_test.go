//go:build integration

package managesieveproxy_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// TestManageSieveProxyFailedDBLoginLogsUser covers #477 in the setup it was reported
// from: the remote lookup does not know the user, lookup_local_users sends the login on
// to PostgreSQL, and the password is wrong. The refusal must be logged with the user who
// tried it; it used to read user="" because the session's username was set only once a
// login had succeeded.
func TestManageSieveProxyFailedDBLoginLogsUser(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)

	email := fmt.Sprintf("failed-login-log-%d@example.com", time.Now().UnixNano())
	if _, err := rdb.CreateAccountWithRetry(context.Background(), db.CreateAccountRequest{
		Email: email, Password: "right-password", HashType: "bcrypt", IsPrimary: true,
	}); err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer lookup.Close()

	logs := common.CaptureLogs(t)
	proxyAddress := common.GetRandomAddress(t)
	// No login gets past authentication, so the backend is never dialed.
	proxy := setupManageSieveProxyWithFallback(t, rdb, proxyAddress, []string{"127.0.0.1:1"}, lookup.URL, true)
	defer proxy.Close()

	client, err := NewManageSieveClient(proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
	}
	defer client.Close()
	plain := base64.StdEncoding.EncodeToString([]byte("\x00" + email + "\x00wrong-password"))
	if err := client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", plain)); err != nil {
		t.Fatalf("Failed to send AUTHENTICATE: %v", err)
	}
	reply, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read AUTHENTICATE reply: %v", err)
	}
	if !strings.HasPrefix(reply, "NO") {
		t.Fatalf("AUTHENTICATE with a wrong password answered %q, want NO", reply)
	}

	line := logs.WaitForLine(t, "authentication failed", "method=main_db")
	if want := " user=" + email + " "; !strings.Contains(line, want) {
		t.Errorf("wrong password for %s logged as\n  %s\nwant it to name%s", email, line, want)
	}
}
