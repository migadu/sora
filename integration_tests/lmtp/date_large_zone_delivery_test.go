//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

func TestLMTP_DateISO8601LargeZone(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	id, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatal(err)
	}
	addr := startTestLMTPServer(t, rdb)
	for i, tc := range []struct{ value, want string }{
		{"Tue, 01 Jan 2019 12:00:00 +2500", "2018-12-31T11:00:00Z"},
		{"Tue, 01 Jan 2019 12:00:00 -2500", "2019-01-02T13:00:00Z"},
		{"Tue, 01 Jan 2019 12:00:00 +2400", "2018-12-31T12:00:00Z"},
		{"Tue, 01 Jan 2019 12:00:00 +2359", "2019-01-01T12:00:00+23:59"},
		{"Mon, 02 Jan 2017 00:59:60 +2500", "2016-12-31T23:59:60Z"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			script := fmt.Sprintf(`require ["date","fileinto","mailbox"]; if date :originalzone "Date" "iso8601" %q {fileinto :create "Normalized";} else {fileinto :create "Wrong";}`, tc.want)
			setActiveSieveScript(t, rdb, id, script)
			marker := fmt.Sprintf("large-zone-%d", i)
			msg := "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: " + marker + "\r\nDate: " + tc.value + "\r\n\r\nbody"
			if reply := deliverLMTPRaw(t, addr, "sender@example.com", account.Email, msg); !strings.HasPrefix(reply, "250") {
				t.Fatalf("LMTP refused: %s", reply)
			}
			var name string
			if err := rdb.QueryRowWithRetry(ctx, `SELECT mb.name FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND m.subject=$2 AND m.expunged_at IS NULL`, id, marker).Scan(&name); err != nil {
				t.Fatal(err)
			}
			if name != "Normalized" {
				t.Fatalf("stored in %q, want Normalized", name)
			}
		})
	}
}
