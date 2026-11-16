//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
)

func TestLMTP_MalformedDateZoneDelivery(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	id, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatal(err)
	}
	setActiveSieveScript(t, rdb, id, `require ["date", "fileinto", "mailbox", "relational", "comparator-i;ascii-numeric"];
if allof (date :count "eq" :comparator "i;ascii-numeric" "date" "hour" "1",
 date :originalzone "date" "hour" "12",
 date :originalzone "date" "zone" "+0000",
 date :originalzone "date" "iso8601" "2019-01-01T12:00:00Z",
 date :originalzone "date" "std11" "Tue, 01 Jan 2019 12:00:00 +0000",
 date :zone "+0100" "date" "time" "13:00:00") { fileinto :create "Written"; }
else { fileinto :create "Other"; }
`)
	addr, _ := startTestLMTPServerWithOptions(t, rdb, lmtpserver.LMTPServerOptions{})
	for i, tc := range []struct{ zone, want string }{
		{"GMT+1", "Written"}, {"GMT-5", "Written"}, {"GMT+0200", "Written"},
		{"UTC-0500", "Written"}, {"PDT+0400", "Written"}, {"+01", "Written"},
		{"CET/CEST", "Written"}, {"PDT/UTC", "Written"}, {"XYZ", "Written"},
		{"+0000", "Written"}, {"-0000", "Written"}, {"PDT", "Other"}, {"PM -0700", "Other"},
	} {
		t.Run(tc.zone, func(t *testing.T) {
			marker := fmt.Sprintf("zone-%d-%d", time.Now().UnixNano(), i)
			msg := strings.Join([]string{"From: sender@example.com", "To: " + account.Email,
				"Subject: " + marker, "Message-ID: <" + marker + "@example.com>",
				"Date: Tue, 01 Jan 2019 12:00:00 " + tc.zone, "", "body"}, "\r\n")
			if resp := deliverLMTPRaw(t, addr, "sender@example.com", account.Email, msg); !strings.HasPrefix(resp, "250") {
				t.Fatalf("not accepted: %s", resp)
			}
			var name string
			err := rdb.QueryRowWithRetry(context.Background(), `SELECT mb.name FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND m.subject=$2 AND m.expunged_at IS NULL`, id, marker).Scan(&name)
			if err != nil {
				t.Fatal(err)
			}
			if name != tc.want {
				t.Errorf("zone %s stored in %s, want %s", tc.zone, name, tc.want)
			}
		})
	}
}
