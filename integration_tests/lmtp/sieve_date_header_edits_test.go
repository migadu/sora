//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/stretchr/testify/require"
)

// Date tests must see the same current fields as the other header tests, including
// their order after addheader/deleteheader. A named false branch also proves an
// invalid date returns false rather than failing the script into implicit keep.
func TestLMTP_DateReadsEditedHeaders(t *testing.T) {
	extensions := sieveengine.EffectiveExtensions(append(slices.Clone(sieveengine.DefaultSieveExtensions), "editheader"))
	srv, _ := common.SetupLMTPServerWithOptions(t, lmtpserver.LMTPServerOptions{SieveExtensions: extensions})
	defer srv.Close()
	rdb, ctx := srv.ResilientDB, context.Background()
	for _, tc := range []struct{ name, pre, condition, want string }{
		{"deleted date count is zero", `deleteheader "Date";`, `date :count "eq" :comparator "i;ascii-numeric" "Date" "year" "0"`, "Matched"},
		{"added date field", `addheader "X-D" "Wed, 1 Apr 1998 09:06:31 -0800";`, `date :is "X-D" "year" "1998"`, "Matched"},
		{"prepended field is first", `addheader "Date" "Wed, 1 Apr 1998 09:06:31 -0800";`, `date :is "Date" "year" "1998"`, "Matched"},
		{"appended field is last", `addheader :last "Date" "Tue, 1 Apr 2003 09:06:31 -0800";`, `date :index 1 :last :is "Date" "year" "2003"`, "Matched"},
		{"delete first moves second into first", `deleteheader :index 1 "Date";`, `date :is "Date" "year" "2001"`, "Matched"},
		{"delete last retains original first", `deleteheader :index 1 :last "Date";`, `date :index 1 :last :is "Date" "year" "1997"`, "Matched"},
		{"index beyond edited fields counts zero", `deleteheader :index 1 "Date";`, `date :index 2 :count "eq" :comparator "i;ascii-numeric" "Date" "year" "0"`, "Matched"},
		{"malformed replacement counts zero", `deleteheader "Date"; addheader "Date" "not a date";`, `date :count "eq" :comparator "i;ascii-numeric" "Date" "year" "0"`, "Matched"},
		{"invalid first does not skip to a valid later field", `addheader "Date" "not a date";`, `date :is "Date" "year" "1997"`, "Fallback"},
		{"expanded header name sees edits", `set "which" "X-D"; addheader "X-D" "Wed, 1 Apr 1998 09:06:31 -0800";`, `date :is "${which}" "year" "1998"`, "Matched"},
		{"edited leap second survives", `addheader "Date" "Sat, 31 Dec 2016 23:59:60 +0000";`, `date :originalzone :is "Date" "second" "60"`, "Matched"},
		{"unchanged first field control", ``, `date :is "Date" "year" "1997"`, "Matched"},
		{"unchanged malformed field count control", ``, `date :count "eq" :comparator "i;ascii-numeric" "X-Bad" "year" "0"`, "Matched"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := common.CreateTestAccount(t, rdb)
			accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
			require.NoError(t, err)
			for _, folder := range []string{"Matched", "Fallback"} {
				require.NoError(t, rdb.CreateMailboxWithRetry(ctx, accountID, folder, nil))
			}
			script := `require ["date", "editheader", "index", "relational", "comparator-i;ascii-numeric", "variables", "fileinto"];` + tc.pre + `
if ` + tc.condition + ` { fileinto "Matched"; } else { fileinto "Fallback"; }`
			_, err = sieveengine.NewSieveExecutorWithExtensions(script, extensions)
			require.NoError(t, err, "script must compile before delivery")
			stored, err := rdb.CreateScriptWithRetry(ctx, accountID, "date-edits", script)
			require.NoError(t, err)
			require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, stored.ID, accountID, true))
			marker := fmt.Sprintf("date-edits-%d", time.Now().UnixNano())
			raw := "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: " + marker + "\r\nMessage-ID: <" + marker + "@example.com>\r\n" +
				"Date: Tue, 1 Apr 1997 09:06:31 -0800\r\nDate: Sun, 1 Apr 2001 09:06:31 -0800\r\nX-Bad: not a date\r\n\r\nbody\r\n"
			response := deliverLMTPRaw(t, srv.Address, "sender@example.com", account.Email, raw)
			require.True(t, strings.HasPrefix(response, "250"), "%s", response)
			require.Equal(t, 1, countForAccount(t, rdb, accountID))
			require.Equal(t, 1, countInMailbox(t, rdb, accountID, tc.want), "date test must use the current edited field list")
			require.Zero(t, countInMailbox(t, rdb, accountID, "INBOX"), "script must complete rather than fail into implicit keep")
		})
	}
}
