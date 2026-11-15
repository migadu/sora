//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// SENT* tests a parsed Date header; ON still tests INTERNALDATE. COPY must
// preserve that distinction, and pre-000061 NULL markers retain legacy behavior.
func TestIMAP_SentSearchSkipsMissingAndInvalidDates(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	require.NoError(t, rc.conn.SetDeadline(time.Now().Add(30*time.Second)))
	rc.login(account)
	for i, date := range []string{"", "Date: not-a-date\r\n", "Date: Thu, 02 Jan 2020 12:00:00 +0000\r\n", ""} {
		msg := fmt.Sprintf("From: a@example.com\r\nSubject: sent key %d\r\n%s\r\nbody\r\n", i, date)
		_, tagged := rc.cmd(fmt.Sprintf("a%d", i), fmt.Sprintf("APPEND INBOX \" 1-Jan-2020 10:00:00 +0000\" {%d+}\r\n%s", len(msg), msg))
		require.Contains(t, tagged, " OK ")
	}
	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	require.NoError(t, err)
	// Old rows cannot be distinguished from dated mail and intentionally keep
	// matching by sent_date. Model one alongside the newly marked no-Date rows.
	changed, err := server.ResilientDB.ExecWithRetry(context.Background(), `UPDATE messages SET sent_date_unknown = NULL WHERE account_id = $1 AND uid = 4`, accountID)
	require.NoError(t, err)
	require.EqualValues(t, 1, changed.RowsAffected())
	_, tagged := rc.cmd("c", "CREATE SentKeyCopy")
	require.Contains(t, tagged, " OK ")
	_, tagged = rc.cmd("s", "SELECT INBOX")
	require.Contains(t, tagged, " OK ")
	_, tagged = rc.cmd("cp", "COPY 1:4 SentKeyCopy")
	require.Contains(t, tagged, " OK ")
	for _, mailbox := range []string{"INBOX", "SentKeyCopy"} {
		_, tagged = rc.cmd("s", "SELECT "+mailbox)
		require.Contains(t, tagged, " OK ")
		for i, tc := range []struct{ cmd, want string }{
			{"UID SEARCH ON 1-Jan-2020", "* SEARCH 1 2 3 4"},
			{"UID SEARCH SENTON 1-Jan-2020", "* SEARCH 4"},
			{"UID SEARCH SENTSINCE 1-Jan-2020", "* SEARCH 3 4"},
			{"UID SEARCH SENTBEFORE 2-Jan-2020", "* SEARCH 4"},
			{"UID SEARCH NOT SENTON 1-Jan-2020", "* SEARCH 1 2 3"},
			{"UID SEARCH NOT SENTBEFORE 2-Jan-2020", "* SEARCH 1 2 3"},
			{"UID SEARCH OR SENTON 1-Jan-2020 SENTON 2-Jan-2020", "* SEARCH 3 4"},
			{"UID SORT (DATE) UTF-8 SENTON 1-Jan-2020", "* SORT 4"},
			{"UID THREAD REFERENCES UTF-8 SENTON 1-Jan-2020", "* THREAD (4)"},
			{"THREAD REFERENCES UTF-8 SENTON 1-Jan-2020", "* THREAD (4)"},
			{"THREAD REFERENCES UTF-8 NOT SENTON 1-Jan-2020", "* THREAD (1)(2)(3)"},
			{"THREAD REFERENCES UTF-8 OR SENTON 1-Jan-2020 SENTON 2-Jan-2020", "* THREAD (4)(3)"},
		} {
			t.Run(mailbox+" "+tc.cmd, func(t *testing.T) {
				lines, tagged := rc.cmd(fmt.Sprintf("q%d", i), tc.cmd)
				require.Contains(t, tagged, " OK ")
				require.Contains(t, lines, tc.want)
			})
		}
	}
	lines, tagged := rc.cmd("e", "ESEARCH IN (MAILBOXES (INBOX SentKeyCopy)) RETURN (ALL) SENTON 1-Jan-2020")
	require.Contains(t, tagged, " OK ")
	var results []string
	for _, line := range lines {
		if strings.HasPrefix(line, "* ESEARCH ") {
			results = append(results, line)
			require.Contains(t, line, " ALL 4")
		}
	}
	require.Len(t, results, 2, "one dated legacy result in each mailbox: %v", lines)
}
