//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_SearchRateLimit_ChargesByCost checks over the wire which commands the
// search rate limit charges. With a budget of two searches, the commands a client
// navigates with (a SEARCH by UID set, sequence set or flag, a SORT or UID THREAD
// of one page's UIDs) run any number of times, before and after the budget is
// spent; content searches, whole-mailbox SORT and THREAD, and THREAD answered in
// sequence numbers spend it, and are then refused with NO [LIMIT] (RFC 5530)
// saying how long to wait.
func TestIMAP_SearchRateLimit_ChargesByCost(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Two searches an hour: nothing refills while the test runs.
	server, account := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{
		SearchRateLimitPerMin: 2,
		SearchRateLimitWindow: time.Hour,
	})
	defer server.Close()

	conn, r := esearchDialLogin(t, server, account.Email, account.Password)
	defer conn.Close()

	for i := 1; i <= 3; i++ {
		esearchAppend(t, conn, r, fmt.Sprintf("a%d", i), "INBOX", fmt.Sprintf("Rate %d", i))
	}
	esearchCmdOK(t, conn, r, "s1", "SELECT INBOX")

	free := []string{
		"UID SEARCH UID 1:3",
		"SEARCH 1:3",
		"UID SEARCH 1,3",
		"SEARCH UNSEEN",
		"UID SEARCH SINCE 1-Jan-2020 LARGER 1 NOT KEYWORD $Junk",
		"UID SORT (REVERSE DATE) UTF-8 UID 1:3",
		"SORT (REVERSE DATE) UTF-8 UID 1:3",
		"UID THREAD REFS UTF-8 UID 1:3",
	}
	tag := 0
	runFree := func(when string) {
		t.Helper()
		for _, cmd := range free {
			for range 3 {
				tag++
				esearchCmdOK(t, conn, r, fmt.Sprintf("f%d", tag), cmd)
			}
		}
		t.Logf("free commands ran %s the budget was spent", when)
	}

	runFree("before")

	esearchCmdOK(t, conn, r, "c1", `UID SEARCH FROM "nobody"`)
	esearchCmdOK(t, conn, r, "c2", "UID THREAD REFS UTF-8 ALL")

	refused := []string{
		"UID SORT (DATE) UTF-8 ALL",
		`UID SEARCH BODY "body"`,
		`SEARCH OR SEEN NOT SUBJECT "Rate"`,
		"UID SORT (DATE) UTF-8 UID 1:4294967295",
		"UID THREAD REFS UTF-8 UID 1:*",
		// Numbered by ranking every message in the mailbox, however few it names.
		"THREAD REFS UTF-8 UID 3",
		// A sequence set is mapped to UIDs by ranking the mailbox, so it confines nothing.
		"UID THREAD REFS UTF-8 1:3",
		"UID SORT (DATE) UTF-8 2",
		"ESEARCH IN (personal) RETURN (ALL) UNSEEN",
	}
	for i, cmd := range refused {
		rtag := fmt.Sprintf("r%d", i)
		_, tagged := esearchExec(t, conn, r, rtag, cmd)
		if !strings.HasPrefix(tagged, rtag+" NO [LIMIT] ") || !strings.Contains(tagged, "please wait") {
			t.Errorf("%s with the budget spent: got %q, want NO [LIMIT] with a time to wait", cmd, tagged)
		}
	}

	runFree("after")
}
