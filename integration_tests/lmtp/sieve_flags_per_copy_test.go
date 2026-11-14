//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
)

// TestLMTP_SieveFlagsPerCopy is issue #453: imap4flags flags belong to the copy one
// keep or fileinto stores. RFC 5232 §5: "The copy of the message filed into the
// mailbox will have only flags listed after the :flags tagged argument." §3: "If the
// :flags tagged argument is not specified with those two actions, the current value
// of the internal variable is used instead. The value of the internal variable also
// applies to the implicit keep." Every copy used to get one list, the internal
// variable as :flags had last overwritten it.
func TestLMTP_SieveFlagsPerCopy(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	for _, name := range []string{"Archive", "Projects"} {
		if _, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, name); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}

	lmtpAddr, _ := startTestLMTPServerWithOptions(t, rdb, lmtpserver.LMTPServerOptions{
		SieveExtensions: []string{"fileinto", "envelope", "mailbox", "subaddress", "variables", "imap4flags", "copy"},
	})

	cases := []struct {
		name   string
		script string
		want   map[string][]string
	}{
		{
			name:   "fileinto :flags then keep",
			script: `fileinto :flags "\\Flagged" "Archive"; keep;`,
			want:   map[string][]string{"Archive": {`\flagged`}, "INBOX": {}},
		},
		{
			name:   "each fileinto target its own flags",
			script: `fileinto :flags "\\Flagged" "Archive"; fileinto "Projects";`,
			want:   map[string][]string{"Archive": {`\flagged`}, "Projects": {}},
		},
		{
			name:   "fileinto :copy :flags, the implicit keep has the internal variable",
			script: `setflag "\\Seen"; fileinto :copy :flags "Work" "Archive";`,
			want:   map[string][]string{"Archive": {"work"}, "INBOX": {`\seen`}},
		},
		{
			name:   "the internal variable as it is when fileinto runs",
			script: `addflag "Work"; fileinto :copy "Archive"; removeflag "Work"; addflag "\\Seen";`,
			want:   map[string][]string{"Archive": {"work"}, "INBOX": {`\seen`}},
		},
		{
			name:   "keep :flags then fileinto :flags",
			script: `keep :flags "\\Flagged"; fileinto :flags "\\Seen" "Archive";`,
			want:   map[string][]string{"Archive": {`\seen`}, "INBOX": {`\flagged`}},
		},
		{
			name:   "keep :flags leaves the internal variable",
			script: `addflag "Work"; keep :flags "\\Flagged";`,
			want:   map[string][]string{"INBOX": {`\flagged`}},
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := `require ["fileinto", "imap4flags", "copy"];` + "\r\n" + tc.script + "\r\n"
			if _, err := rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountID); err != nil {
				t.Fatalf("clear sieve scripts: %v", err)
			}
			if _, err := rdb.ExecWithRetry(ctx, `
				INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
				VALUES ($1, $2, $3, true, NOW(), NOW())`,
				accountID, fmt.Sprintf("flags-per-copy-%d", i), script); err != nil {
				t.Fatalf("insert sieve: %v", err)
			}

			stamp := time.Now().UnixNano()
			subject := fmt.Sprintf("flags per copy %d", stamp)
			msg := strings.Join([]string{
				"From: sender@example.com",
				"To: " + account.Email,
				"Subject: " + subject,
				"Date: " + time.Now().Format(time.RFC1123Z),
				fmt.Sprintf("Message-ID: <flags-per-copy-%d@example.com>", stamp),
				"",
				"body",
			}, "\r\n")
			if resp := deliverLMTPRaw(t, lmtpAddr, "sender@example.com", account.Email, msg); !strings.HasPrefix(resp, "250") {
				t.Fatalf("delivery not accepted: %s", resp)
			}

			if got := common.SieveFlagsBySubject(t, rdb, accountID, subject); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("copies and their flags = %v, want %v", got, tc.want)
			}
		})
	}
}
