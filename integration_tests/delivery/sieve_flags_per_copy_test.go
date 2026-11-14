//go:build integration

package delivery_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// TestDelivery_SieveFlagsPerCopy is the Admin API /deliver counterpart of
// TestLMTP_SieveFlagsPerCopy (issue #453): each copy a keep or fileinto stores has
// that action's flags (RFC 5232 §3, §5), not one list applied to every copy.
func TestDelivery_SieveFlagsPerCopy(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	for _, name := range []string{"Archive", "Projects"} {
		_, err = rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, name)
		require.NoError(t, err)
	}
	recipient := newSelfRecipient(t, accountID, account.Email)

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
			name:   "keep :flags then fileinto :flags",
			script: `keep :flags "\\Flagged"; fileinto :flags "\\Seen" "Archive";`,
			want:   map[string][]string{"Archive": {`\seen`}, "INBOX": {`\flagged`}},
		},
		{
			name:   "fileinto :flags alone",
			script: `addflag "Work"; fileinto :flags "\\Flagged" "Archive";`,
			want:   map[string][]string{"Archive": {`\flagged`}},
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountID)
			require.NoError(t, err)
			script := fmt.Sprintf("require [\"fileinto\", \"imap4flags\", \"copy\"];\r\n# %d\r\n%s\r\n", i, tc.script)
			dctx := newSieveDeliveryContext(t, rdb, fake, accountID, script)

			subject := fmt.Sprintf("flags-per-copy-%d-%d", i, common.GetTimestamp())
			msg := []byte("From: sender@example.com\r\nTo: " + account.Email +
				"\r\nSubject: " + subject + "\r\nMessage-ID: <" + subject + "@example.com>\r\n\r\nbody\r\n")
			res, err := dctx.DeliverMessage(recipient, msg)
			require.NoError(t, err, "delivery failed (result=%+v)", res)
			require.True(t, res.Success, "delivery not accepted (result=%+v)", res)

			got := common.SieveFlagsBySubject(t, rdb, accountID, subject)
			require.Equal(t, tc.want, got, "copies and their flags")
		})
	}
}
