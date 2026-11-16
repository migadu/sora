//go:build integration

package delivery_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/delivery"
	"github.com/migadu/sora/server/sieveengine"
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
		{
			name:   "fileinto INBOX then keep uses last flags",
			script: `fileinto :copy :flags "A" "INBOX"; keep :flags "B";`,
			want:   map[string][]string{"INBOX": {"b"}},
		},
		{
			name:   "keep then fileinto INBOX uses last flags",
			script: `keep :flags "A"; fileinto :flags "B" "INBOX";`,
			want:   map[string][]string{"INBOX": {"b"}},
		},
		{
			name:   "case aliases with repeated first spelling use last flags",
			script: `fileinto :flags "A" "Archive"; fileinto :flags "B" "archive"; fileinto :flags "C" "Archive";`,
			want:   map[string][]string{"Archive": {"c"}},
		},
		{
			name:   "implicit keep does not override explicit INBOX filing",
			script: `fileinto :copy :flags "A" "INBOX"; setflag "B";`,
			want:   map[string][]string{"INBOX": {"a"}},
		},
		{
			name:   "empty keep flags clear earlier fileinto flags",
			script: `fileinto :flags "A" "INBOX"; keep :flags "";`,
			want:   map[string][]string{"INBOX": {}},
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountID)
			require.NoError(t, err)
			script := fmt.Sprintf("require [\"fileinto\", \"imap4flags\", \"copy\"];\r\n# %d\r\n%s\r\n", i, tc.script)
			require.NoError(t, sieveengine.ValidateScript(script, []string{"fileinto", "imap4flags", "copy"}))
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

// The default spam target follows its special-use mailbox after a rename. Its
// per-copy flags must follow too, before the user's kept flags are merged in.
func TestDelivery_RenamedDefaultJunkPreservesCopyFlags(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	junk, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "Junk")
	require.NoError(t, err)
	require.NoError(t, rdb.RenameMailboxWithRetry(ctx, junk.ID, accountID, "Spam", nil))

	evaluate := func(script string) sieveengine.Result {
		t.Helper()
		executor, err := sieveengine.NewSieveExecutorWithExtensions(
			`require ["fileinto", "imap4flags"]; `+script, []string{"fileinto", "imap4flags"})
		require.NoError(t, err)
		result, err := executor.Evaluate(ctx, sieveengine.Context{
			EnvelopeFrom: "sender@example.com", EnvelopeTo: account.Email,
			Header:  map[string][]string{"From": {"sender@example.com"}, "To": {account.Email}},
			Message: []byte("From: sender@example.com\r\nTo: " + account.Email + "\r\n\r\nbody\r\n"),
		})
		require.NoError(t, err)
		return result
	}
	original := evaluate(`fileinto :flags "SpamTag" "Junk";`)
	resolved, err := delivery.ResolveDefaultJunk(ctx, rdb, accountID, original)
	require.NoError(t, err)
	merged, kept := delivery.MergeSieveResults(resolved, evaluate(`keep :flags "UserTag";`))
	require.True(t, kept)
	require.Equal(t, []sieveengine.Destination{{Mailbox: "Spam", Flags: []string{"spamtag", "usertag"}}}, merged.Destinations(false))
	require.Equal(t, []string{"Junk"}, original.Mailboxes, "renaming a result must not mutate its source")
	require.Equal(t, map[string][]string{"Junk": {"spamtag"}}, original.MailboxFlags)
	require.Equal(t, map[string]uint64{"Junk": 1}, original.MailboxStoreOrder)
	require.Equal(t, map[string]uint64{"Spam": 1}, resolved.MailboxStoreOrder)
}
