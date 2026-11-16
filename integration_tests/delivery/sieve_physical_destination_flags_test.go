//go:build integration

package delivery_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/stretchr/testify/require"
)

// This is the Admin API /deliver physical-identity counterpart of
// TestLMTP_SieveFlagsPerCopy (issue #453): each copy a keep or fileinto stores has
// that action's flags (RFC 5232 §3, §5), not one list applied to every copy.
func TestDelivery_SievePhysicalDestinationFlags(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	for _, name := range []string{"Archive", "Projects", "ſent", "İx", "ix"} {
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
			name:   "resubmission_does_not_rewrite_flags",
			script: `fileinto :flags "A" "Archive";`,
			want:   map[string][]string{"Archive": {"a"}},
		},
		{
			name:   "attachment_keywords_each_copy",
			script: `fileinto :flags ["A", "$HasNoAttachment"] "Archive"; fileinto :flags ["B", "$HasAttachment"] "Projects";`,
			want:   map[string][]string{"Archive": {"a"}, "Projects": {"b"}},
		},
		{
			name:   "create_all_before_missing_fallback",
			script: `fileinto :flags "A" "CreatedAlias"; fileinto :create :flags "B" "CreatedAlias";`,
			want:   map[string][]string{"CreatedAlias": {"b"}},
		},
		{
			name:   "empty_keep_clears_fallback_flags",
			script: `fileinto :flags "A" "MissingNeverCreated"; keep :flags "";`,
			want:   map[string][]string{"INBOX": {}},
		},
		{
			name:   "long_s_distinct_physical_mailboxes",
			script: `fileinto :flags "A" "ſent"; fileinto :flags "B" "sent";`,
			want:   map[string][]string{"ſent": {"a"}, "Sent": {"b"}},
		},
		{
			name:   "keep_then_missing_target_last_flags",
			script: `keep :flags "A"; fileinto :flags "B" "MissingNeverCreated";`,
			want:   map[string][]string{"INBOX": {"b"}},
		},
		{
			name:   "missing_target_then_keep_last_flags",
			script: `fileinto :flags "A" "MissingNeverCreated"; keep :flags "B";`,
			want:   map[string][]string{"INBOX": {"b"}},
		},
		{
			name:   "missing_targets_last_flags",
			script: `fileinto :flags "A" "MissingNeverCreated"; fileinto :flags "B" "MissingAlsoNeverCreated";`,
			want:   map[string][]string{"INBOX": {"b"}},
		},
	}

	first, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "İx")
	if err != nil {
		t.Fatal(err)
	}
	second, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "ix")
	if err != nil {
		t.Fatal(err)
	}
	aliasWant := map[string][]string{first.Name: {"a"}}
	aliasWant[second.Name] = []string{"b"}
	repeatWant := map[string][]string{first.Name: {"c"}, second.Name: {"b"}}
	if first.ID == second.ID {
		repeatWant[first.Name] = []string{"c"}
	}
	var sameCreateAlias bool
	if err := rdb.GetOperationalDatabase().GetWritePool().QueryRow(ctx, `SELECT LOWER($1::text)=LOWER($2::text)`, "İcreated", "icreated").Scan(&sameCreateAlias); err != nil {
		t.Fatal(err)
	}
	createWant := map[string][]string{"icreated": {"b"}}
	if !sameCreateAlias {
		createWant["INBOX"] = []string{"a"}
	}
	cases = append(cases,
		struct {
			name, script string
			want         map[string][]string
		}{"database_alias_create_before_fallback", `fileinto :flags "A" "İcreated"; fileinto :create :flags "B" "icreated";`, createWant},
		struct {
			name, script string
			want         map[string][]string
		}{"database_alias_last_flags", `fileinto :flags "A" "İx"; fileinto :flags "B" "ix";`, aliasWant},
		struct {
			name, script string
			want         map[string][]string
		}{"database_alias_repeat_first_last_flags", `fileinto :flags "A" "İx"; fileinto :flags "B" "ix"; fileinto :flags "C" "İx";`, repeatWant},
	)
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountID)
			require.NoError(t, err)
			script := fmt.Sprintf("require [\"fileinto\", \"imap4flags\", \"copy\", \"mailbox\"];\r\n# %d\r\n%s\r\n", i, tc.script)
			require.NoError(t, sieveengine.ValidateScript(script, []string{"fileinto", "imap4flags", "copy", "mailbox"}))
			dctx := newSieveDeliveryContext(t, rdb, fake, accountID, script)

			subject := fmt.Sprintf("flags-per-copy-%d-%d", i, common.GetTimestamp())
			msg := []byte("From: sender@example.com\r\nTo: " + account.Email +
				"\r\nSubject: " + subject + "\r\nMessage-ID: <" + subject + "@example.com>\r\n\r\nbody\r\n")
			if tc.name == "attachment_keywords_each_copy" {
				msg = []byte(strings.Replace(string(msg), "\r\n\r\nbody", "\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=flags\r\n\r\n--flags\r\nContent-Type: text/plain\r\n\r\nbody\r\n--flags\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=x.bin\r\n\r\nbytes\r\n--flags--\r\n", 1))
			}
			res, err := dctx.DeliverMessage(recipient, msg)
			require.NoError(t, err, "delivery failed (result=%+v)", res)
			require.True(t, res.Success, "delivery not accepted (result=%+v)", res)

			got := common.SieveFlagsBySubject(t, rdb, accountID, subject)
			require.Equal(t, tc.want, got, "copies and their flags")
			if tc.name == "attachment_keywords_each_copy" {
				var classified bool
				err := rdb.GetOperationalDatabase().GetWritePool().QueryRow(ctx, `SELECT bool_and(EXISTS (SELECT 1 FROM jsonb_array_elements_text(ms.custom_flags) f WHERE LOWER(f) = '$hasattachment')) FROM messages m JOIN message_state ms ON ms.message_id=m.id AND ms.mailbox_id=m.mailbox_id JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE mb.account_id=$1 AND m.subject=$2 AND m.expunged_at IS NULL`, accountID, subject).Scan(&classified)
				if err != nil || !classified {
					t.Fatalf("every physical copy must have the classified attachment keyword: %v, %v", classified, err)
				}
			}

			if tc.name == "resubmission_does_not_rewrite_flags" {
				_, err := rdb.ExecWithRetry(ctx, `UPDATE sieve_scripts SET script=$1 WHERE account_id=$2 AND active`, `require ["fileinto", "imap4flags"]; fileinto :flags "B" "Archive";`, accountID)
				require.NoError(t, err)
				retry, err := dctx.DeliverMessage(recipient, msg)
				require.NoError(t, err)
				require.True(t, retry.Success)
				require.Equal(t, tc.want, common.SieveFlagsBySubject(t, rdb, accountID, subject), "resubmission must not rewrite existing flags")
			}

		})
	}
}
