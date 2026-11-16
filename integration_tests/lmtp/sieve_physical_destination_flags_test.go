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
	"github.com/migadu/sora/server/sieveengine"
)

// Physical identity, not a Go case fold or an unresolved name, determines which
// copies collide. The latest explicit action supplies that physical copy's flags.
// The basic per-copy contract from issue #453 remains: imap4flags flags belong to the copy one
// keep or fileinto stores. RFC 5232 §5: "The copy of the message filed into the
// mailbox will have only flags listed after the :flags tagged argument." §3: "If the
// :flags tagged argument is not specified with those two actions, the current value
// of the internal variable is used instead. The value of the internal variable also
// applies to the implicit keep." Every copy used to get one list, the internal
// variable as :flags had last overwritten it.
func TestLMTP_SievePhysicalDestinationFlags(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	for _, name := range []string{"Archive", "Projects", "ſent", "İx", "ix"} {
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
			script := `require ["fileinto", "imap4flags", "copy", "mailbox"];` + "\r\n" + tc.script + "\r\n"
			if err := sieveengine.ValidateScript(script, []string{"fileinto", "imap4flags", "copy", "mailbox"}); err != nil {
				t.Fatalf("compile test script: %v", err)
			}
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
			if tc.name == "attachment_keywords_each_copy" {
				msg = strings.Replace(msg, "\r\n\r\nbody", "\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=flags\r\n\r\n--flags\r\nContent-Type: text/plain\r\n\r\nbody\r\n--flags\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=x.bin\r\n\r\nbytes\r\n--flags--\r\n", 1)
			}
			if resp := deliverLMTPRaw(t, lmtpAddr, "sender@example.com", account.Email, msg); !strings.HasPrefix(resp, "250") {
				t.Fatalf("delivery not accepted: %s", resp)
			}

			if got := common.SieveFlagsBySubject(t, rdb, accountID, subject); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("copies and their flags = %v, want %v", got, tc.want)
			}
			if tc.name == "attachment_keywords_each_copy" {
				var classified bool
				err := rdb.GetOperationalDatabase().GetWritePool().QueryRow(ctx, `SELECT bool_and(EXISTS (SELECT 1 FROM jsonb_array_elements_text(ms.custom_flags) f WHERE LOWER(f) = '$hasattachment')) FROM messages m JOIN message_state ms ON ms.message_id=m.id AND ms.mailbox_id=m.mailbox_id JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE mb.account_id=$1 AND m.subject=$2 AND m.expunged_at IS NULL`, accountID, subject).Scan(&classified)
				if err != nil || !classified {
					t.Fatalf("every physical copy must have the classified attachment keyword: %v, %v", classified, err)
				}
			}

			if tc.name == "resubmission_does_not_rewrite_flags" {
				_, err := rdb.ExecWithRetry(ctx, `UPDATE sieve_scripts SET script=$1 WHERE account_id=$2 AND active`, `require ["fileinto", "imap4flags"]; fileinto :flags "B" "Archive";`, accountID)
				if err != nil {
					t.Fatal(err)
				}
				if reply := deliverLMTPRaw(t, lmtpAddr, "sender@example.com", account.Email, msg); !strings.HasPrefix(reply, "250") {
					t.Fatal(reply)
				}
				if got := common.SieveFlagsBySubject(t, rdb, accountID, subject); !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("resubmission changed existing flags: %v, want %v", got, tc.want)
				}
			}

		})
	}
}
