//go:build integration

package lmtp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-message"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/stretchr/testify/require"
)

// TestLMTP_EditHeaderUpdatesStoredMetadata verifies that when a Sieve script modifies
// address headers or MIME body-decoding headers via RFC 5293 editheader, LMTP extracts
// stored recipients_json, sort columns, and staged FTS text_body from the post-edit
// message rather than the pre-edit arrival headers.
func TestLMTP_EditHeaderUpdatesStoredMetadata(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()
	extensions := sieveengine.EffectiveExtensions(append(slices.Clone(sieveengine.DefaultSieveExtensions), "editheader", "copy"))
	addr, dir := startLMTPForDelivery(t, rdb, lmtpserver.LMTPServerOptions{SieveExtensions: extensions})
	waitForLMTPListener(t, addr, nil)

	t.Run("recipients_and_sort_columns", func(t *testing.T) {
		account := common.CreateTestAccount(t, rdb)
		accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
		require.NoError(t, err)

		script := `require ["editheader", "fileinto", "copy", "mailbox"];
deleteheader "From";
addheader "From" "New Sender <new-from@example.com>";
deleteheader "Cc";
addheader "Cc" "new-cc@example.com";
deleteheader "Reply-To";
addheader "Reply-To" "new-reply@example.com";
addheader "Bcc" "";
deleteheader "Sender";
fileinto :create :copy "Archive";
`
		_, err = sieveengine.NewSieveExecutorWithExtensions(script, extensions)
		require.NoError(t, err)
		stored, err := rdb.CreateScriptWithRetry(ctx, accountID, "editheader-recipients", script)
		require.NoError(t, err)
		require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, stored.ID, accountID, true))

		marker := fmt.Sprintf("editheader-rcpt-%d", time.Now().UnixNano())
		raw := strings.Join([]string{
			"From: Old Sender <old-from@example.com>",
			"To: " + account.Email,
			"Cc: old-cc@example.com",
			"Reply-To: old-reply@example.com",
			"Sender: old-sender@example.com",
			"Subject: " + marker,
			"Message-ID: <" + marker + "@example.com>",
			"",
			"body",
			"",
		}, "\r\n")

		reply := deliverLMTPRaw(t, addr, "sender@example.com", account.Email, raw)
		require.True(t, strings.HasPrefix(reply, "250"), "unexpected LMTP reply: %s", reply)

		for _, mailbox := range []string{"INBOX", "Archive"} {
			var recipientsBytes []byte
			var presence int16
			var fromEmailSort, fromNameSort, ccEmailSort string
			err := rdb.QueryRowWithRetry(ctx, `
				SELECT m.recipients_json, COALESCE(m.from_email_sort, ''), COALESCE(m.from_name_sort, ''), COALESCE(m.cc_email_sort, ''), m.header_presence
				FROM messages m
				JOIN mailboxes mb ON mb.id = m.mailbox_id
				WHERE m.account_id = $1 AND mb.name = $2 AND m.subject = $3 AND m.expunged_at IS NULL
			`, accountID, mailbox, marker).Scan(&recipientsBytes, &fromEmailSort, &fromNameSort, &ccEmailSort, &presence)
			require.NoError(t, err, "mailbox %s", mailbox)
			bit, _ := helpers.HeaderPresenceBit("bcc")
			require.NotZero(t, presence&bit, "post-edit empty Bcc in %s", mailbox)
			bit, _ = helpers.HeaderPresenceBit("sender")
			require.Zero(t, presence&bit, "deleted Sender in %s", mailbox)

			var recipients []helpers.Recipient
			require.NoError(t, json.Unmarshal(recipientsBytes, &recipients), "mailbox %s", mailbox)

			require.Contains(t, recipients, helpers.Recipient{
				EmailAddress: "new-from@example.com",
				AddressType:  "from",
				Name:         "New Sender",
			}, "mailbox %s recipients_json should contain edited From", mailbox)
			require.Contains(t, recipients, helpers.Recipient{
				EmailAddress: "new-cc@example.com",
				AddressType:  "cc",
			}, "mailbox %s recipients_json should contain edited Cc", mailbox)
			require.Contains(t, recipients, helpers.Recipient{
				EmailAddress: "new-reply@example.com",
				AddressType:  "reply-to",
			}, "mailbox %s recipients_json should contain edited Reply-To", mailbox)

			for _, r := range recipients {
				require.NotEqual(t, "old-from@example.com", r.EmailAddress, "mailbox %s still contains pre-edit From", mailbox)
				require.NotEqual(t, "old-cc@example.com", r.EmailAddress, "mailbox %s still contains pre-edit Cc", mailbox)
				require.NotEqual(t, "old-reply@example.com", r.EmailAddress, "mailbox %s still contains pre-edit Reply-To", mailbox)
			}

			require.Equal(t, "new-from@example.com", fromEmailSort, "mailbox %s from_email_sort", mailbox)
			require.Equal(t, "new sender", fromNameSort, "mailbox %s from_name_sort", mailbox)
			require.Equal(t, "new-cc@example.com", ccEmailSort, "mailbox %s cc_email_sort", mailbox)
		}
	})

	t.Run("fts_plaintext_body_after_transfer_encoding_edit", func(t *testing.T) {
		account := common.CreateTestAccount(t, rdb)
		accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
		require.NoError(t, err)

		script := `require ["editheader"];
addheader "Content-Transfer-Encoding" "base64";
`
		_, err = sieveengine.NewSieveExecutorWithExtensions(script, extensions)
		require.NoError(t, err)
		stored, err := rdb.CreateScriptWithRetry(ctx, accountID, "editheader-cte", script)
		require.NoError(t, err)
		require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, stored.ID, accountID, true))

		marker := fmt.Sprintf("editheader-body-%d", time.Now().UnixNano())
		// "hello editheader body" in base64 is "aGVsbG8gZWRpdGhlYWRlciBib2R5".
		raw := strings.Join([]string{
			"From: sender@example.com",
			"To: " + account.Email,
			"Subject: " + marker,
			"Message-ID: <" + marker + "@example.com>",
			"MIME-Version: 1.0",
			"Content-Type: text/plain; charset=utf-8",
			"",
			"aGVsbG8gZWRpdGhlYWRlciBib2R5",
			"",
		}, "\r\n")

		reply := deliverLMTPRaw(t, addr, "sender@example.com", account.Email, raw)
		require.True(t, strings.HasPrefix(reply, "250"), "unexpected LMTP reply: %s", reply)

		var contentHash, textBody string
		err = rdb.QueryRowWithRetry(ctx, `
			SELECT m.content_hash, COALESCE(f.text_body, '')
			FROM messages m
			JOIN mailboxes mb ON mb.id = m.mailbox_id
			JOIN messages_fts_v2 f ON f.content_hash = m.content_hash AND f.account_id = m.account_id
			WHERE m.account_id = $1 AND mb.name = 'INBOX' AND m.subject = $2 AND m.expunged_at IS NULL
		`, accountID, marker).Scan(&contentHash, &textBody)
		require.NoError(t, err)

		// Sanity-check that the stored RFC822 message on disk carries the added header.
		storedBytes, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%d", accountID), contentHash))
		require.NoError(t, err)
		entity, err := message.Read(bytes.NewReader(storedBytes))
		require.NoError(t, err)
		require.Equal(t, "base64", entity.Header.Get("Content-Transfer-Encoding"))

		require.Equal(t, "hello editheader body", textBody)
	})
}
