package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-message"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/migadu/sora/server/uploader"
	"github.com/stretchr/testify/require"
)

// TestDeliverMessage_EditHeaderUpdatesFTSPlaintextBody verifies that when an active
// Sieve script adds, deletes, or replaces Content-Type or Content-Transfer-Encoding
// via RFC 5293 editheader during DeliverMessage, the plaintext body staged in
// messages_fts_v2.text_body is extracted from the post-editheader messageEntity
// rather than the pre-editheader arrival entity.
func TestDeliverMessage_EditHeaderUpdatesFTSPlaintextBody(t *testing.T) {
	rdb := setupDeliveryTestDatabase(t)
	ctx := context.Background()
	extensions := sieveengine.EffectiveExtensions(append(slices.Clone(sieveengine.DefaultSieveExtensions), "editheader", "copy"))

	newAccountAndContext := func(t *testing.T, script string) (int64, RecipientInfo, *DeliveryContext, *uploader.UploadWorker) {
		t.Helper()
		email := fmt.Sprintf("delivery-editheader-fts-%d@example.com", time.Now().UnixNano())
		accountID, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
			Email:     email,
			Password:  "testpassword123",
			IsPrimary: true,
			HashType:  "bcrypt",
		})
		require.NoError(t, err)

		_, err = sieveengine.NewSieveExecutorWithExtensions(script, extensions)
		require.NoError(t, err)
		stored, err := rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
		require.NoError(t, err)
		require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, stored.ID, accountID, true))

		up, err := uploader.NewWithS3Interface(t.TempDir(), 10, 1, 3, time.Second, 0, "delivery-test", rdb, nil, nil, nil)
		require.NoError(t, err)

		dctx := &DeliveryContext{
			Ctx:          ctx,
			RDB:          rdb,
			Uploader:     up,
			Hostname:     "mx.example.com",
			InstanceID:   "delivery-test",
			MetricsLabel: "http_delivery",
			Logger:       nopDeliveryLogger{},
		}
		dctx.SieveExecutor = &StandardSieveExecutor{
			DeliveryCtx:     dctx,
			VacationOracle:  &VacationOracle{RDB: rdb},
			SieveExtensions: extensions,
		}

		recipient, err := dctx.LookupRecipient(ctx, email)
		require.NoError(t, err)
		fromAddr, err := server.NewAddress("sender@example.com")
		require.NoError(t, err)
		recipient.FromAddress = &fromAddr

		return accountID, *recipient, dctx, up
	}

	t.Run("content_type_replaced_with_text_plain", func(t *testing.T) {
		script := "require [\"editheader\", \"fileinto\", \"copy\", \"mailbox\"];\r\n" +
			"deleteheader \"Content-Type\";\r\n" +
			"addheader \"Content-Type\" \"text/plain; charset=utf-8\";\r\n" +
			"fileinto :create :copy \"Archive\";\r\n"
		accountID, recipient, dctx, up := newAccountAndContext(t, script)

		marker := fmt.Sprintf("editheader-ct-plain-%d", time.Now().UnixNano())
		raw := strings.Join([]string{
			"From: sender@example.com",
			"To: " + recipient.Address.FullAddress(),
			"Subject: " + marker,
			"Message-ID: <" + marker + "@example.com>",
			"MIME-Version: 1.0",
			"Content-Type: application/octet-stream",
			"",
			"searchable body after editheader",
			"",
		}, "\r\n")

		res, err := dctx.DeliverMessage(recipient, []byte(raw))
		require.NoError(t, err, "DeliverMessage failed: result=%+v", res)
		require.True(t, res.Success)

		for _, mailbox := range []string{"INBOX", "Archive"} {
			var contentHash, textBody string
			var rawFlags []byte
			err := rdb.QueryRowWithRetry(ctx, `
				SELECT m.content_hash, ms.custom_flags, COALESCE(f.text_body, '')
				FROM messages m
				JOIN mailboxes mb ON mb.id = m.mailbox_id
				JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
				LEFT JOIN messages_fts_v2 f ON f.content_hash = m.content_hash AND f.account_id = m.account_id
				WHERE m.account_id = $1 AND mb.name = $2 AND m.subject = $3 AND m.expunged_at IS NULL
			`, accountID, mailbox, marker).Scan(&contentHash, &rawFlags, &textBody)
			require.NoError(t, err, "mailbox %s", mailbox)

			storedBytes, err := os.ReadFile(up.FilePath(contentHash, accountID))
			require.NoError(t, err, "mailbox %s staged file", mailbox)
			entity, err := message.Read(bytes.NewReader(storedBytes))
			require.NoError(t, err)
			require.Equal(t, "text/plain; charset=utf-8", entity.Header.Get("Content-Type"), "mailbox %s stored Content-Type", mailbox)

			var keywords []string
			require.NoError(t, json.Unmarshal(rawFlags, &keywords))
			require.Contains(t, keywords, "$hasnoattachment", "mailbox %s keywords", mailbox)
			require.NotContains(t, keywords, "$hasattachment", "mailbox %s keywords", mailbox)

			require.Equal(t, "searchable body after editheader", strings.TrimSpace(textBody),
				"mailbox %s messages_fts_v2.text_body must reflect post-editheader Content-Type", mailbox)
		}
	})

	t.Run("content_type_added_text_html", func(t *testing.T) {
		script := "require [\"editheader\"];\r\n" +
			"addheader \"Content-Type\" \"text/html; charset=utf-8\";\r\n"
		accountID, recipient, dctx, up := newAccountAndContext(t, script)

		marker := fmt.Sprintf("editheader-ct-html-%d", time.Now().UnixNano())
		raw := strings.Join([]string{
			"From: sender@example.com",
			"To: " + recipient.Address.FullAddress(),
			"Subject: " + marker,
			"Message-ID: <" + marker + "@example.com>",
			"MIME-Version: 1.0",
			"",
			"<p>alpha</p><script>secret</script>",
			"",
		}, "\r\n")

		res, err := dctx.DeliverMessage(recipient, []byte(raw))
		require.NoError(t, err, "DeliverMessage failed: result=%+v", res)
		require.True(t, res.Success)

		var contentHash, textBody string
		err = rdb.QueryRowWithRetry(ctx, `
			SELECT m.content_hash, COALESCE(f.text_body, '')
			FROM messages m
			JOIN mailboxes mb ON mb.id = m.mailbox_id
			LEFT JOIN messages_fts_v2 f ON f.content_hash = m.content_hash AND f.account_id = m.account_id
			WHERE m.account_id = $1 AND mb.name = 'INBOX' AND m.subject = $2 AND m.expunged_at IS NULL
		`, accountID, marker).Scan(&contentHash, &textBody)
		require.NoError(t, err)

		storedBytes, err := os.ReadFile(up.FilePath(contentHash, accountID))
		require.NoError(t, err)
		entity, err := message.Read(bytes.NewReader(storedBytes))
		require.NoError(t, err)
		require.Equal(t, "text/html; charset=utf-8", entity.Header.Get("Content-Type"))

		require.Equal(t, "alpha", strings.TrimSpace(textBody),
			"messages_fts_v2.text_body must strip HTML/script markup after editheader adds Content-Type: text/html")
	})

	t.Run("content_transfer_encoding_added_base64", func(t *testing.T) {
		script := "require [\"editheader\"];\r\n" +
			"addheader \"Content-Transfer-Encoding\" \"base64\";\r\n"
		accountID, recipient, dctx, up := newAccountAndContext(t, script)

		marker := fmt.Sprintf("editheader-cte-b64-%d", time.Now().UnixNano())
		// "hello editheader body" in base64 is "aGVsbG8gZWRpdGhlYWRlciBib2R5".
		raw := strings.Join([]string{
			"From: sender@example.com",
			"To: " + recipient.Address.FullAddress(),
			"Subject: " + marker,
			"Message-ID: <" + marker + "@example.com>",
			"MIME-Version: 1.0",
			"Content-Type: text/plain; charset=utf-8",
			"",
			"aGVsbG8gZWRpdGhlYWRlciBib2R5",
			"",
		}, "\r\n")

		res, err := dctx.DeliverMessage(recipient, []byte(raw))
		require.NoError(t, err, "DeliverMessage failed: result=%+v", res)
		require.True(t, res.Success)

		var contentHash, textBody string
		err = rdb.QueryRowWithRetry(ctx, `
			SELECT m.content_hash, COALESCE(f.text_body, '')
			FROM messages m
			JOIN mailboxes mb ON mb.id = m.mailbox_id
			LEFT JOIN messages_fts_v2 f ON f.content_hash = m.content_hash AND f.account_id = m.account_id
			WHERE m.account_id = $1 AND mb.name = 'INBOX' AND m.subject = $2 AND m.expunged_at IS NULL
		`, accountID, marker).Scan(&contentHash, &textBody)
		require.NoError(t, err)

		storedBytes, err := os.ReadFile(up.FilePath(contentHash, accountID))
		require.NoError(t, err)
		entity, err := message.Read(bytes.NewReader(storedBytes))
		require.NoError(t, err)
		require.Equal(t, "base64", entity.Header.Get("Content-Transfer-Encoding"))

		require.Equal(t, "hello editheader body", textBody,
			"messages_fts_v2.text_body must decode base64 after editheader adds Content-Transfer-Encoding")
	})
}
