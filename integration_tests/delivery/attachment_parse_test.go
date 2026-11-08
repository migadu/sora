//go:build integration

package delivery_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/stretchr/testify/require"
)

func TestDelivery_AttachmentKeywordMultipartAndMalformed(t *testing.T) {
	b, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer b.Close()
	rdb := b.ResilientDB
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	dctx := newSieveDeliveryContext(t, rdb, fake, accountID,
		"require [\"fileinto\", \"copy\"];\r\nfileinto :copy \"Archive\";\r\n")
	addr, err := server.NewAddress(account.Email)
	require.NoError(t, err)
	recipient := delivery.RecipientInfo{AccountID: accountID, Address: &addr, ToAddress: &addr}

	for _, tc := range []struct {
		name, mime, keyword string
	}{
		{"attached document", strings.Join([]string{
			`Content-Type: multipart/related; boundary="b"`,
			`Content-Disposition: attachment; filename="page.mhtml"`, "",
			"--b", "Content-Type: text/html", "", "<p>Attached page</p>", "--b--", "",
		}, "\r\n"), "$hasattachment"},
		{"malformed", strings.Join([]string{
			`Content-Type: multipart/mixed; boundary="declared"`, "",
			"--actual", "Content-Type: text/plain", "", "body", "--actual--", "",
		}, "\r\n"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker := fmt.Sprintf("attachment-parse-%s-%d", strings.ReplaceAll(tc.name, " ", "-"), common.GetTimestamp())
			message := []byte("From: sender@example.com\r\nTo: " + account.Email +
				"\r\nSubject: " + marker + "\r\nMessage-ID: <" + marker + "@example.com>\r\n" + tc.mime)
			result, err := dctx.DeliverMessage(recipient, message)
			require.NoError(t, err)
			require.True(t, result.Success)
			for _, mailbox := range []string{"INBOX", "Archive"} {
				var raw []byte
				err := rdb.QueryRowWithRetry(ctx, `
					SELECT ms.custom_flags FROM messages m
					JOIN mailboxes mb ON mb.id = m.mailbox_id
					JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
					WHERE m.account_id = $1 AND mb.name = $2 AND m.subject = $3 AND m.expunged_at IS NULL
				`, accountID, mailbox, marker).Scan(&raw)
				require.NoError(t, err)
				var keywords []string
				require.NoError(t, json.Unmarshal(raw, &keywords))
				if tc.keyword == "" {
					require.NotContains(t, keywords, "$hasattachment", mailbox)
					require.NotContains(t, keywords, "$hasnoattachment", mailbox)
				} else {
					require.True(t, slices.Contains(keywords, tc.keyword), "%s keywords: %v", mailbox, keywords)
					require.NotContains(t, keywords, "$hasnoattachment", mailbox)
				}
			}
		})
	}
}
