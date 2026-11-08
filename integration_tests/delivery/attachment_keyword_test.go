//go:build integration

package delivery_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/stretchr/testify/require"
)

// TestDelivery_AttachmentKeyword: the Admin API delivery path sets the RFC 9979
// §4 attachment keyword, overriding one a Sieve script set, on both the kept
// message and a fileinto :copy.
func TestDelivery_AttachmentKeyword(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	// The script claims an attachment; the plain message below has none.
	dctx := newSieveDeliveryContext(t, rdb, fake, accountID,
		"require [\"imap4flags\", \"fileinto\", \"copy\"];\r\naddflag \"$hasattachment\";\r\nfileinto :copy \"Archive\";\r\n")

	addr, err := server.NewAddress(account.Email)
	require.NoError(t, err)
	recipient := delivery.RecipientInfo{AccountID: accountID, Address: &addr, ToAddress: &addr}

	marker := fmt.Sprintf("attachment-keyword-%d", common.GetTimestamp())
	msgBytes := []byte("From: sender@example.com\r\nTo: " + account.Email +
		"\r\nSubject: " + marker + "\r\nMessage-ID: <" + marker + "@example.com>\r\n\r\nbody\r\n")
	result, err := dctx.DeliverMessage(recipient, msgBytes)
	require.NoError(t, err, "delivery must succeed (result=%+v)", result)
	require.True(t, result.Success)

	for _, mailbox := range []string{"INBOX", "Archive"} {
		var raw []byte
		err := rdb.QueryRowWithRetry(ctx, `
			SELECT ms.custom_flags FROM messages m
			JOIN mailboxes mb ON m.mailbox_id = mb.id
			JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
			WHERE mb.account_id = $1 AND mb.name = $2 AND m.expunged_at IS NULL
		`, accountID, mailbox).Scan(&raw)
		require.NoError(t, err, "read %s flags", mailbox)
		var keywords []string
		require.NoError(t, json.Unmarshal(raw, &keywords))
		if !slices.Contains(keywords, "$hasnoattachment") || slices.Contains(keywords, "$hasattachment") {
			t.Errorf("%s keywords = %v, want $hasnoattachment in place of the script's $hasattachment", mailbox, keywords)
		}
	}
}
