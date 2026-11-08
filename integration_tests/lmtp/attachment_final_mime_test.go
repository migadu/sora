//go:build integration

package lmtp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLMTP_AttachmentKeywordFinalMime(t *testing.T) {
	b, account := common.SetupLMTPServerWithOptions(t, lmtpserver.LMTPServerOptions{
		SieveExtensions: []string{"fileinto", "envelope", "mailbox", "subaddress", "variables", "editheader", "copy"},
	})
	defer b.Close()
	rdb, ctx := b.ResilientDB, context.Background()
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	script, err := rdb.CreateScriptWithRetry(ctx, accountID, "attachment-final-mime", `require ["editheader", "fileinto", "copy", "mailbox"];
if header :is "X-Test-Edit" "add" { addheader "Content-Disposition" "attachment"; }
if header :is "X-Test-Edit" "remove" { deleteheader "Content-Disposition"; }
fileinto :create :copy "Archive";
`)
	require.NoError(t, err)
	require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, script.ID, accountID, true))
	c, err := NewLMTPClient(b.Address)
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.SendCommand("LHLO test.example.com"))
	_, err = c.ReadMultilineResponse()
	require.NoError(t, err)
	cases := common.AttachmentKeywordRegressionCases()
	cases = append(cases,
		struct{ Name, MIME, Keyword string }{"edit adds attachment", "X-Test-Edit: add\r\nContent-Type: text/plain\r\n\r\nbody\r\n", "$hasattachment"},
		struct{ Name, MIME, Keyword string }{"edit removes attachment", "X-Test-Edit: remove\r\nContent-Type: text/plain\r\nContent-Disposition: attachment\r\n\r\nbody\r\n", "$hasnoattachment"},
	)
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			command := func(cmd, prefix string) {
				t.Helper()
				require.NoError(t, c.SendCommand(cmd))
				resp, err := c.ReadResponse()
				require.NoError(t, err)
				require.True(t, strings.HasPrefix(resp, prefix), "%s: %s", cmd, resp)
			}
			command("MAIL FROM:<sender@example.com>", "250")
			command("RCPT TO:<"+account.Email+">", "250")
			command("DATA", "354")
			marker := fmt.Sprintf("final-mime-%d", time.Now().UnixNano())
			raw := "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: " + marker +
				"\r\nMessage-ID: <" + marker + "@example.com>\r\n" + tc.MIME
			require.NoError(t, c.SendCommand(raw+"\r\n."))
			resp, err := c.ReadDataResponses(1)
			require.NoError(t, err)
			require.Len(t, resp, 1)
			require.True(t, strings.HasPrefix(resp[0], "250"), "%v", resp)
			for _, mailbox := range []string{"INBOX", "Archive"} {
				var flagBytes, structureBytes []byte
				err := rdb.QueryRowWithRetry(ctx, `SELECT ms.custom_flags, m.body_structure FROM messages m
					JOIN mailboxes mb ON mb.id = m.mailbox_id
					JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
					WHERE m.account_id = $1 AND mb.name = $2 AND m.subject = $3 AND m.expunged_at IS NULL`,
					accountID, mailbox, marker).Scan(&flagBytes, &structureBytes)
				require.NoError(t, err)
				var keywords []string
				require.NoError(t, json.Unmarshal(flagBytes, &keywords))
				if tc.Keyword == "" {
					require.NotContains(t, keywords, "$hasattachment", mailbox)
					require.NotContains(t, keywords, "$hasnoattachment", mailbox)
				} else {
					assert.Contains(t, keywords, tc.Keyword, mailbox)
				}
				bs, err := helpers.DeserializeBodyStructureGob(structureBytes)
				require.NoError(t, err)
				if strings.HasPrefix(tc.Name, "edit ") {
					if tc.Keyword == "$hasattachment" {
						require.NotNil(t, (*bs).Disposition(), "BODYSTRUCTURE must include Sieve's edit")
						require.Equal(t, "attachment", (*bs).Disposition().Value)
					} else {
						require.Nil(t, (*bs).Disposition(), "BODYSTRUCTURE must include Sieve's removal")
					}
				}
			}
		})
	}
}
