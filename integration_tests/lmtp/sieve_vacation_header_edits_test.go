//go:build integration

package lmtp_test

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/stretchr/testify/require"
)

func TestLMTP_VacationSubjectReadsEditedHeaders(t *testing.T) {
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()
	queue := &captureRelayQueue{}
	extensions := sieveengine.EffectiveExtensions(append(slices.Clone(sieveengine.DefaultSieveExtensions), "editheader"))
	addr, _ := startTestLMTPServerWithOptions(t, rdb, lmtpserver.LMTPServerOptions{SieveExtensions: extensions, RelayQueue: queue})
	for _, tc := range []struct{ name, commands, subject string }{
		{"original subject", `vacation "away";`, "Auto: hello"},
		{"replaced subject", `deleteheader "Subject"; addheader "Subject" "[list] hello"; vacation "away";`, "Auto: [list] hello"},
		{"deleted subject", `deleteheader "Subject"; vacation "away";`, "Automated reply"},
		{"later edit does not change earlier action", `vacation "away"; deleteheader "Subject";`, "Auto: hello"},
		{"explicit subject control", `deleteheader "Subject"; vacation :subject "Custom" "away";`, "Custom"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := common.CreateTestAccount(t, rdb)
			accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
			require.NoError(t, err)
			script := `require ["vacation", "editheader"]; ` + tc.commands
			_, err = sieveengine.NewSieveExecutorWithExtensions(script, extensions)
			require.NoError(t, err)
			stored, err := rdb.CreateScriptWithRetry(ctx, accountID, "vacation-edits", script)
			require.NoError(t, err)
			require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, stored.ID, accountID, true))
			sender := fmt.Sprintf("vacation-edits-%d@example.org", time.Now().UnixNano())
			raw := "From: " + sender + "\r\nTo: " + account.Email + "\r\nSubject: hello\r\nMessage-ID: <" + sender + ">\r\n\r\nbody\r\n"
			before := len(queue.items())
			response := deliverLMTPRaw(t, addr, sender, account.Email, raw)
			require.True(t, strings.HasPrefix(response, "250"), "%s", response)
			require.Equal(t, 1, countInMailbox(t, rdb, accountID, "INBOX"))
			var replies []relayItem
			for _, item := range queue.items()[before:] {
				if item.msgType == "vacation" {
					replies = append(replies, item)
				}
			}
			require.Len(t, replies, 1, "a personal message must generate exactly one reply")
			require.Empty(t, replies[0].from)
			require.Equal(t, sender, replies[0].to)
			parsed, err := mail.CreateReader(bytes.NewReader(replies[0].body))
			require.NoError(t, err)
			subject, err := parsed.Header.Subject()
			require.NoError(t, err)
			require.Equal(t, tc.subject, subject)
		})
	}
}
