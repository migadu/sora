//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-message"
	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/stretchr/testify/require"
)

// Check the stored bytes as well as the script's view: valid punctuation in a
// field name must not prevent deleteheader from finding another ASCII spelling.
func TestLMTP_DeleteHeaderNameASCIICase(t *testing.T) {
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()
	extensions := sieveengine.EffectiveExtensions(append(slices.Clone(sieveengine.DefaultSieveExtensions), "editheader"))
	for _, tc := range []struct {
		name, fields, action, field string
		want                        []string
	}{
		{"delete all", "X(a: 1\r\n", `deleteheader "x(A";`, "X(a", nil},
		{"last index", "X(a: 1\r\nX(a: 2\r\n", `deleteheader :index 1 :last "x(A";`, "X(a", []string{"1"}},
		{"value", "X(a: 1\r\nX(a: 2\r\n", `deleteheader :is "x(A" "2";`, "X(a", []string{"1"}},
		{"token control", "X-Foo: 1\r\n", `deleteheader "x-FOO";`, "X-Foo", nil},
		{"other field kept", "X(a: 1\r\nX[a: 2\r\n", `deleteheader "x(A";`, "X[a", []string{"2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := common.CreateTestAccount(t, rdb)
			accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
			require.NoError(t, err)
			script := `require ["editheader", "index"]; ` + tc.action + ` if exists "` + tc.field + `" { addheader "X-Visible-After-Edit" "yes"; }`
			_, err = sieveengine.NewSieveExecutorWithExtensions(script, extensions)
			require.NoError(t, err)
			stored, err := rdb.CreateScriptWithRetry(ctx, accountID, "deleteheader-ascii", script)
			require.NoError(t, err)
			require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, stored.ID, accountID, true))
			addr, dir := startLMTPForDelivery(t, rdb, lmtpserver.LMTPServerOptions{SieveExtensions: extensions})
			waitForLMTPListener(t, addr, nil)
			marker := fmt.Sprintf("deleteheader-ascii-%d", time.Now().UnixNano())
			raw := tc.fields + "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: " + marker + "\r\nMessage-ID: <" + marker + "@example.com>\r\n\r\nbody\r\n"
			reply := deliverLMTPRaw(t, addr, "sender@example.com", account.Email, raw)
			require.True(t, strings.HasPrefix(reply, "250"), "%s", reply)
			require.Equal(t, 1, countInMailbox(t, rdb, accountID, "INBOX"))
			entity, err := message.Read(strings.NewReader(readStoredMessage(t, dir)))
			require.NoError(t, err)
			var values []string
			for f := entity.Header.Fields(); f.Next(); {
				if strings.EqualFold(f.Key(), tc.field) {
					values = append(values, f.Value())
				}
			}
			require.Equal(t, tc.want, values, "stored field list must agree with deleteheader")
			wantVisible := ""
			if len(tc.want) > 0 {
				wantVisible = "yes"
			}
			require.Equal(t, wantVisible, entity.Header.Get("X-Visible-After-Edit"))
		})
	}
}
