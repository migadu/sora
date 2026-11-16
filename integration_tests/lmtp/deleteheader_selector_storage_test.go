//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/stretchr/testify/require"
)

// The script's view and actual stored bytes must select the same occurrence,
// including an empty value, without rewriting unrelated fields or body bytes.
func TestLMTP_DeleteHeaderSelectorStorage(t *testing.T) {
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()
	extensions := sieveengine.EffectiveExtensions(append(slices.Clone(sieveengine.DefaultSieveExtensions), "editheader"))
	const fields = "X-Foo:\r\nX-Keep:\tleft  \r\nX-Foo: keep\r\nX-Foo: \t\r\nX-End: right\r\n"
	for _, tc := range []struct {
		name, fields, action, field, wantFields, wantVisible string
		legacyInvalid                                        bool
	}{
		{"empty value", fields, `deleteheader :is "X-Foo" "";`, "X-Foo", "X-Keep:\tleft  \r\nX-Foo: keep\r\nX-End: right\r\n", "yes", false},
		{"ASCII punctuation alias", "X(a:\r\nX-Keep:\tleft  \r\nx(A: keep\r\nX(a: \t\r\nX-End: right\r\n", `deleteheader :is "x(A" "";`, "X(a", "X-Keep:\tleft  \r\nx(A: keep\r\nX-End: right\r\n", "yes", false},
		{"last indexed empty value", fields, `deleteheader :index 1 :last :is "X-Foo" "";`, "X-Foo", "X-Foo:\r\nX-Keep:\tleft  \r\nX-Foo: keep\r\nX-End: right\r\n", "yes", false},
		{"delete all without patterns", fields, `deleteheader "x-foo";`, "X-Foo", "X-Keep:\tleft  \r\nX-End: right\r\n", "no", false},
		{"legacy index zero falls back to keep", fields, `deleteheader :index 0 "X-Foo"; discard;`, "X-Foo", fields, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := common.CreateTestAccount(t, rdb)
			accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
			require.NoError(t, err)
			_, err = rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, "Archive")
			require.NoError(t, err)
			script := `require ["editheader", "fileinto"]; ` + tc.action
			if !tc.legacyInvalid {
				script += ` if exists "` + tc.field + `" { addheader :last "X-Visible-After-Edit" "yes"; } else { addheader :last "X-Visible-After-Edit" "no"; } fileinto "Archive";`
			}
			if !tc.legacyInvalid {
				require.NoError(t, sieveengine.ValidateScript(script, extensions))
			}
			// Store directly to model a script saved by an earlier release. Normal
			// script-store callers validate it before reaching this database method.
			stored, err := rdb.CreateScriptWithRetry(ctx, accountID, "deleteheader-selector", script)
			require.NoError(t, err)
			require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, stored.ID, accountID, true))
			addr, dir := startLMTPForDelivery(t, rdb, lmtpserver.LMTPServerOptions{SieveExtensions: extensions})
			waitForLMTPListener(t, addr, nil)
			marker := fmt.Sprintf("deleteheader-selector-%d", time.Now().UnixNano())
			const body = "body cafe\t  \r\nsecond line"
			raw := tc.fields + "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: " + marker + "\r\nMessage-ID: <" + marker + "@example.com>\r\n\r\n" + body
			reply := deliverLMTPRaw(t, addr, "sender@example.com", account.Email, raw)
			require.True(t, strings.HasPrefix(reply, "250"), "%s", reply)
			wantMailbox, otherMailbox := "Archive", "INBOX"
			if tc.legacyInvalid {
				wantMailbox, otherMailbox = otherMailbox, wantMailbox
			}
			require.Equal(t, 1, countInMailbox(t, rdb, accountID, wantMailbox))
			require.Equal(t, 0, countInMailbox(t, rdb, accountID, otherMailbox))
			content := readStoredMessage(t, dir)
			require.Contains(t, content, tc.wantFields+"From: sender@example.com\r\n", "unselected raw fields keep order and bytes")
			require.True(t, strings.HasSuffix(content, "\r\n\r\n"+body+"\r\n"), "body bytes changed: %q", content)
			if tc.wantVisible != "" {
				require.Contains(t, content, "X-Visible-After-Edit: "+tc.wantVisible+"\r\n", "stored message must agree with script's view")
			}
		})
	}
}
