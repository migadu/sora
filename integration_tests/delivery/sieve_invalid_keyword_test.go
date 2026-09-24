//go:build integration

package delivery_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// capturingLogger records delivery log lines so a test can assert on them, and
// still forwards them to the test log. Delivery may log from more than one
// goroutine, so the buffer is guarded.
type capturingLogger struct {
	t     *testing.T
	mu    sync.Mutex
	lines []string
}

func (l *capturingLogger) Log(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	l.t.Logf("[delivery] %s", line)
	l.mu.Lock()
	l.lines = append(l.lines, line)
	l.mu.Unlock()
}

func (l *capturingLogger) contains(substr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		if strings.Contains(strings.ToLower(line), strings.ToLower(substr)) {
			return true
		}
	}
	return false
}

// TestDelivery_SieveInvalidKeywordIsDroppedAndLogged is the Admin API /deliver
// counterpart of the LMTP guard: the shared delivery engine runs the user's Sieve
// too, and imap4flags is the one flag source that never passes an IMAP parser.
// A keyword that is not an IMAP atom must not be stored -- in the mailbox keyword
// registry it wedges SELECT for good -- a valid keyword from the same script must
// survive, and the dropped ones must be named in the log so the user's script
// line can be pointed at.
func TestDelivery_SieveInvalidKeywordIsDroppedAndLogged(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	script := fmt.Sprintf("require [\"imap4flags\"];\r\n# %d\r\n"+
		"addflag \"НЕОБРАБОТЕНО\";\r\naddflag \"bad%%tag\";\r\naddflag \"Work\";\r\nkeep;\r\n",
		common.GetTimestamp())
	dctx := newSieveDeliveryContext(t, rdb, fake, accountID, script)
	logs := &capturingLogger{t: t}
	dctx.Logger = logs
	recipient := newSelfRecipient(t, accountID, account.Email)

	deliverSieveProbe(t, dctx, recipient, account.Email, "invalid-keyword")

	var customFlagsJSON []byte
	require.NoError(t, rdb.QueryRowWithRetry(ctx, `
		SELECT ms.custom_flags
		FROM messages m
		JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.account_id = $1 AND m.expunged_at IS NULL
		ORDER BY m.id DESC
		LIMIT 1`, accountID).Scan(&customFlagsJSON))
	var customFlags []string
	require.NoError(t, json.Unmarshal(customFlagsJSON, &customFlags))

	hasFold := func(want string) bool {
		for _, f := range customFlags {
			if strings.EqualFold(f, want) {
				return true
			}
		}
		return false
	}
	for _, bad := range []string{"НЕОБРАБОТЕНО", "bad%tag"} {
		require.Falsef(t, hasFold(bad),
			"keyword %q is not a valid IMAP flag-keyword but was stored: custom_flags=%v", bad, customFlags)
	}
	require.Truef(t, hasFold("Work"),
		"valid keyword \"Work\" was lost alongside the invalid ones: custom_flags=%v", customFlags)

	for _, bad := range []string{"НЕОБРАБОТЕНО", "bad%tag"} {
		require.Truef(t, logs.contains(bad),
			"dropped keyword %q was not named in the delivery log", bad)
	}
}
