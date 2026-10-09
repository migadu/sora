//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
)

// TestLMTP_SieveBodyAndSizeSeeTheStoredMessage pins what the Sieve body (RFC 5173) and
// size (RFC 5228 §5.9) tests evaluate against at LMTP delivery: the message as stored.
//
// Delivery used to hand Sieve the extracted full-text-search text as the "body" and its
// length as the size. That text carries no MIME structure, so a body test never matched
// a multipart message (nearly all real mail), never saw an attachment's content type,
// and size ignored attachments. Every such rule silently fell through to INBOX.
func TestLMTP_SieveBodyAndSizeSeeTheStoredMessage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	addr := startTestLMTPServer(t, rdb)
	ctx := context.Background()

	for _, tc := range common.SieveRawMessageCases() {
		t.Run(tc.Name, func(t *testing.T) {
			account := common.CreateTestAccount(t, rdb)
			accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
			if err != nil {
				t.Fatalf("lookup account: %v", err)
			}
			script, err := rdb.CreateScriptWithRetry(ctx, accountID, "active", tc.Script)
			if err != nil {
				t.Fatalf("create sieve script: %v", err)
			}
			if err := rdb.SetScriptActiveWithRetry(ctx, script.ID, accountID, true); err != nil {
				t.Fatalf("activate sieve script: %v", err)
			}

			subject := fmt.Sprintf("raw-%d", time.Now().UnixNano())
			resp := deliverLMTPRaw(t, addr, "sender@example.com", account.Email, tc.Message(account.Email, subject))
			if !strings.HasPrefix(resp, "250") {
				t.Fatalf("delivery not accepted: %s", resp)
			}

			if tc.Mailbox == "" {
				if n := countForAccount(t, rdb, accountID); n != 0 {
					t.Errorf("script %q: want the message discarded, found %d stored (INBOX holds %d)",
						tc.Script, n, countInMailbox(t, rdb, accountID, "INBOX"))
				}
				return
			}
			if n := countInMailbox(t, rdb, accountID, tc.Mailbox); n != 1 {
				t.Errorf("script %q: want the message in %s, found %d there (INBOX holds %d)",
					tc.Script, tc.Mailbox, n, countInMailbox(t, rdb, accountID, "INBOX"))
			}
		})
	}
}

// countForAccount counts the stored, unexpunged messages of an account in any mailbox.
func countForAccount(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64) int {
	t.Helper()
	var n int
	if err := rdb.QueryRowWithRetry(context.Background(),
		`SELECT COUNT(*) FROM messages WHERE account_id = $1 AND expunged_at IS NULL`, accountID,
	).Scan(&n); err != nil {
		t.Fatalf("count messages: %v", err)
	}
	return n
}
