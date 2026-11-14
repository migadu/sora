//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/adminapi"
)

// captureRelay records what the delivery path hands to the relay queue.
type captureRelay struct {
	mu    sync.Mutex
	items []capturedRelayItem
}

type capturedRelayItem struct {
	from, to, msgType string
}

func (q *captureRelay) Enqueue(from, to, messageType string, _ []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, capturedRelayItem{from: from, to: to, msgType: messageType})
	return nil
}

// redirectedTo returns the sorted redirect targets enqueued so far.
func (q *captureRelay) redirectedTo() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	var to []string
	for _, it := range q.items {
		if it.msgType == "redirect" {
			to = append(to, it.to)
		}
	}
	slices.Sort(to)
	return to
}

// TestAdminAPI_DeliverMail_SieveEveryFilingAndRedirectHappens is issue #322 on the
// Admin API path: every fileinto target gets a copy and a redirect next to a
// fileinto is relayed, with the keep deciding the INBOX copy, as over LMTP.
func TestAdminAPI_DeliverMail_SieveEveryFilingAndRedirectHappens(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rq := &captureRelay{}
	server, _ := setupHTTPAPIServerWithOptions(t, func(o *adminapi.ServerOptions) {
		o.RelayQueue = rq
		o.RedirectRateLimit = 100
		o.RedirectRateWindow = time.Hour
	})
	defer server.Close()

	const target = "other@example.org"
	cases := []struct {
		name       string
		script     []string
		wantStored []string // sorted mailbox names, one entry per copy
		wantRelay  []string
	}{
		{
			name:       "fileinto and redirect",
			script:     []string{`require ["fileinto"];`, `fileinto "Archive";`, `redirect "` + target + `";`},
			wantStored: []string{"Archive"},
			wantRelay:  []string{target},
		},
		{
			name:       "fileinto twice",
			script:     []string{`require ["fileinto"];`, `fileinto "Archive";`, `fileinto "Projects";`},
			wantStored: []string{"Archive", "Projects"},
		},
		{
			// The redirect cancels the implicit keep that fileinto :copy left (RFC 3894 §3).
			name:       "fileinto :copy and redirect",
			script:     []string{`require ["fileinto", "copy"];`, `fileinto :copy "Archive";`, `redirect "` + target + `";`},
			wantStored: []string{"Archive"},
			wantRelay:  []string{target},
		},
		{
			name:       "fileinto :copy and redirect :copy",
			script:     []string{`require ["fileinto", "copy"];`, `fileinto :copy "Archive";`, `redirect :copy "` + target + `";`},
			wantStored: []string{"Archive", "INBOX"},
			wantRelay:  []string{target},
		},
		{
			name:       "fileinto twice and keep",
			script:     []string{`require ["fileinto"];`, `fileinto "Archive";`, `fileinto "Projects";`, `keep;`},
			wantStored: []string{"Archive", "INBOX", "Projects"},
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			email := fmt.Sprintf("apiactions-%d-%d@example.com", i, time.Now().UnixNano())
			createDeliveryAccount(t, server, email)
			accountID, err := server.rdb.GetAccountIDByAddressWithRetry(ctx, email)
			if err != nil {
				t.Fatalf("lookup account: %v", err)
			}
			for _, name := range []string{"Archive", "Projects"} {
				if _, err := server.rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, name); err != nil {
					t.Fatalf("create %s: %v", name, err)
				}
			}
			// A comment unique to this account, so another test's cached compile of
			// the same text cannot serve it.
			script := strings.Join(append([]string{"# " + email}, tc.script...), "\r\n") + "\r\n"
			sc, err := server.rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
			if err != nil {
				t.Fatalf("create sieve script: %v", err)
			}
			if err := server.rdb.SetScriptActiveWithRetry(ctx, sc.ID, accountID, true); err != nil {
				t.Fatalf("activate sieve script: %v", err)
			}

			relayedBefore := len(rq.redirectedTo())
			msg := "From: sender@example.com\r\nTo: " + email + "\r\nSubject: multi-action\r\n" +
				"Message-ID: <" + email + ">\r\n\r\nBody via API.\r\n"
			resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{
				"recipients": []string{email},
				"from":       "sender@example.com",
				"message":    msg,
			})
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("deliver: %d %s", resp.StatusCode, string(body))
			}

			if got := storedMailboxes(t, server, accountID); !slices.Equal(got, tc.wantStored) {
				t.Errorf("stored in %v, want %v", got, tc.wantStored)
			}
			relayed := len(rq.redirectedTo()) - relayedBefore
			if relayed != len(tc.wantRelay) {
				t.Errorf("relayed %d redirects, want %v", relayed, tc.wantRelay)
			}
			var logged int
			if err := server.rdb.QueryRowWithRetry(ctx,
				"SELECT COUNT(*) FROM redirect_log WHERE account_id = $1", accountID).Scan(&logged); err != nil {
				t.Fatalf("count redirect_log: %v", err)
			}
			if logged != len(tc.wantRelay) {
				t.Errorf("rate limit charged %d redirects, want %d", logged, len(tc.wantRelay))
			}
		})
	}
}

// storedMailboxes names the mailboxes holding the account's live messages, sorted,
// one entry per copy.
func storedMailboxes(t *testing.T, server *HTTPAPITestServer, accountID int64) []string {
	t.Helper()
	rows, err := server.rdb.QueryWithRetry(context.Background(), `
		SELECT mb.name
		FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE m.account_id = $1 AND m.expunged_at IS NULL
		ORDER BY mb.name
	`, accountID)
	if err != nil {
		t.Fatalf("query stored messages: %v", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan mailbox name: %v", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate stored messages: %v", err)
	}
	return names
}
