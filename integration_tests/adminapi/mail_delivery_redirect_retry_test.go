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

// targetRelayQueue records the redirect targets handed to the relay worker.
type targetRelayQueue struct {
	mu      sync.Mutex
	targets []string
}

func (q *targetRelayQueue) Enqueue(from, to, messageType string, messageBytes []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if messageType == "redirect" {
		q.targets = append(q.targets, to)
	}
	return nil
}

// Hold records the message when it is committed, which is when the relay worker
// would first see it.
func (q *targetRelayQueue) Hold(from, to, messageType string, messageBytes []byte) (func() error, func(), error) {
	return func() error { return q.Enqueue(from, to, messageType, messageBytes) }, func() {}, nil
}

func (q *targetRelayQueue) relayedTo() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	got := append([]string(nil), q.targets...)
	slices.Sort(got)
	return got
}

// TestAdminAPI_DeliverMail_SieveRedirectRetryNotRequeued is issue #1942, the Admin API
// half of #1912: a caller that retries POST /admin/mail/deliver (it timed out after Sora
// had already queued the redirects) must not get the redirects queued again, with or
// without :copy. The retry goes to a second Admin API server with its own relay queue,
// as a retry may land on another node: only the database is shared.
func TestAdminAPI_DeliverMail_SieveRedirectRetryNotRequeued(t *testing.T) {
	for _, tc := range []struct {
		name    string
		script  string
		targets []string // sorted
	}{
		{"redirect", `redirect "fwd@example.org";`, []string{"fwd@example.org"}},
		{"redirect copy", `require ["copy"]; redirect :copy "fwd@example.org";`, []string{"fwd@example.org"}},
		{"several redirects", `redirect "one@example.com"; redirect "two@example.org";`, []string{"one@example.com", "two@example.org"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)

			newNode := func() (*HTTPAPITestServer, *targetRelayQueue) {
				rq := &targetRelayQueue{}
				srv, _ := setupHTTPAPIServerWithOptions(t, func(o *adminapi.ServerOptions) { o.RelayQueue = rq })
				t.Cleanup(srv.Close)
				return srv, rq
			}
			nodeA, rqA := newNode()
			nodeB, rqB := newNode()

			email := fmt.Sprintf("redirect-retry-%d@example.com", time.Now().UnixNano())
			createDeliveryAccount(t, nodeA, email)
			setActiveScript(t, nodeA, email, tc.script+"\r\n")

			msg := strings.Join([]string{
				"From: sender@example.com",
				"To: " + email,
				"Subject: redirect retry",
				fmt.Sprintf("Message-ID: <%d@example.com>", time.Now().UnixNano()),
				"", "body", "",
			}, "\r\n")

			deliverRaw(t, nodeA, email, msg)
			if got := rqA.relayedTo(); !slices.Equal(got, tc.targets) {
				t.Fatalf("first delivery relayed to %v, want %v", got, tc.targets)
			}

			// The caller's retry of the same request, on another node.
			deliverRaw(t, nodeB, email, msg)
			if got := rqB.relayedTo(); len(got) != 0 {
				t.Errorf("the retry queued the redirects again: %v (the first delivery already queued %v)", got, tc.targets)
			}
		})
	}
}

// TestAdminAPI_DeliverMail_SieveRedirectSameMessageIDNewContent: a message that is not
// a retry, only shares the Message-ID of one already redirected, is redirected too.
func TestAdminAPI_DeliverMail_SieveRedirectSameMessageIDNewContent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rq := &targetRelayQueue{}
	srv, _ := setupHTTPAPIServerWithOptions(t, func(o *adminapi.ServerOptions) { o.RelayQueue = rq })
	defer srv.Close()

	email := fmt.Sprintf("redirect-newcontent-%d@example.com", time.Now().UnixNano())
	createDeliveryAccount(t, srv, email)
	setActiveScript(t, srv, email, `redirect "fwd@example.org";`+"\r\n")

	msgID := fmt.Sprintf("Message-ID: <%d@example.com>", time.Now().UnixNano())
	for _, body := range []string{"first body", "second body"} {
		deliverRaw(t, srv, email, strings.Join([]string{"From: sender@example.com", "To: " + email, "Subject: same id", msgID, "", body, ""}, "\r\n"))
	}
	if got, want := rq.relayedTo(), []string{"fwd@example.org", "fwd@example.org"}; !slices.Equal(got, want) {
		t.Errorf("relayed to %v, want %v: two different messages are two redirects", got, want)
	}
}

func setActiveScript(t *testing.T, srv *HTTPAPITestServer, email, script string) {
	t.Helper()
	ctx := context.Background()
	accountID, err := srv.rdb.GetAccountIDByAddressWithRetry(ctx, email)
	if err != nil {
		t.Fatalf("lookup account: %v", err)
	}
	sc, err := srv.rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
	if err != nil {
		t.Fatalf("create sieve script: %v", err)
	}
	if err := srv.rdb.SetScriptActiveWithRetry(ctx, sc.ID, accountID, true); err != nil {
		t.Fatalf("activate sieve script: %v", err)
	}
}

func deliverRaw(t *testing.T, srv *HTTPAPITestServer, email, msg string) {
	t.Helper()
	resp, body := srv.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{
		"recipients": []string{email},
		"message":    msg,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deliver: %d %s", resp.StatusCode, string(body))
	}
}
