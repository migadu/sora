//go:build integration

package lmtp_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
)

// Multiple targets may partially accept a message. A local spool failure must
// happen before any handoff, or a sender retry would queue accepted targets twice.
func TestLMTP_SieveMultipleRedirectsSpoolFailureRelaysNothing(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account := common.SetupIMAPServer(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	id, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatal(err)
	}
	setActiveSieveScript(t, rdb, id, `redirect "one@example.com"; redirect "two@example.org";`)
	q := &refusingRelayQueue{refuse: "two@example.org"}
	addr, up := startTestLMTPServerWithOptions(t, rdb, lmtpserver.LMTPServerOptions{RelayQueue: q, RedirectRateLimit: 100, RedirectRateWindow: time.Hour})
	accountDir := filepath.Dir(up.FilePath(strings.Repeat("0", 64), id))
	if err := os.WriteFile(accountDir, []byte("obstruct spool directory"), 0600); err != nil {
		t.Fatal(err)
	}
	msg := "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: same delivery retry\r\nMessage-ID: <spool-retry@example.com>\r\n\r\nbody\r\n"
	first := deliverLMTPRaw(t, addr, "sender@example.com", account.Email, msg)
	if !strings.HasPrefix(first, "4") {
		t.Fatalf("want temporary spool failure, got %s", first)
	}
	if q.count() != 0 {
		t.Fatalf("spool failure relayed to %d targets; reply=%s", q.count(), first)
	}
	if err := os.Remove(accountDir); err != nil {
		t.Fatal(err)
	}
	second := deliverLMTPRaw(t, addr, "sender@example.com", account.Email, msg)
	if !strings.HasPrefix(second, "250") || q.count() != 1 {
		t.Fatalf("retry must hand off once: %s count=%d", second, q.count())
	}
	if n := countInMailbox(t, rdb, id, "INBOX"); n != 1 {
		t.Fatalf("failed second target needs one INBOX fallback, got %d", n)
	}
}
