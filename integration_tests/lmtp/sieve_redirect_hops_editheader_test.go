//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/sieveengine"
)

// TestLMTP_SieveRedirectHops_DeleteheaderKeepsCount is issue #1624: with editheader
// enabled, a script that deletes X-Sora-Loop and Delivered-To before redirect must not
// restart the redirect hop count. Each redirect is stamped one above the count the
// message arrived with, so a message fed back through the same script (a self-redirect,
// or a cycle of accounts with such scripts) is redirected max_redirect_hops times and
// then kept.
func TestLMTP_SieveRedirectHops_DeleteheaderKeepsCount(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	setActiveSieveScript(t, rdb, accountID, strings.Join([]string{
		`require ["editheader"];`,
		`deleteheader "X-Sora-Loop";`,
		`deleteheader "Delivered-To";`,
		`redirect "other@example.org";`,
	}, "\r\n")+"\r\n")

	const maxHops = 2
	rq := &captureRelayQueue{}
	lmtpAddr, _ := startTestLMTPServerWithOptions(t, rdb, lmtpserver.LMTPServerOptions{
		RelayQueue:      rq,
		SieveExtensions: sieveengine.EffectiveExtensions(append(slices.Clone(sieveengine.DefaultSieveExtensions), "editheader")),
		MaxRedirectHops: maxHops,
	})
	inboxBefore := countInMailbox(t, rdb, accountID, "INBOX")

	msg := strings.Join([]string{
		"From: sender@example.com",
		"To: " + account.Email,
		"Subject: redirect hops",
		"Date: " + time.Now().Format(time.RFC1123Z),
		fmt.Sprintf("Message-ID: <%d@example.com>", time.Now().UnixNano()),
		"",
		"body",
	}, "\r\n")
	for pass := 1; pass <= maxHops+2; pass++ {
		before := rq.count()
		if resp := deliverLMTPRaw(t, lmtpAddr, "sender@example.com", account.Email, msg); !strings.HasPrefix(resp, "250") {
			t.Fatalf("pass %d: delivery not accepted: %s", pass, resp)
		}
		if rq.count() == before {
			break // not redirected: kept
		}
		rq.mu.Lock()
		relayed := rq.enqueued[len(rq.enqueued)-1].body
		rq.mu.Unlock()
		if hops := relayedHopCount(t, relayed); hops != pass {
			t.Errorf("pass %d: redirected copy carries %s: %d, want %d (one above the count it arrived with)",
				pass, helpers.RedirectLoopHeader, hops, pass)
		}
		// Feed the redirected copy back in, as the redirect target would.
		msg = strings.TrimSuffix(string(relayed), "\r\n")
	}

	if got := rq.count(); got != maxHops {
		t.Errorf("message redirected %d times, want max_redirect_hops = %d", got, maxHops)
	}
	if n := countInMailbox(t, rdb, accountID, "INBOX") - inboxBefore; n != 1 {
		t.Errorf("copies kept in INBOX = %d, want 1 (the redirect refused at the hop limit keeps the message)", n)
	}
}

// relayedHopCount reads the redirect hop count of a relayed message.
func relayedHopCount(t *testing.T, msg []byte) int {
	t.Helper()
	m, err := mail.ReadMessage(strings.NewReader(string(msg)))
	if err != nil {
		t.Fatalf("parse relayed message: %v", err)
	}
	return helpers.RedirectHopCount(helpers.HeaderGetter(m.Header))
}
