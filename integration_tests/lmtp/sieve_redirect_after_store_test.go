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
)

// TestLMTP_SieveRedirectRelayedOnlyAfterStore is issue #452: a redirect is handed to
// the relay only once the message is stored. A store that fails is answered 451 and
// the MTA retries the delivery; had the redirect been relayed before the store, every
// retry would relay it again.
func TestLMTP_SieveRedirectRelayedOnlyAfterStore(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapSrv, account := common.SetupIMAPServer(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	setActiveSieveScript(t, rdb, accountID, "require [\"copy\"];\r\nredirect :copy \"other@example.org\";\r\n")
	rq := &captureRelayQueue{}
	lmtpAddr := startTestLMTPServerWithRedirect(t, rdb, rq, 100, time.Hour)

	const sender = "sender@example.com"
	msg := strings.Join([]string{
		"From: " + sender,
		"To: " + account.Email,
		"Subject: redirect after store",
		fmt.Sprintf("Message-ID: <%d@example.com>", time.Now().UnixNano()),
		"",
		"body",
	}, "\r\n")

	// First attempt: INBOX goes away between RCPT, which creates the default
	// mailboxes, and DATA, so storing the :copy fails.
	resp := deliverLMTPRawBeforeData(t, lmtpAddr, sender, account.Email, msg, func() {
		if _, err := rdb.ExecWithRetry(ctx,
			"UPDATE mailboxes SET deleted_at = NOW() WHERE account_id = $1 AND LOWER(name) = 'inbox' AND deleted_at IS NULL",
			accountID); err != nil {
			t.Fatalf("remove INBOX: %v", err)
		}
	})
	if !strings.HasPrefix(resp, "4") {
		t.Fatalf("want a temporary failure when the message cannot be stored, got %s", resp)
	}
	if got := rq.relayedTo(); len(got) != 0 {
		t.Errorf("a delivery whose store failed relayed the message to %v", got)
	}

	// The MTA's retry: RCPT recreates INBOX, the message is stored and relayed once.
	if resp := deliverLMTPRaw(t, lmtpAddr, sender, account.Email, msg); !strings.HasPrefix(resp, "250") {
		t.Fatalf("retry: want 250, got %s", resp)
	}
	if got, want := rq.relayedTo(), []string{"other@example.org"}; !slices.Equal(got, want) {
		t.Errorf("after the retry the message was relayed to %v, want %v (once)", got, want)
	}
	if n := countInMailbox(t, rdb, accountID, "INBOX"); n != 1 {
		t.Errorf("INBOX holds %d copies after the retry, want 1", n)
	}
}

// deliverLMTPRawBeforeData runs one LMTP transaction like deliverLMTPRaw, calling
// beforeData once RCPT has been accepted and before DATA is sent.
func deliverLMTPRawBeforeData(t *testing.T, lmtpAddr, from, rcpt, message string, beforeData func()) string {
	t.Helper()
	c, err := NewLMTPClient(lmtpAddr)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	steps := []struct{ cmd, want string }{
		{"LHLO test.example.com", "250"},
		{fmt.Sprintf("MAIL FROM:<%s>", from), "250"},
		{fmt.Sprintf("RCPT TO:<%s>", rcpt), "250"},
	}
	for _, step := range steps {
		if err := c.SendCommand(step.cmd); err != nil {
			t.Fatalf("%s: %v", step.cmd, err)
		}
		lines, err := c.ReadMultilineResponse()
		if err != nil {
			t.Fatalf("%s response: %v", step.cmd, err)
		}
		if last := lines[len(lines)-1]; !strings.HasPrefix(last, step.want) {
			t.Fatalf("%s: got %s", step.cmd, last)
		}
	}
	beforeData()
	if err := c.SendCommand("DATA"); err != nil {
		t.Fatalf("DATA: %v", err)
	}
	if _, err := c.ReadResponse(); err != nil {
		t.Fatalf("DATA response: %v", err)
	}
	if err := c.SendCommand(message + "\r\n."); err != nil {
		t.Fatalf("send message: %v", err)
	}
	resp, err := c.ReadDataResponses(1)
	if err != nil {
		t.Fatalf("DATA per-recipient response: %v", err)
	}
	return resp[0]
}
