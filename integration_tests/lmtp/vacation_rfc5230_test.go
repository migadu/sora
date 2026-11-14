//go:build integration

package lmtp_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTP_SieveVacationRFC5230 is issue #326 over LMTP. Mail for the user also
// arrives through an outside forwarding address, which the script lists in
// :addresses. RFC 5230 §4.5 counts such an address as the recipient's for the
// personal message check; §5.1 asks for MAIL FROM <>; §5.3 makes the default subject
// "Auto: " followed by the original subject.
func TestLMTP_SieveVacationRFC5230(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapSrv, account := common.SetupIMAPServer(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB

	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	if _, err := rdb.ExecWithRetry(context.Background(), "DELETE FROM vacation_responses WHERE account_id = $1", accountID); err != nil {
		t.Fatalf("clear vacation_responses: %v", err)
	}
	const forwarded = "user@example.net" // not a credential of the account
	setActiveSieveScript(t, rdb, accountID, strings.Join([]string{
		`require ["vacation"];`,
		`vacation :days 1 :addresses ["` + forwarded + `"] "I am away until Monday.";`,
	}, "\r\n")+"\r\n")

	rq := &captureRelayQueue{}
	lmtpAddr := startTestLMTPServerWithRedirect(t, rdb, rq, 10, time.Hour)

	for _, to := range []string{account.Email, forwarded} {
		t.Run("To "+to, func(t *testing.T) {
			// A sender of its own: the :days window is per sender.
			sender := fmt.Sprintf("sender-%d@example.org", time.Now().UnixNano())
			before := len(rq.items())
			msg := strings.Join([]string{
				"From: " + sender,
				"To: " + to,
				"Subject: Project update",
				fmt.Sprintf("Message-ID: <%d@example.org>", time.Now().UnixNano()),
				"",
				"body",
			}, "\r\n")
			if resp := deliverLMTPRaw(t, lmtpAddr, sender, account.Email, msg); !strings.HasPrefix(resp, "250") {
				t.Fatalf("delivery not accepted: %s", resp)
			}

			var replies []relayItem
			for _, it := range rq.items()[before:] {
				if it.msgType == "vacation" {
					replies = append(replies, it)
				}
			}
			if len(replies) != 1 {
				t.Fatalf("the message is personal: want 1 vacation reply, got %d", len(replies))
			}
			reply := replies[0]
			if reply.from != "" || reply.to != sender {
				t.Errorf("reply envelope = <%s> -> <%s>, want <> -> <%s>", reply.from, reply.to, sender)
			}
			entity, err := mail.CreateReader(bytes.NewReader(reply.body))
			if err != nil {
				t.Fatalf("parse reply: %v", err)
			}
			if subject, _ := entity.Header.Subject(); subject != "Auto: Project update" {
				t.Errorf("reply subject = %q, want %q", subject, "Auto: Project update")
			}
		})
	}
}
