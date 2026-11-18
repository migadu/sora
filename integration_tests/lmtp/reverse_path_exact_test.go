//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTP_VacationAndRedirectKeepSenderLocalPart is #2101 over LMTP: the vacation reply
// goes to the MAIL FROM mailbox as the sender wrote it, and a redirect is relayed with it
// as MAIL FROM. The local part keeps its case (RFC 5321 §2.4: "SMTP implementations MUST
// take care to preserve the case of mailbox local-parts") and is quoted once, with the
// minimum quoting possible (RFC 5321 §4.1.2), so `"John.Doe"` goes back as John.Doe.
// The :days window still treats senders that differ only in case as one.
func TestLMTP_VacationAndRedirectKeepSenderLocalPart(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()
	rq := &captureRelayQueue{}
	addr := startTestLMTPServerWithRedirect(t, rdb, rq, 100, time.Hour)

	const forwardTo = "fwd@example.net"
	type delivery struct {
		mailFrom string // between the angle brackets of MAIL FROM
		want     string // the vacation reply's RCPT and the redirect's MAIL FROM
		reply    bool   // a vacation reply is due (the :days window is not open yet)
	}
	for _, tc := range []struct {
		name       string
		deliveries []delivery
	}{
		{name: "quoted local part with a space", deliveries: []delivery{
			{mailFrom: `"John Doe"@example.com`, want: `"John Doe"@example.com`, reply: true},
		}},
		{name: "quoted dot-string", deliveries: []delivery{
			{mailFrom: `"John.Doe"@example.com`, want: `John.Doe@example.com`, reply: true},
		}},
		{name: "dot-string and a days window blind to case", deliveries: []delivery{
			{mailFrom: `John.Doe@Example.com`, want: `John.Doe@example.com`, reply: true},
			{mailFrom: `JOHN.DOE@example.com`, want: `JOHN.DOE@example.com`, reply: false},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := common.CreateTestAccount(t, rdb)
			accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
			if err != nil {
				t.Fatalf("account id: %v", err)
			}
			setActiveSieveScript(t, rdb, accountID, `require ["vacation"]; redirect "`+forwardTo+`"; vacation :days 1 "Away.";`)

			for _, d := range tc.deliveries {
				before := len(rq.items())
				stamp := time.Now().UnixNano()
				msg := strings.Join([]string{
					"From: sender@example.com",
					"To: " + account.Email,
					fmt.Sprintf("Subject: hello %d", stamp),
					fmt.Sprintf("Message-ID: <%d@example.com>", stamp),
					"", "body",
				}, "\r\n")
				if resp := deliverLMTPRaw(t, addr, d.mailFrom, account.Email, msg); !strings.HasPrefix(resp, "250") {
					t.Fatalf("MAIL FROM:<%s>: delivery %s", d.mailFrom, resp)
				}

				var replies, redirectsFrom []string
				for _, it := range rq.items()[before:] {
					switch it.msgType {
					case "vacation":
						replies = append(replies, it.to)
					case "redirect":
						redirectsFrom = append(redirectsFrom, it.from)
					}
				}
				wantReplies := []string{}
				if d.reply {
					wantReplies = []string{d.want}
				}
				if fmt.Sprint(replies) != fmt.Sprint(wantReplies) {
					t.Errorf("MAIL FROM:<%s>: vacation replies to %q, want %q", d.mailFrom, replies, wantReplies)
				}
				if len(redirectsFrom) != 1 || redirectsFrom[0] != d.want {
					t.Errorf("MAIL FROM:<%s>: redirects relayed with MAIL FROM %q, want one with %q", d.mailFrom, redirectsFrom, d.want)
				}
			}
		})
	}
}
