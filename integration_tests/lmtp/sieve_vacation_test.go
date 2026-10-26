//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	lmtpserver "github.com/migadu/sora/server/lmtp"
)

// TestLMTP_SieveVacation_AlongsideOtherActions is issue #113's reproduction driven
// through the full LMTP delivery path: one active script holds the vacation and the
// user's filters, the way alps writes an auto-reply. RFC 5230 §4.7: "Vacation does not
// affect Sieve's implicit keep action" and "Implementations MUST NOT consider vacation
// used with discard, keep, fileinto, or redirect an error." So every message gets the
// reply, whatever the filters did with it, and what the filters did still happens. That
// includes the default script's filing, which a user script that only keeps the
// message leaves standing.
func TestLMTP_SieveVacation_AlongsideOtherActions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapSrv, account := common.SetupIMAPServer(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	for _, name := range []string{"Invoices", "Junk"} {
		if _, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, name); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	for _, table := range []string{"sieve_scripts", "vacation_responses", "redirect_log"} {
		if _, err := rdb.ExecWithRetry(ctx, "DELETE FROM "+table+" WHERE account_id = $1", accountID); err != nil {
			t.Fatalf("clear %s: %v", table, err)
		}
	}

	const redirectTarget = "elsewhere@example.net"
	script := strings.Join([]string{
		`require ["fileinto", "vacation"];`,
		`vacation :days 1 :subject "Away" "I am away until Monday.";`,
		`if header :contains "subject" "invoice" { fileinto "Invoices"; }`,
		`elsif header :contains "subject" "forward" { redirect "` + redirectTarget + `"; }`,
		`elsif header :contains "subject" "drop" { discard; }`,
	}, "\r\n") + "\r\n"
	if _, err := rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
		VALUES ($1, $2, $3, true, NOW(), NOW())`,
		accountID, "away-and-filters", script); err != nil {
		t.Fatalf("insert sieve: %v", err)
	}

	rq := &captureRelayQueue{}
	lmtpAddr := startTestLMTPServerWithRedirect(t, rdb, rq, 10, time.Hour)

	cases := []struct {
		name    string
		subject string
		header  string // an extra header line
		stored  string // the mailbox the message must be in; "" for none
		relayed bool   // the message itself must be redirected
	}{
		{name: "keep", subject: "hello", stored: "INBOX"},
		// default.sieve files spam into Junk; the user script keeps it, so Junk stands.
		{name: "default script files spam", subject: "cheap", header: "X-Spam: Yes", stored: "Junk"},
		{name: "fileinto", subject: "invoice 42", stored: "Invoices"},
		{name: "redirect", subject: "forward this", relayed: true},
		{name: "discard", subject: "drop this"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A sender of its own: the :days window an earlier case opened is per sender.
			stamp := time.Now().UnixNano()
			sender := fmt.Sprintf("sender-%d@example.com", stamp)
			subject := fmt.Sprintf("%s %d", tc.subject, stamp)
			relayedBefore := len(rq.items())

			lines := []string{
				"From: " + sender,
				"To: " + account.Email,
				"Subject: " + subject,
				"Date: " + time.Now().Format(time.RFC1123Z),
				fmt.Sprintf("Message-ID: <%d@example.com>", stamp),
			}
			if tc.header != "" {
				lines = append(lines, tc.header)
			}
			msg := strings.Join(append(lines, "", "body"), "\r\n")
			if resp := deliverLMTPRaw(t, lmtpAddr, sender, account.Email, msg); !strings.HasPrefix(resp, "250") {
				t.Fatalf("delivery not accepted: %s", resp)
			}

			var replies, redirects int
			for _, it := range rq.items()[relayedBefore:] {
				switch {
				case it.msgType == "vacation" && it.to == sender:
					replies++
				case it.msgType == "redirect" && it.to == redirectTarget:
					redirects++
				default:
					t.Errorf("unexpected relay item %+v", it)
				}
			}
			if replies != 1 {
				t.Errorf("the sender must get exactly one vacation reply, got %d", replies)
			}
			wantRedirects := 0
			if tc.relayed {
				wantRedirects = 1
			}
			if redirects != wantRedirects {
				t.Errorf("redirects = %d, want %d", redirects, wantRedirects)
			}

			got := mailboxesHolding(t, rdb, accountID, subject)
			if tc.stored == "" && len(got) != 0 {
				t.Errorf("the message must not be stored, found it in %v", got)
			}
			if tc.stored != "" && (len(got) != 1 || got[0] != tc.stored) {
				t.Errorf("the message must be stored once in %s, found it in %v", tc.stored, got)
			}
		})
	}
}

// TestLMTP_SieveDefaultFilingKeepsUserEditsAndFlags: when the user script ends in
// the implicit keep, the default script's filing stands, and what else the user
// script did still happens: its flags, its header edits, and its vacation, which sees
// those edits (RFC 5293 §7). An Auto-Submitted header the user adds therefore
// suppresses the reply. Only the reply used to be carried over to the default's
// result, so the message was filed without the user's flags and edits, and replied to.
func TestLMTP_SieveDefaultFilingKeepsUserEditsAndFlags(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapSrv, account := common.SetupIMAPServer(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	if _, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, "Junk"); err != nil {
		t.Fatalf("create Junk: %v", err)
	}
	for _, table := range []string{"sieve_scripts", "vacation_responses"} {
		if _, err := rdb.ExecWithRetry(ctx, "DELETE FROM "+table+" WHERE account_id = $1", accountID); err != nil {
			t.Fatalf("clear %s: %v", table, err)
		}
	}
	script := strings.Join([]string{
		`require ["vacation", "editheader", "imap4flags"];`,
		`addheader "Auto-Submitted" "auto-generated";`,
		`addheader "X-User-Edit" "kept";`,
		`addflag "UserTag";`,
		`vacation :days 1 "I am away until Monday.";`,
	}, "\r\n") + "\r\n"
	if _, err := rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
		VALUES ($1, $2, $3, true, NOW(), NOW())`,
		accountID, "edits-and-away", script); err != nil {
		t.Fatalf("insert sieve: %v", err)
	}

	rq := &captureRelayQueue{}
	lmtpAddr, up := startTestLMTPServerWithOptions(t, rdb, lmtpserver.LMTPServerOptions{
		RelayQueue: rq,
		// default.sieve's extensions, and editheader and imap4flags for the user script.
		SieveExtensions: []string{"fileinto", "envelope", "mailbox", "subaddress", "variables", "vacation", "editheader", "imap4flags"},
	})

	stamp := time.Now().UnixNano()
	sender := fmt.Sprintf("sender-%d@example.com", stamp)
	subject := fmt.Sprintf("cheap %d", stamp)
	msg := strings.Join([]string{
		"From: " + sender,
		"To: " + account.Email,
		"Subject: " + subject,
		fmt.Sprintf("Message-ID: <%d@example.com>", stamp),
		"X-Spam: Yes",
		"",
		"body",
	}, "\r\n")
	if resp := deliverLMTPRaw(t, lmtpAddr, sender, account.Email, msg); !strings.HasPrefix(resp, "250") {
		t.Fatalf("delivery not accepted: %s", resp)
	}

	var mailbox, flags, contentHash string
	if err := rdb.QueryRowWithRetry(ctx, `
		SELECT mb.name, ms.custom_flags::text, m.content_hash
		FROM messages m
		JOIN message_state ms ON ms.message_id = m.id
		JOIN mailboxes mb ON mb.id = m.mailbox_id
		WHERE mb.account_id = $1 AND m.subject = $2 AND m.expunged_at IS NULL
	`, accountID, subject).Scan(&mailbox, &flags, &contentHash); err != nil {
		t.Fatalf("find message: %v", err)
	}
	if mailbox != "Junk" {
		t.Errorf("the default script's filing must stand: stored in %s, want Junk", mailbox)
	}
	if !strings.Contains(strings.ToLower(flags), "usertag") {
		t.Errorf("the user's flag was dropped: custom flags %s", flags)
	}
	stored, err := os.ReadFile(up.FilePath(contentHash, accountID))
	if err != nil {
		t.Fatalf("read stored message: %v", err)
	}
	if !strings.Contains(string(stored), "X-User-Edit: kept") {
		t.Errorf("the user's header edit was dropped from the stored message")
	}
	for _, it := range rq.items() {
		if it.msgType == "vacation" {
			t.Errorf("the user's Auto-Submitted header must suppress the reply, got %+v", it)
		}
	}
}

// items returns a snapshot of everything enqueued so far.
func (q *captureRelayQueue) items() []relayItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]relayItem(nil), q.enqueued...)
}

// mailboxesHolding names the mailboxes of ownerAccountID holding a live message with
// the given subject, one entry per copy.
func mailboxesHolding(t *testing.T, rdb *resilient.ResilientDatabase, ownerAccountID int64, subject string) []string {
	t.Helper()
	rows, err := rdb.QueryWithRetry(context.Background(), `
		SELECT mb.name
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE mb.account_id = $1 AND m.subject = $2 AND m.expunged_at IS NULL
		ORDER BY mb.name
	`, ownerAccountID, subject)
	if err != nil {
		t.Fatalf("find message %q: %v", subject, err)
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
		t.Fatalf("find message %q: %v", subject, err)
	}
	return names
}
