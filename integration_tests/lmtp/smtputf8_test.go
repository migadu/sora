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

// SMTPUTF8 (RFC 6531) on the backend LMTP server. The production bounce behind these
// tests was "550 5.1.3 Bad destination mailbox address syntax" for
// RCPT TO:<me+josé@dejanstrbac.com>: a non-ASCII local part the address parser rejected.

// lhloSession connects and greets; the LHLO reply lines are returned for inspection.
func lhloSession(t *testing.T, lmtpAddr string) (*LMTPClient, []string) {
	t.Helper()
	c, err := NewLMTPClient(lmtpAddr)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.SendCommand("LHLO test.example.com"); err != nil {
		t.Fatalf("LHLO: %v", err)
	}
	lines, err := c.ReadMultilineResponse()
	if err != nil {
		t.Fatalf("LHLO response: %v", err)
	}
	return c, lines
}

// runTransaction sends MAIL FROM (mailFromArgs is the raw text after "MAIL FROM:", e.g.
// "<a@b> SMTPUTF8"), then RCPT TO and DATA, and returns the three replies. It stops at
// the first reply that is not 250, so rejections can be asserted too.
func runTransaction(t *testing.T, c *LMTPClient, mailFromArgs, rcpt, message string) (mailResp, rcptResp, dataResp string) {
	t.Helper()
	if err := c.SendCommand("MAIL FROM:" + mailFromArgs); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	var err error
	if mailResp, err = c.ReadResponse(); err != nil {
		t.Fatalf("MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(mailResp, "250") {
		return
	}
	if err := c.SendCommand("RCPT TO:<" + rcpt + ">"); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}
	if rcptResp, err = c.ReadResponse(); err != nil {
		t.Fatalf("RCPT TO response: %v", err)
	}
	if !strings.HasPrefix(rcptResp, "250") {
		return
	}
	if err := c.SendCommand("DATA"); err != nil {
		t.Fatalf("DATA: %v", err)
	}
	if resp, err := c.ReadResponse(); err != nil || !strings.HasPrefix(resp, "354") {
		t.Fatalf("DATA response: %q, %v", resp, err)
	}
	if err := c.SendCommand(message + "\r\n."); err != nil {
		t.Fatalf("send message: %v", err)
	}
	resps, err := c.ReadDataResponses(1)
	if err != nil {
		t.Fatalf("end-of-data response: %v", err)
	}
	return mailResp, rcptResp, resps[0]
}

func smtputf8TestMessage(subject string) string {
	return strings.Join([]string{
		"From: sender@example.com",
		"To: recipient@example.com",
		"Subject: " + subject,
		"Date: " + time.Now().Format(time.RFC1123Z),
		fmt.Sprintf("Message-ID: <smtputf8-%d@example.com>", time.Now().UnixNano()),
		"",
		"body",
	}, "\r\n")
}

func requireAccepted(t *testing.T, mailResp, rcptResp, dataResp string) {
	t.Helper()
	for what, resp := range map[string]string{"MAIL FROM": mailResp, "RCPT TO": rcptResp, "end-of-data": dataResp} {
		if !strings.HasPrefix(resp, "250") {
			t.Fatalf("%s must be accepted, got %q (MAIL %q, RCPT %q, DATA %q)", what, resp, mailResp, rcptResp, dataResp)
		}
	}
}

// RFC 6531 §3.1: a server that accepts internationalized envelopes announces SMTPUTF8.
func TestLMTP_SMTPUTF8_Advertised(t *testing.T) {
	_, lmtpAddr, _ := setupLMTPForDelivery(t)
	_, lines := lhloSession(t, lmtpAddr)
	for _, l := range lines {
		if strings.HasSuffix(strings.TrimSpace(l), "SMTPUTF8") {
			return
		}
	}
	t.Fatalf("LHLO must advertise SMTPUTF8, got:\n%s", strings.Join(lines, "\n"))
}

// The production case: an ASCII account addressed with a non-ASCII +detail. The
// transaction (with the SMTPUTF8 parameter) is accepted, the message lands in the
// account, the trace names UTF8LMTP, and the detail reaches Sieve's envelope test
// intact — the script files the message into a mailbox named after it.
func TestLMTP_SMTPUTF8_NonASCIIDetailReachesSieve(t *testing.T) {
	account, lmtpAddr, tempDir := setupLMTPForDelivery(t)
	ctx := context.Background()
	rdb := common.SetupTestDatabase(t)
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	script := `require ["fileinto", "envelope", "mailbox", "subaddress", "variables"];
if envelope :matches :detail "to" "*" {
  fileinto :create "${1}";
}`
	if _, err := rdb.ExecWithRetry(ctx,
		`INSERT INTO sieve_scripts (account_id, name, script, active) VALUES ($1, $2, $3, true)`,
		accountID, "smtputf8-detail", script); err != nil {
		t.Fatalf("store sieve script: %v", err)
	}

	local, domain, _ := strings.Cut(account.Email, "@")
	rcpt := local + "+josé@" + domain
	c, _ := lhloSession(t, lmtpAddr)
	mailResp, rcptResp, dataResp := runTransaction(t, c, "<josé@sender.example> SMTPUTF8", rcpt, smtputf8TestMessage("non-ascii detail"))
	requireAccepted(t, mailResp, rcptResp, dataResp)

	stored := readStoredMessage(t, tempDir)
	if !strings.HasPrefix(stored, "Delivered-To: "+account.Email+"\r\n") {
		t.Errorf("Delivered-To must be the account's primary address\n%s", head(stored))
	}
	if !strings.Contains(stored, "with UTF8LMTP") {
		t.Errorf("Received: must record the transaction as UTF8LMTP (RFC 6531 §3.7.3)\n%s", head(stored))
	}

	var n int
	if err := rdb.QueryRowWithRetry(ctx, `
		SELECT COUNT(*) FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE mb.account_id = $1 AND mb.name = $2`, accountID, "josé").Scan(&n); err != nil {
		t.Fatalf("count messages in mailbox josé: %v", err)
	}
	if n != 1 {
		t.Fatalf("Sieve must have filed the message into mailbox %q by its envelope detail, found %d messages there", "josé", n)
	}
}

// A non-ASCII primary address, delivered WITHOUT the SMTPUTF8 parameter: accepted anyway
// (an MTA that does not negotiate the extension still gets its mail delivered, as Postfix
// does with strict_smtputf8=no), the credential lookup finds the account, and the trace
// still records the transaction as internationalized.
func TestLMTP_SMTPUTF8_NonASCIIPrimaryAddressWithoutParameter(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	email := fmt.Sprintf("josé-%d@example.com", time.Now().UnixNano())
	account := common.CreateTestAccountWithEmail(t, rdb, email, "s3cur3p4ss!")
	lmtpAddr, tempDir := startLMTPForDelivery(t, rdb)

	c, _ := lhloSession(t, lmtpAddr)
	mailResp, rcptResp, dataResp := runTransaction(t, c, "<sender@example.com>", account.Email, smtputf8TestMessage("non-ascii primary"))
	requireAccepted(t, mailResp, rcptResp, dataResp)

	stored := readStoredMessage(t, tempDir)
	for _, want := range []string{"Delivered-To: " + email + "\r\n", "for <" + email + ">", "with UTF8LMTP"} {
		if !strings.Contains(stored, want) {
			t.Errorf("stored message missing %q\n%s", want, head(stored))
		}
	}
}

// Malformed UTF-8 is not an internationalized address. It stays a permanent syntax error
// on both MAIL FROM and RCPT TO — never a 4xx that would make the MTA retry forever.
func TestLMTP_SMTPUTF8_MalformedUTF8IsPermanent(t *testing.T) {
	account, lmtpAddr, _ := setupLMTPForDelivery(t)
	local, domain, _ := strings.Cut(account.Email, "@")

	t.Run("recipient", func(t *testing.T) {
		c, _ := lhloSession(t, lmtpAddr)
		_, rcptResp, _ := runTransaction(t, c, "<sender@example.com>", local+"+jos\xe9@"+domain, "")
		if !strings.HasPrefix(rcptResp, "5") {
			t.Fatalf("malformed UTF-8 recipient must be a permanent failure, got %q", rcptResp)
		}
	})
	t.Run("sender", func(t *testing.T) {
		c, _ := lhloSession(t, lmtpAddr)
		mailResp, _, _ := runTransaction(t, c, "<jos\xe9@sender.example>", account.Email, "")
		if !strings.HasPrefix(mailResp, "5") {
			t.Fatalf("malformed UTF-8 sender must be a permanent failure, got %q", mailResp)
		}
	})
}
