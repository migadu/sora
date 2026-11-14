//go:build integration

package lmtp_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// DATA or non-final BDAT after every RCPT was refused, and BDAT after a
// completed BDAT LAST, are a bad sequence of commands: 503, not 502 (#748). RFC 2033 section 4.2: "when there have
// been no successful RCPT commands in the mail transaction, the DATA command MUST fail
// with a 503 reply code." RFC 3030 section 2: "Any BDAT command sent after the BDAT LAST
// is illegal and MUST be replied to with a 503 "Bad sequence of commands" reply code."
func TestLMTP_OutOfSequenceAfterRecipientOrDelivery(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	lmtpAddr, _ := startLMTPForDelivery(t, rdb)

	c, err := NewLMTPClient(lmtpAddr)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	expect := func(cmd, prefix string) {
		t.Helper()
		line, err := c.ReadResponse()
		if err != nil {
			t.Fatalf("%s: reading reply: %v", cmd, err)
		}
		if !strings.HasPrefix(line, prefix) {
			t.Fatalf("%s: %q, want %q", cmd, line, prefix)
		}
	}
	send := func(cmd, prefix string) {
		t.Helper()
		c.SendCommand(cmd)
		expect(cmd, prefix)
	}
	outOfSequence := func(cmd string) {
		t.Helper()
		c.SendCommand(cmd)
		line, err := c.ReadResponse()
		if err != nil {
			t.Fatalf("%s: reading reply: %v", cmd, err)
		}
		if !strings.HasPrefix(line, "503 5.5.1 ") {
			t.Errorf("%s: %q, want 503 5.5.1 (bad sequence of commands)", cmd, line)
		}
	}

	c.SendCommand("LHLO client.example.org")
	if _, err := c.ReadMultilineResponse(); err != nil {
		t.Fatalf("LHLO response: %v", err)
	}

	// Every recipient refused: no successful RCPT in the transaction.
	// Use non-LAST BDAT: LMTP LAST has a distinct zero-reply rule (RFC 2033 section 4.3).
	for _, cmd := range []string{"DATA", "BDAT 0"} {
		send("MAIL FROM:<sender@example.org>", "250 ")
		send("RCPT TO:<nobody-748@example.com>", "550 ")
		outOfSequence(cmd)
		send("RSET", "250 ")
	}

	// A message delivered by BDAT LAST ends the transaction; a further BDAT is illegal.
	send("MAIL FROM:<sender@example.org>", "250 ")
	send("RCPT TO:<"+account.Email+">", "250 ")
	body := "From: sender@example.org\r\nTo: " + account.Email + "\r\nSubject: bdat\r\n\r\nbody\r\n"
	fmt.Fprintf(c.conn, "BDAT %d LAST\r\n%s", len(body), body)
	expect("BDAT LAST", "250 ")
	outOfSequence("BDAT 0 LAST")
}
