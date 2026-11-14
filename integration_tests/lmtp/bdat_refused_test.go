//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// A BDAT the backend refuses fails the transaction, so a BDAT LAST the client pipelined
// behind it does not deliver a message that lacks the refused chunk. RFC 3030 section 2:
// "If a 5XX or 4XX code is received by the sender-SMTP in response to a BDAT chunk, the
// transaction should be considered failed", and the receiver "MUST be prepared to accept
// and discard additional BDAT chunks already in the pipeline after the failed BDAT".
func TestLMTP_RefusedBDATFailsTransaction(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	lmtpAddr, _ := startLMTPForDelivery(t, rdb)

	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	countMessages := func() int {
		t.Helper()
		var n int
		if err := rdb.QueryRowWithRetry(ctx,
			`SELECT COUNT(*) FROM messages WHERE account_id = $1`, accountID).Scan(&n); err != nil {
			t.Fatalf("count messages: %v", err)
		}
		return n
	}

	c, err := NewLMTPClient(lmtpAddr)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	expect := func(prefix string) {
		t.Helper()
		line, err := c.ReadResponse()
		if err != nil {
			t.Fatalf("reading reply: %v", err)
		}
		if !strings.HasPrefix(line, prefix) {
			t.Fatalf("reply %q, want %q", line, prefix)
		}
	}
	transaction := func() {
		t.Helper()
		c.SendCommand("MAIL FROM:<sender@example.org>")
		expect("250 ")
		c.SendCommand("RCPT TO:<" + account.Email + ">")
		expect("250 ")
	}

	if err := c.SendCommand("LHLO client.example.org"); err != nil {
		t.Fatalf("LHLO: %v", err)
	}
	if _, err := c.ReadMultilineResponse(); err != nil {
		t.Fatalf("LHLO response: %v", err)
	}

	header := "From: sender@example.org\r\nTo: " + account.Email + "\r\nSubject: bdat\r\n\r\n"
	const refused, tail = "second part\r\n", "last part\r\n"

	transaction()
	fmt.Fprintf(c.conn, "BDAT %d\r\n%s", len(header), header)
	expect("250 ")
	// One write, as a pipelining client sends it: a refused BDAT (unknown end marker),
	// then the BDAT LAST that would complete the message without the refused chunk.
	fmt.Fprintf(c.conn, "BDAT %d FIRST\r\n%sBDAT %d LAST\r\n%sNOOP\r\n", len(refused), refused, len(tail), tail)
	expect("501 ")
	line, err := c.ReadResponse()
	if err != nil {
		t.Fatalf("reading reply: %v", err)
	}
	if !strings.HasPrefix(line, "5") {
		t.Fatalf("BDAT LAST behind the refused BDAT: %q, want a refusal; the transaction went on without the refused chunk", line)
	}
	expect("250 2.0.0 I have successfully done nothing")
	if n := countMessages(); n != 0 {
		t.Fatalf("%d messages delivered after the refused BDAT, want none", n)
	}

	// Control: the same connection delivers a complete message by BDAT.
	c.SendCommand("RSET")
	expect("250 ")
	transaction()
	body := header + refused + tail
	fmt.Fprintf(c.conn, "BDAT %d LAST\r\n%s", len(body), body)
	expect("250 ")
	if n := countMessages(); n != 1 {
		t.Fatalf("%d messages after a complete BDAT transaction, want 1", n)
	}
}
