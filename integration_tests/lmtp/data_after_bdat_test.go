//go:build integration

package lmtp_test

import (
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// The backend advertises CHUNKING, and DATA and BDAT may not be mixed in one transaction
// (#762). RFC 3030 section 2: "DATA and BDAT commands cannot be used in the same
// transaction. If a DATA statement is issued after a BDAT for the current transaction, a
// 503 "Bad sequence of commands" MUST be issued." 502 means the command is not
// implemented (RFC 5321 section 4.2.4), and DATA is. MAIL and RCPT inside the BDAT
// transfer are a bad sequence as well.
func TestLMTP_DataAfterBDATIsBadSequence(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupLMTPServer(t)
	defer server.Close()

	c, lhlo := lhloSession(t, server.Address)
	chunking := false
	for _, line := range lhlo {
		chunking = chunking || strings.HasSuffix(line, "CHUNKING")
	}
	if !chunking {
		t.Fatalf("LHLO does not advertise CHUNKING: %q", lhlo)
	}

	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	for _, step := range []struct{ cmd, reply string }{
		{"MAIL FROM:<sender@example.org>", "250 "},
		{"RCPT TO:<" + account.Email + ">", "250 "},
		// The chunk is "Hello\r\n"; SendCommand adds the CRLF.
		{"BDAT 7\r\nHello", "250 "},
		// MAIL and RCPT are out of sequence after BDAT too: RFC 3030 section 2 sends
		// BDAT "After all MAIL and RCPT responses are collected and processed", and
		// RFC 5321 section 4.3.2 lists 503, not 502, for both.
		{"MAIL FROM:<other@example.org>", "503 5.5.1 "},
		{"RCPT TO:<" + account.Email + ">", "503 5.5.1 "},
		{"DATA", "503 5.5.1 "},
		// The state after the 503 is indeterminate; RSET clears it.
		{"RSET", "250 "},
	} {
		if err := c.SendCommand(step.cmd); err != nil {
			t.Fatalf("%q: %v", step.cmd, err)
		}
		reply, err := c.ReadResponse()
		if err != nil {
			t.Fatalf("%q: reading reply: %v", step.cmd, err)
		}
		if !strings.HasPrefix(reply, step.reply) {
			t.Fatalf("%q: got %q, want %q", step.cmd, reply, step.reply)
		}
	}
}
