//go:build integration

package lmtp_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/lmtp"
)

// The message size limit over the wire, where go-smtp's DATA reader enforces it as well
// as the session. RFC 1870 section 4 makes the advertised SIZE "the size of the largest
// message that the server is willing to accept", counted per section 5 with CR-LF pairs
// but without the terminating dot: a message of exactly max_message_size is delivered.
// One octet more is refused with 552 5.3.4, and the rest of that body is consumed as
// data, never read as commands.
func TestLMTP_MessageSizeLimitOverTheWire(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// The message as it goes on the wire, its final CRLF included and the end-of-data
	// line not, which is what RFC 1870 section 5 counts.
	header := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: size limit\r\n\r\n"
	content := header + strings.Repeat("a", 200) + "\r\n"
	limit := int64(len(content))

	server, account := common.SetupLMTPServerWithOptions(t, lmtp.LMTPServerOptions{MaxMessageSize: limit})
	defer server.Close()

	c, lhlo := lhloSession(t, server.Address)
	if want := fmt.Sprintf("250-SIZE %d", limit); !containsLine(lhlo, want) {
		t.Fatalf("LHLO reply %q lacks %q", lhlo, want)
	}

	// runTransaction appends the CRLF before the end-of-data line.
	_, _, data := runTransaction(t, c, "<sender@example.com>", account.Email, strings.TrimSuffix(content, "\r\n"))
	if !strings.HasPrefix(data, "250 ") {
		t.Fatalf("message of exactly max_message_size (%d octets): %q, want 250", limit, data)
	}

	oversized := header + strings.Repeat("a", 201) + "\r\n" +
		"MAIL FROM:<smuggled@example.org>\r\n" +
		"RCPT TO:<" + account.Email + ">\r\n" +
		"DATA"
	_, _, data = runTransaction(t, c, "<sender@example.com>", account.Email, oversized)
	if !strings.HasPrefix(data, "552 5.3.4 ") {
		t.Fatalf("message over max_message_size: %q, want 552 5.3.4", data)
	}

	if err := c.SendCommand("NOOP"); err != nil {
		t.Fatal(err)
	}
	if resp, err := c.ReadResponse(); err != nil || !strings.HasPrefix(resp, "250 ") {
		t.Fatalf("NOOP after the refused message: %q, %v (the rest of the body was read as commands?)", resp, err)
	}
}

func containsLine(lines []string, want string) bool {
	for _, line := range lines {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}
