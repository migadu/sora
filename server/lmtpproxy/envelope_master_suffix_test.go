package lmtpproxy

import (
	"io"
	"strings"
	"testing"
)

// A recipient is an envelope address, not a login name: the master-token suffix
// (user@domain@SUFFIX) has no meaning in it (#1938). Read with the suffix rule it was
// routed, and delivered, as the account before the suffix. It is a syntax error, as on
// a sora backend, and the transaction stays open for the next recipient.
func TestRCPTRefusesMasterSuffix(t *testing.T) {
	backend := startNestedMailBackend(t)
	conn, reader, _ := startNestedMailProxySession(t, backend.addr)
	send := func(cmd string) string {
		t.Helper()
		if _, err := io.WriteString(conn, cmd+"\r\n"); err != nil {
			t.Fatalf("writing %q: %v", cmd, err)
		}
		return readReply(t, reader)
	}

	if got := send("LHLO client.example.com"); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("LHLO: %q, want 250", got)
	}
	if got := send("MAIL FROM:<sender@example.org>"); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("MAIL: %q, want 250", got)
	}
	if got := send("RCPT TO:<user@example.com@SUFFIX>"); !strings.HasPrefix(got, "550 5.1.3 ") {
		t.Errorf("RCPT TO:<user@example.com@SUFFIX>: %q, want 550 5.1.3", got)
	}
	if got := send("RCPT TO:<a@example.com>"); !strings.HasPrefix(got, "250 ") {
		t.Fatalf("RCPT: %q, want 250", got)
	}
	for _, cmd := range backend.commands() {
		if strings.Contains(cmd, "SUFFIX") {
			t.Errorf("backend was sent %q", cmd)
		}
	}
}
