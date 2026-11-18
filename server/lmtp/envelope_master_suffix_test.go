package lmtp

import (
	"strings"
	"testing"
)

// A recipient is an envelope address, not a login name: the master-token suffix
// (user@domain@SUFFIX) has no meaning in it (#1938). go-smtp hands the quoted local part
// of `"a@b.example"@example.com` over unquoted, and read with the suffix rule it was
// looked up, and delivered, as the account a@b.example. Recipients are dot-strings, so
// both forms are a syntax error, answered before any lookup (no database is needed).
func TestRCPTRefusesMasterSuffix(t *testing.T) {
	_, addr := startWireBackend(t, "rcpt-master-suffix", LMTPServerOptions{})
	c := dialWire(t, addr)
	if resp := c.cmd("LHLO client.example.org"); !strings.HasPrefix(resp[len(resp)-1], "250 ") {
		t.Fatalf("LHLO: %q", resp)
	}
	for _, to := range []string{
		`"a@b.example"@example.com`,
		"user@example.com@SUFFIX",
	} {
		if resp := c.cmd("MAIL FROM:<sender@example.org>"); !strings.HasPrefix(resp[0], "250 ") {
			t.Fatalf("MAIL FROM: %q", resp)
		}
		if resp := c.cmd("RCPT TO:<" + to + ">"); !strings.HasPrefix(resp[0], "553 5.1.3 ") {
			t.Errorf("RCPT TO:<%s>: %q, want 553 5.1.3", to, resp[0])
			// A recipient that reached the lookup panics on the test's empty database
			// and closes the connection.
			c = dialWire(t, addr)
			c.cmd("LHLO client.example.org")
			continue
		}
		c.cmd("RSET")
	}
}
