package lmtp

import (
	"strings"
	"testing"
)

// A MAIL or RCPT parameter given twice is a syntax error, 501 5.5.4, whatever its keyword,
// before any parameter is looked at: the server cannot tell which value the client meant.
// RFC 6152 section 3: "Only one BODY parameter may be used in a single MAIL command." RFC
// 1870 section 6: "Only one SIZE parameter may be specified in a single MAIL command." The
// backend took the last value and answered 250 (#1721); the LMTP proxy refuses the same
// commands with the same reply.
func TestMAILAndRCPTRefuseRepeatedParameters(t *testing.T) {
	_, addr := startWireBackend(t, "repeated-params", LMTPServerOptions{})
	c := dialWire(t, addr)
	c.cmd("LHLO client.example.org")

	for _, params := range []string{
		"BODY=7BIT BODY=8BITMIME",
		"SIZE=10 SIZE=20",
		"SIZE=10 size=10",
		"SMTPUTF8 smtputf8",
		"BODY=7BIT BODY=BINARYMIME",
		"FOO=1 FOO=2",
	} {
		resp := c.cmd("MAIL FROM:<a@example.org> " + params)
		if !strings.HasPrefix(resp[0], "501 5.5.4 ") {
			t.Errorf("MAIL FROM with %s: %q, want 501 5.5.4", params, resp)
		}
		if strings.HasPrefix(resp[0], "250 ") {
			c.cmd("RSET")
		}
	}

	// Each parameter once is taken.
	if resp := c.cmd("MAIL FROM:<a@example.org> BODY=8BITMIME SIZE=10 SMTPUTF8"); !strings.HasPrefix(resp[0], "250 ") {
		t.Fatalf("MAIL with each parameter once: %q", resp)
	}
	// RCPT parameters are parsed before the recipient is looked up, so no database is
	// needed for the refusals.
	for _, params := range []string{
		"FOO=1 FOO=2",
		"XRCPTFORWARD=dXNlcj1qb2hu xrcptforward=dXNlcj1qYW5l",
	} {
		if resp := c.cmd("RCPT TO:<b@example.org> " + params); !strings.HasPrefix(resp[0], "501 5.5.4 ") {
			t.Errorf("RCPT TO with %s: %q, want 501 5.5.4", params, resp)
		}
	}
}
