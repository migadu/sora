package lmtp

import (
	"strings"
	"testing"
)

// A MAIL or RCPT parameter the backend does not recognize, or whose extension it has
// not enabled, is answered with 555 (#1562); go-smtp answered 500 and 504. RFC 5321
// section 4.1.1.11: "If the server SMTP does not recognize or cannot implement one or
// more of the parameters associated with a particular MAIL FROM or RCPT TO command, it
// will return code 555." Section 4.3.2 lists neither 500 nor 504 among the error replies
// to MAIL and RCPT. The backend enables RCPT extensions for XRCPTFORWARD alone, so
// go-smtp refuses every other unrecognized RCPT parameter as well. The refusals come
// before the database, so no account is needed.
func TestUnsupportedMailRcptParametersGet555(t *testing.T) {
	_, addr := startWireBackend(t, "param-555", LMTPServerOptions{})
	c := dialWire(t, addr)
	c.cmd("LHLO client.example.org")

	for _, param := range []string{
		"FOO=1",           // not recognized
		"RET=HDRS",        // DSN (RFC 3461), not enabled
		"ENVID=QQ314159",  // DSN (RFC 3461), not enabled
		"REQUIRETLS",      // RFC 8689, not enabled
		"BODY=BINARYMIME", // RFC 3030, not enabled
		"BY=120;R",        // DELIVERBY (RFC 2852), not enabled
		"MT-PRIORITY=3",   // RFC 6710, not enabled
	} {
		if resp := c.cmd("MAIL FROM:<a@example.org> " + param); !strings.HasPrefix(resp[0], "555 5.5.4 ") {
			t.Errorf("MAIL FROM with %s: %q, want 555 5.5.4", param, resp)
		}
	}

	if resp := c.cmd("MAIL FROM:<a@example.org>"); !strings.HasPrefix(resp[0], "250 ") {
		t.Fatalf("MAIL: %q", resp)
	}
	for _, param := range []string{
		"FOO=1",                      // not recognized
		"X-UNKNOWN",                  // not recognized, no value
		"NOTIFY=NEVER",               // DSN (RFC 3461), not enabled
		"ORCPT=rfc822;b@example.org", // DSN (RFC 3461), not enabled
		"RRVS=2014-04-03T23:01:00Z",  // RFC 7293, not enabled
	} {
		if resp := c.cmd("RCPT TO:<b@example.org> " + param); !strings.HasPrefix(resp[0], "555 5.5.4 ") {
			t.Errorf("RCPT TO with %s: %q, want 555 5.5.4", param, resp)
		}
	}
}
