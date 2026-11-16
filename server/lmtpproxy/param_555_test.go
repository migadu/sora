package lmtpproxy

import (
	"strings"
	"testing"
)

// A MAIL or RCPT parameter the proxy does not implement gets 555 5.5.4, as on the backend
// (#1562): RFC 5321 section 4.1.1.11, "If the server SMTP does not recognize or cannot
// implement one or more of the parameters associated with a particular MAIL FROM or RCPT
// TO command, it will return code 555." The proxy answered 250 to MAIL whatever its
// parameters and dropped every RCPT parameter but XRCPTFORWARD. It takes what its LHLO
// reply advertises: SIZE, SMTPUTF8 and BODY=7BIT or BODY=8BITMIME, and XRCPTFORWARD on
// RCPT, which it forwards. A refused MAIL starts no transaction; a refused RCPT is not
// routed and leaves the transaction open.
func TestUnsupportedMailRcptParametersGet555(t *testing.T) {
	addr, lines := scriptedLMTPBackendLines(t, map[string][]lmtpStep{
		"LHLO": {{0, "250-fake\r\n250 PIPELINING"}},
		"MAIL": {{0, "250 2.1.0 OK"}},
		"RCPT": {{0, "250 2.1.5 OK"}},
		"RSET": {{0, "250 2.0.0 OK"}},
	})
	send := startSizeForwardingSession(t, addr)

	for _, param := range []string{
		"FOO=1",                              // not recognized
		"x-unknown",                          // not recognized, no value
		"RET=HDRS",                           // DSN (RFC 3461), not advertised
		"ENVID=QQ314159",                     // DSN (RFC 3461), not advertised
		"REQUIRETLS",                         // RFC 8689, not advertised
		"BODY=BINARYMIME",                    // RFC 3030, not advertised
		"BY=120;R",                           // DELIVERBY (RFC 2852), not advertised
		"MT-PRIORITY=3",                      // RFC 6710, not advertised
		"AUTH=<>",                            // RFC 4954, not advertised
		"SIZE=10 BODY=8BITMIME NOTIFY=NEVER", // a refused one among accepted ones
	} {
		if reply := send("MAIL FROM:<a@example.org> " + param); !strings.HasPrefix(reply, "555 5.5.4 ") {
			t.Errorf("MAIL FROM with %s: %q, want 555 5.5.4", param, reply)
		}
		send("RSET")
	}
	for _, param := range []string{
		"BODY=BINARY", // body-value = "7BIT" / "8BITMIME" (RFC 6152 section 2)
		"BODY=",
		"BODY=7BIT BODY=8BITMIME", // "Only one BODY parameter may be used" (section 3)
		"SMTPUTF8=YES",            // "The parameter does not accept a value" (RFC 6531 section 3.4)
	} {
		if reply := send("MAIL FROM:<a@example.org> " + param); !strings.HasPrefix(reply, "501 5.5.4 ") {
			t.Errorf("MAIL FROM with %s: %q, want 501 5.5.4", param, reply)
		}
		send("RSET")
	}
	for _, param := range []string{
		"SIZE=10",
		"SMTPUTF8",
		"BODY=7BIT",
		"BODY=8BITMIME",
		"body=8bitmime smtputf8 size=10",
	} {
		if reply := send("MAIL FROM:<a@example.org> " + param); !strings.HasPrefix(reply, "250 ") {
			t.Errorf("MAIL FROM with %s: %q, want 250", param, reply)
		}
		send("RSET")
	}
	// A parameter before the path is not one the check can skip.
	if reply := send("MAIL RET=HDRS FROM:<a@example.org>"); !strings.HasPrefix(reply, "501 ") {
		t.Errorf("MAIL with RET=HDRS before FROM: %q, want 501", reply)
	}
	send("RSET")

	// A refused MAIL starts no transaction.
	if reply := send("MAIL FROM:<a@example.org> FOO=1"); !strings.HasPrefix(reply, "555 5.5.4 ") {
		t.Errorf("MAIL FROM with FOO=1: %q, want 555 5.5.4", reply)
	}
	if reply := send("RCPT TO:<user@example.com>"); !strings.HasPrefix(reply, "503 ") {
		t.Errorf("RCPT after a MAIL refused for its parameters: %q, want 503", reply)
	}
	send("RSET")

	if reply := send("MAIL FROM:<a@example.org>"); !strings.HasPrefix(reply, "250 ") {
		t.Fatalf("MAIL: %q", reply)
	}
	for _, param := range []string{
		"FOO=1",                         // not recognized
		"X-UNKNOWN",                     // not recognized, no value
		"NOTIFY=NEVER",                  // DSN (RFC 3461), not advertised
		"NOTIFY=SUCCESS,FAILURE",        // DSN (RFC 3461), not advertised
		"ORCPT=rfc822;user@example.com", // DSN (RFC 3461), not advertised
		"RRVS=2014-04-03T23:01:00Z",     // RFC 7293, not advertised
		"XRCPTFORWARD=eD15 FOO=1",       // a refused one next to XRCPTFORWARD
		"xrcptforward=eD15 notify=never",
	} {
		if reply := send("RCPT TO:<user@example.com> " + param); !strings.HasPrefix(reply, "555 5.5.4 ") {
			t.Errorf("RCPT TO with %s: %q, want 555 5.5.4", param, reply)
		}
	}
	if reply := send("RCPT NOTIFY=NEVER TO:<user@example.com>"); !strings.HasPrefix(reply, "501 ") {
		t.Errorf("RCPT with NOTIFY=NEVER before TO: %q, want 501", reply)
	}
	// The transaction is still open: the recipients the proxy takes are routed.
	if reply := send("RCPT TO:<user@example.com> XRCPTFORWARD=eD15"); !strings.HasPrefix(reply, "250 ") {
		t.Errorf("RCPT TO with XRCPTFORWARD after refused parameters: %q, want 250", reply)
	}
	if reply := send("RCPT TO:<other@example.com>"); !strings.HasPrefix(reply, "250 ") {
		t.Errorf("RCPT TO without parameters after refused parameters: %q, want 250", reply)
	}
	if reply := send("QUIT"); !strings.HasPrefix(reply, "221 ") {
		t.Errorf("QUIT: %q, want 221", reply)
	}

	var mail, rcpt []string
	for _, line := range lines() {
		switch verb, _, _ := strings.Cut(line, " "); verb {
		case "MAIL":
			mail = append(mail, line)
		case "RCPT":
			rcpt = append(rcpt, line)
		}
	}
	if want := []string{"MAIL FROM:<a@example.org>"}; strings.Join(mail, "\n") != strings.Join(want, "\n") {
		t.Errorf("backend MAIL commands = %q, want %q", mail, want)
	}
	if want := []string{"RCPT TO:<user@example.com> XRCPTFORWARD=eD15", "RCPT TO:<other@example.com>"}; strings.Join(rcpt, "\n") != strings.Join(want, "\n") {
		t.Errorf("backend RCPT commands = %q, want %q (refused recipients are not routed)", rcpt, want)
	}
}
