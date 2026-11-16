package lmtpproxy

import (
	"strings"
	"testing"
)

// A MAIL or RCPT parameter given twice gets 501 5.5.4 whatever its keyword, before any
// parameter is looked at, as on the backend (#1721): the server cannot tell which value the
// client meant. RFC 6152 section 3: "Only one BODY parameter may be used in a single MAIL
// command." The proxy refused a second BODY, SIZE, SMTPUTF8 or XRCPTFORWARD with 501, but a
// repeated parameter it does not take, or one repeated after a parameter it does not take,
// got the 555 of that parameter, where the backend answers 501. A refused MAIL starts no
// transaction; a refused RCPT is not routed and leaves the transaction open.
func TestRepeatedMailRcptParametersGet501(t *testing.T) {
	addr, lines := scriptedLMTPBackendLines(t, map[string][]lmtpStep{
		"LHLO": {{0, "250-fake\r\n250 PIPELINING"}},
		"MAIL": {{0, "250 2.1.0 OK"}},
		"RCPT": {{0, "250 2.1.5 OK"}},
		"RSET": {{0, "250 2.0.0 OK"}},
	})
	send := startSizeForwardingSession(t, addr)

	for _, params := range []string{
		"BODY=7BIT BODY=8BITMIME",
		"SIZE=10 SIZE=20",
		"SMTPUTF8 smtputf8",
		"BODY=7BIT BODY=BINARYMIME",
		"SIZE=10 FOO=1 size=20",
		"FOO=1 FOO=2",
		"x-unknown X-UNKNOWN",
	} {
		if reply := send("MAIL FROM:<a@example.org> " + params); !strings.HasPrefix(reply, "501 5.5.4 ") {
			t.Errorf("MAIL FROM with %s: %q, want 501 5.5.4", params, reply)
		}
		if reply := send("RCPT TO:<user@example.com>"); !strings.HasPrefix(reply, "503 ") {
			t.Errorf("RCPT after MAIL FROM with %s: %q, want 503", params, reply)
		}
		send("RSET")
	}

	if reply := send("MAIL FROM:<a@example.org> BODY=8BITMIME SIZE=10 SMTPUTF8"); !strings.HasPrefix(reply, "250 ") {
		t.Fatalf("MAIL with each parameter once: %q", reply)
	}
	for _, params := range []string{
		"XRCPTFORWARD=eD15 xrcptforward=eD16",
		"FOO=1 FOO=2",
		"NOTIFY=NEVER notify=never",
	} {
		if reply := send("RCPT TO:<user@example.com> " + params); !strings.HasPrefix(reply, "501 5.5.4 ") {
			t.Errorf("RCPT TO with %s: %q, want 501 5.5.4", params, reply)
		}
	}
	if reply := send("RCPT TO:<user@example.com> XRCPTFORWARD=eD15"); !strings.HasPrefix(reply, "250 ") {
		t.Errorf("RCPT TO with XRCPTFORWARD once after refused parameters: %q, want 250", reply)
	}
	send("QUIT")

	var rcpt []string
	for _, line := range lines() {
		if strings.HasPrefix(line, "RCPT ") {
			rcpt = append(rcpt, line)
		}
	}
	if want := "RCPT TO:<user@example.com> XRCPTFORWARD=eD15"; strings.Join(rcpt, "\n") != want {
		t.Errorf("backend RCPT commands = %q, want only %q", rcpt, want)
	}
}
