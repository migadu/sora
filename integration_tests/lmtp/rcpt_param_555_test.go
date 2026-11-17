//go:build integration

package lmtp_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// RFC 5321 section 4.1.1.11: "If the server SMTP does not recognize or cannot implement
// one or more of the parameters associated with a particular MAIL FROM or RCPT TO
// command, it will return code 555." The backend enables go-smtp's RCPT extensions for
// XRCPTFORWARD alone, so go-smtp refuses every other RCPT parameter with 555, for an
// existing recipient too, while XRCPTFORWARD keeps working (#1562).
func TestLMTP_UnknownRcptParameterGets555(t *testing.T) {
	server, account := common.SetupLMTPServer(t)
	defer server.Close()

	c, _ := lhloSession(t, server.Address)
	if err := c.SendCommand("MAIL FROM:<sender@example.org>"); err != nil {
		t.Fatal(err)
	}
	if resp, err := c.ReadResponse(); err != nil || !strings.HasPrefix(resp, "250 ") {
		t.Fatalf("MAIL: %q, %v", resp, err)
	}

	xrcptforward := "XRCPTFORWARD=" + base64.StdEncoding.EncodeToString([]byte("proxy=127.0.0.1"))
	rcpt := func(params string) string {
		t.Helper()
		if err := c.SendCommand("RCPT TO:<" + account.Email + "> " + params); err != nil {
			t.Fatal(err)
		}
		resp, err := c.ReadResponse()
		if err != nil {
			t.Fatalf("RCPT with %s: %v", params, err)
		}
		return resp
	}
	for _, params := range []string{
		"FOO=1",
		"x-unknown",             // keywords are case-insensitive (RFC 5321 section 2.4)
		xrcptforward + " FOO=1", // one unknown parameter refuses the command
	} {
		if resp := rcpt(params); !strings.HasPrefix(resp, "555 5.5.4 ") {
			t.Errorf("RCPT TO with %s: %q, want 555 5.5.4", params, resp)
		}
	}

	// The refusals left the transaction open; XRCPTFORWARD is still taken.
	if resp := rcpt(xrcptforward); !strings.HasPrefix(resp, "250 ") {
		t.Fatalf("RCPT TO with %s: %q, want 250", xrcptforward, resp)
	}
}
