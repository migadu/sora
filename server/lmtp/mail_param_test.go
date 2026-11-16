package lmtp

import (
	"strings"
	"testing"
)

// The backend's LHLO reply does not announce AUTH (LMTP has no authentication here) and
// announces SMTPUTF8, whose MAIL parameter takes no value. AUTH= on MAIL belongs to an
// extension that was not negotiated: RFC 5321 section 4.1.1.2, "If service extensions
// were negotiated, the MAIL command may also carry parameters associated with a
// particular service extension", and section 4.1.1.11, "If the server SMTP does not
// recognize or cannot implement one or more of the parameters associated with a
// particular MAIL FROM or RCPT TO command, it will return code 555." A valued SMTPUTF8
// is a syntax error: RFC 6531 section 3.4, "If this parameter is provided, it MUST not
// accept a value." So is "=" with nothing after it, for any parameter: RFC 5321 section
// 4.1.2, "esmtp-value = 1*(%d33-60 / %d62-126)". The LMTP proxy refuses all of them with
// the same replies (#1697, #1709).
//
// A backend without TLS runs with insecure auth allowed (cmd/sora: InsecureAuth ||
// !TLS), as does one with STARTTLS, so AUTH is allowed on its plaintext connections and
// only the missing mechanism keeps it from being offered: both settings are checked.
func TestMAILRefusesAUTHAndValuedSMTPUTF8(t *testing.T) {
	for _, insecureAuth := range []bool{false, true} {
		name := "secure auth"
		if insecureAuth {
			name = "insecure auth"
		}
		t.Run(name, func(t *testing.T) {
			_, addr := startWireBackend(t, "mail-params", LMTPServerOptions{InsecureAuth: insecureAuth})
			c := dialWire(t, addr)
			lhlo := c.cmd("LHLO client.example.org")
			for _, line := range lhlo {
				if keyword := strings.ToUpper(line[4:]); keyword == "AUTH" || strings.HasPrefix(keyword, "AUTH ") || strings.HasPrefix(keyword, "AUTH=") {
					t.Fatalf("LHLO announces %q", line)
				}
			}

			mail := func(params string) string {
				t.Helper()
				resp := c.cmd("MAIL FROM:<a@example.org> " + params)
				if strings.HasPrefix(resp[0], "250 ") {
					c.cmd("RSET")
				}
				return resp[0]
			}
			for _, tt := range []struct{ params, want string }{
				{"AUTH=<>", "555 5.5.4 "},
				{"AUTH=a@example.org", "555 5.5.4 "},
				{"auth=<>", "555 5.5.4 "},
				{"SMTPUTF8=YES", "501 5.5.4 "},
				{"SMTPUTF8=", "501 5.5.4 "},
				{"SIZE=10 smtputf8=yes", "501 5.5.4 "},
				{"FOO=", "501 5.5.4 "},
				{"FOO=1 BAR=", "501 5.5.4 "},
				{"SMTPUTF8", "250 "},
				{"SIZE=10 SMTPUTF8", "250 "},
			} {
				if resp := mail(tt.params); !strings.HasPrefix(resp, tt.want) {
					t.Errorf("MAIL FROM with %s: %q, want %q", tt.params, resp, tt.want)
				}
			}

			// RCPT parameters are parsed before the recipient is looked up, so no
			// database is needed.
			if resp := c.cmd("MAIL FROM:<a@example.org>"); !strings.HasPrefix(resp[0], "250 ") {
				t.Fatalf("MAIL: %q", resp)
			}
			for _, params := range []string{"XRCPTFORWARD=", "FOO=", "FOO=1 BAR="} {
				if resp := c.cmd("RCPT TO:<b@example.org> " + params); !strings.HasPrefix(resp[0], "501 5.5.4 ") {
					t.Errorf("RCPT TO with %s: %q, want 501 5.5.4", params, resp)
				}
			}
		})
	}
}
