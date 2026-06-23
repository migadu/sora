package helpers

import "testing"

// TestMaskSensitive covers the command forms the IMAP/POP3 proxies now pass through
// MaskSensitive so a cleartext password never reaches the debug log (audit H4).
func TestMaskSensitive(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		command   string
		sensitive []string
		want      string
	}{
		// IMAP (tagged): redact everything after the username / mechanism.
		{"imap login", "a1 LOGIN alice s3cr3t", "LOGIN", []string{"LOGIN", "AUTHENTICATE"}, "a1 LOGIN alice [REDACTED]"},
		{"imap login quoted pass", `a1 LOGIN alice "p a s s"`, "LOGIN", []string{"LOGIN", "AUTHENTICATE"}, "a1 LOGIN alice [REDACTED]"},
		{"imap authenticate", "a2 AUTHENTICATE PLAIN dXNlcgB1c2VyAHBhc3M=", "AUTHENTICATE", []string{"LOGIN", "AUTHENTICATE"}, "a2 AUTHENTICATE PLAIN [REDACTED]"},
		{"imap authenticate no inline data", "a2 AUTHENTICATE PLAIN", "AUTHENTICATE", []string{"LOGIN", "AUTHENTICATE"}, "a2 AUTHENTICATE PLAIN"},
		{"imap non-sensitive", "a3 SELECT INBOX", "SELECT", []string{"LOGIN", "AUTHENTICATE"}, "a3 SELECT INBOX"},

		// POP3 (untagged): redact after PASS; USER (the username) is not secret.
		{"pop3 pass", "PASS s3cr3t", "PASS", []string{"PASS", "AUTH"}, "PASS [REDACTED]"},
		{"pop3 auth", "AUTH PLAIN dXNlcgB1c2VyAHBhc3M=", "AUTH", []string{"PASS", "AUTH"}, "AUTH PLAIN [REDACTED]"},
		{"pop3 user not masked", "USER alice", "USER", []string{"PASS", "AUTH"}, "USER alice"},
		{"pop3 capa", "CAPA", "CAPA", []string{"PASS", "AUTH"}, "CAPA"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := MaskSensitive(c.line, c.command, c.sensitive...); got != c.want {
				t.Errorf("MaskSensitive(%q, %q) = %q, want %q", c.line, c.command, got, c.want)
			}
		})
	}
}
