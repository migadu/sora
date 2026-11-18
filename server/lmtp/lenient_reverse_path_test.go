package lmtp

import (
	"strings"
	"testing"
)

// go-smtp reads a dot-string local part leniently on purpose (leading, trailing and
// consecutive dots are accepted, as Postfix does with strict_rfc821_envelopes = no), and
// takes any domain and a quoted local part. A sender such an MTA hands over must not be
// refused by Sora's own check of the reverse-path: older mobile carriers still send
// "first..last@" senders, and refusing them at MAIL FROM bounces their mail (#1907).
// The forward-path stays strict: such a recipient is no account here.
func TestMAILAcceptsLenientReversePath(t *testing.T) {
	_, addr := startWireBackend(t, "lenient-reverse-path", LMTPServerOptions{})
	c := dialWire(t, addr)
	if resp := c.cmd("LHLO client.example.org"); !strings.HasPrefix(resp[len(resp)-1], "250 ") {
		t.Fatalf("LHLO: %q", resp)
	}

	for _, from := range []string{
		"first..last@example.com",
		".lead@example.com",
		"trail.@example.com",
		"user@localhost",
		`"quoted local"@example.com`,
		`"quoted\"escaped"@example.com`,
		"user@[192.0.2.1]",
		"user@[IPv6:2001:db8::1]",
	} {
		if resp := c.cmd("MAIL FROM:<" + from + ">"); !strings.HasPrefix(resp[0], "250 ") {
			t.Errorf("MAIL FROM:<%s>: %q, want 250", from, resp[0])
			continue
		}
		// RCPT checks the recipient's syntax before any lookup, so no database is needed.
		if resp := c.cmd("RCPT TO:<" + from + ">"); !strings.HasPrefix(resp[0], "553 5.1.3 ") {
			t.Errorf("RCPT TO:<%s>: %q, want 553 5.1.3", from, resp[0])
		}
		c.cmd("RSET")
	}

	// What is not an address at all stays refused, as before.
	for _, from := range []string{
		"user@",
		"user@exa mple.com",
		"user@example..com",
		"user@-",
		"user@exa\"mple.com",
		"user@[192.0.2.1",
	} {
		if resp := c.cmd("MAIL FROM:<" + from + ">"); strings.HasPrefix(resp[0], "250 ") {
			t.Errorf("MAIL FROM:<%s>: %q, want a refusal", from, resp[0])
			c.cmd("RSET")
		}
	}

	// The null reverse-path is unchanged.
	if resp := c.cmd("MAIL FROM:<>"); !strings.HasPrefix(resp[0], "250 ") {
		t.Errorf("MAIL FROM:<>: %q, want 250", resp[0])
	}
}
