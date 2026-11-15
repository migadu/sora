package lmtpproxy

import (
	"io"
	"strings"
	"testing"
)

// RFC 2033 section 4.1: "The HELO and EHLO commands of ESMTP are not present
// in LMTP.  A LMTP server MUST NOT return a Postive Completion reply code to
// these commands.  The 500 reply code is recommended." The proxy refuses them
// as the LMTP backend (go-smtp) does, records no client name for them, and the
// session stays usable for the LHLO the client should have sent.
func TestLMTPProxyRefusesHELOAndEHLO(t *testing.T) {
	for _, command := range []string{
		"HELO client.example.com",
		"EHLO client.example.com",
		"helo client.example.com",
		"ehlo client.example.com",
		"HELO",
		"EHLO",
	} {
		t.Run(command, func(t *testing.T) {
			sess, conn, r := startPlainSession(t)

			io.WriteString(conn, command+"\r\n")
			if line := readReply(t, r); !strings.HasPrefix(line, "500 5.5.1 ") {
				t.Fatalf("%s: %q, want 500 5.5.1", command, line)
			}
			// The session wrote clientHelo, if at all, before the reply just read.
			if sess.clientHelo != "" {
				t.Errorf("%s recorded client name %q, want none", command, sess.clientHelo)
			}

			io.WriteString(conn, "LHLO client.example.com\r\n")
			if line := readReply(t, r); !strings.HasPrefix(line, "250 ") {
				t.Errorf("LHLO after %s: %q, want 250", command, line)
			}
			if sess.clientHelo != "client.example.com" {
				t.Errorf("LHLO after %s recorded client name %q, want client.example.com", command, sess.clientHelo)
			}
		})
	}
}
