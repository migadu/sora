package lmtp

import (
	"bufio"
	"io"
	"strings"
	"testing"
	"time"
)

// MAIL before LHLO, RCPT without MAIL, and DATA or non-final BDAT without an accepted
// recipient, are a bad sequence of commands (503), not an unimplemented command (502),
// which the backend answered (#748). RFC 5321 section 3.3: "If a RCPT command appears
// without a previous MAIL command, the server MUST return a 503 "Bad sequence of
// commands" response." RFC 2033 section 4.2: "when there have been no successful RCPT
// commands in the mail transaction, the DATA command MUST fail with a 503 reply code."
// RFC 5321 section 4.1.1.1: "a client MUST issue HELO or EHLO before starting a mail
// transaction"; section 4.3.2 lists 503, not 502, among the error replies to MAIL.
// RFC 5321 section 4.2.4: "502 SHOULD be used when the command is actually recognized
// by the SMTP server, but not implemented."
func TestOutOfSequenceCommandsGet503(t *testing.T) {
	const mail = "MAIL FROM:<sender@example.org>"
	for _, tc := range []struct {
		name   string
		lhlo   bool     // greet with LHLO first
		before []string // each answered 250
		cmd    string
	}{
		{"MAIL before LHLO", false, nil, mail},
		{"RCPT without MAIL", true, nil, "RCPT TO:<user@example.com>"},
		{"DATA without MAIL", true, nil, "DATA"},
		{"DATA without RCPT", true, []string{mail}, "DATA"},
		{"BDAT without MAIL", true, nil, "BDAT 0"},
		{"BDAT without RCPT", true, []string{mail}, "BDAT 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, addr := startAdmissionTestBackend(t, []string{"127.0.0.0/8"}, false)
			conn := dialUntilListening(t, addr)
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			r := bufio.NewReader(conn)

			if line := readReplyLine(t, r); !strings.HasPrefix(line, "220 ") {
				t.Fatalf("greeting: %q", line)
			}
			if tc.lhlo {
				io.WriteString(conn, "LHLO client.example.org\r\n")
				for {
					line := readReplyLine(t, r)
					if !strings.HasPrefix(line, "250") {
						t.Fatalf("LHLO: %q", line)
					}
					if line[3] == ' ' {
						break
					}
				}
			}
			for _, cmd := range tc.before {
				io.WriteString(conn, cmd+"\r\n")
				if line := readReplyLine(t, r); !strings.HasPrefix(line, "250 ") {
					t.Fatalf("%s: %q", cmd, line)
				}
			}

			io.WriteString(conn, tc.cmd+"\r\n")
			if line := readReplyLine(t, r); !strings.HasPrefix(line, "503 5.5.1 ") {
				t.Fatalf("%s: %q, want 503 5.5.1 (bad sequence of commands)", tc.cmd, line)
			}
		})
	}
}
