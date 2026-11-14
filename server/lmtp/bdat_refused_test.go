package lmtp

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// go-smtp advertises CHUNKING on every LMTP backend. A client sends a BDAT chunk right
// behind the command line without waiting for the reply, so a BDAT refused for a missing
// MAIL or RCPT must still read and drop its chunk, or the chunk is read as LMTP commands
// (#614). RFC 3030 section 2: "If a failure occurs after a BDAT command is received, the
// receiver-SMTP MUST accept and discard the associated message data before sending the
// appropriate 5XX or 4XX code."
func TestRefusedBDATChunkIsNotReadAsCommands(t *testing.T) {
	// Command text on purpose: read as a command, it is answered 252, where the NOOP
	// reply is expected.
	const chunk = "VRFY <other@example.com>\r\n"
	const noopReply = "250 2.0.0 I have successfully done nothing"

	for _, tc := range []struct {
		name   string
		before []string
	}{
		{"no MAIL", nil},
		{"no RCPT", []string{"MAIL FROM:<sender@example.org>"}},
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
			io.WriteString(conn, "LHLO client.example.org\r\n")
			chunking := false
			for {
				line := readReplyLine(t, r)
				if !strings.HasPrefix(line, "250-") && !strings.HasPrefix(line, "250 ") {
					t.Fatalf("LHLO: %q", line)
				}
				chunking = chunking || line[4:] == "CHUNKING"
				if line[3] == ' ' {
					break
				}
			}
			if !chunking {
				t.Fatal("LHLO does not advertise CHUNKING")
			}
			for _, cmd := range tc.before {
				io.WriteString(conn, cmd+"\r\n")
				if line := readReplyLine(t, r); !strings.HasPrefix(line, "250 ") {
					t.Fatalf("%s: %q", cmd, line)
				}
			}

			fmt.Fprintf(conn, "BDAT %d LAST\r\n%sNOOP\r\n", len(chunk), chunk)
			if line := readReplyLine(t, r); !strings.HasPrefix(line, "502 ") {
				t.Fatalf("BDAT without a recipient: %q, want 502", line)
			}
			if line := readReplyLine(t, r); line != noopReply {
				t.Fatalf("next reply after the refused BDAT: %q, want the NOOP reply %q; the chunk was read as commands", line, noopReply)
			}
		})
	}
}
