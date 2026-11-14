package lmtp

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// A BDAT LAST in a transaction whose recipients were all refused gets no reply (#819).
// RFC 2033 section 4.3: "If there were no previously successful RCPT commands in the
// mail transaction, then the BDAT LAST command returns zero replies." The backend
// answered it with a 5xx refusal, one reply more than a pipelining LMTP client counts,
// so every later reply was matched to the wrong command. The chunk, command text here,
// must be read and dropped, not parsed as commands.
func TestBDATLastWithoutAcceptedRecipientGetsNoReply(t *testing.T) {
	const noop = "250 2.0.0 I have successfully done nothing"
	for _, chunk := range []string{"", "RSET\r\n"} {
		t.Run(fmt.Sprintf("chunk of %d octets", len(chunk)), func(t *testing.T) {
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
				if !strings.HasPrefix(line, "250") {
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
			io.WriteString(conn, "MAIL FROM:<sender@example.org>\r\n")
			if line := readReplyLine(t, r); !strings.HasPrefix(line, "250 ") {
				t.Fatalf("MAIL: %q", line)
			}
			// Refused by the backend without a database lookup: not a valid address.
			io.WriteString(conn, "RCPT TO:<postmaster>\r\n")
			if line := readReplyLine(t, r); !strings.HasPrefix(line, "513 ") {
				t.Fatalf("RCPT: %q, want 513 (invalid recipient)", line)
			}

			// One write, as a pipelining client sends it.
			fmt.Fprintf(conn, "BDAT %d LAST\r\n%sNOOP\r\n", len(chunk), chunk)
			if line := readReplyLine(t, r); line != noop {
				t.Fatalf("first reply after BDAT LAST with no accepted recipient: %q, want the NOOP reply %q", line, noop)
			}

			// The transaction is over: a new one starts.
			io.WriteString(conn, "MAIL FROM:<sender@example.org>\r\n")
			if line := readReplyLine(t, r); !strings.HasPrefix(line, "250 ") {
				t.Fatalf("MAIL after BDAT LAST: %q, want 250", line)
			}
		})
	}
}
