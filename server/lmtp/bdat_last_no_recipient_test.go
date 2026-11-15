package lmtp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
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
			if line := readReplyLine(t, r); !strings.HasPrefix(line, "5") {
				t.Fatalf("RCPT: %q, want a permanent refusal for the invalid recipient", line)
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

// Even a chunk with no recipients must obey the content read timeout. Its bytes
// cannot be treated as commands if the client never finishes sending the chunk.
func TestBDATWithoutRecipientsStalledDiscardClosesConnection(t *testing.T) {
	for _, last := range []bool{false, true} {
		t.Run(fmt.Sprintf("last=%t", last), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := l.Addr().String()
			l.Close()
			b, err := New(ctx, "discard-timeout-test", "localhost", addr, nil, nil, nil, LMTPServerOptions{
				TrustedNetworks: []string{"127.0.0.0/8"},
				IdleTimeout:     150 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			go b.Start(make(chan error, 1))
			defer b.Close()
			conn := dialUntilListening(t, addr)
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			r := bufio.NewReader(conn)
			if line := readReplyLine(t, r); !strings.HasPrefix(line, "220 ") {
				t.Fatalf("greeting: %q", line)
			}
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
			io.WriteString(conn, "MAIL FROM:<sender@example.org>\r\n")
			if line := readReplyLine(t, r); !strings.HasPrefix(line, "250 ") {
				t.Fatalf("MAIL: %q", line)
			}
			end := ""
			if last {
				end = " LAST"
			}
			fmt.Fprintf(conn, "BDAT 100%s\r\nNOOP\r\n", end)
			if !last {
				if line := readReplyLine(t, r); !strings.HasPrefix(line, "503 ") {
					t.Fatalf("nonfinal BDAT refusal: %q", line)
				}
			}
			if line, err := r.ReadString('\n'); err != io.EOF {
				t.Fatalf("stalled discard: got %q, %v; want a closed connection with no further reply", line, err)
			}
		})
	}
}
