package lmtpproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// RFC 5321 section 4.1.1.1: "a client MUST issue HELO or EHLO before starting a
// mail transaction", and LHLO is LMTP's EHLO (RFC 2033 section 4.1). The proxy
// refuses MAIL before LHLO with the LMTP backend's (go-smtp) reply, 503 5.5.1
// (section 4.3.2 lists 503 among the MAIL replies), and starts no transaction.
func TestMAILBeforeLHLOIsRefused(t *testing.T) {
	sess, conn, r := startPlainSession(t)

	io.WriteString(conn, "MAIL FROM:<a@example.com>\r\n")
	if line := readReply(t, r); !strings.HasPrefix(line, "503 5.5.1 ") {
		t.Fatalf("MAIL before LHLO: %q, want 503 5.5.1", line)
	}
	// The session wrote its transaction state, if at all, before the reply just read.
	if sess.mailFromReceived || sess.sender != "" {
		t.Errorf("MAIL before LHLO started a transaction: mailFromReceived=%v sender=%q", sess.mailFromReceived, sess.sender)
	}

	io.WriteString(conn, "LHLO client.example.com\r\n")
	if line := readReply(t, r); !strings.HasPrefix(line, "250 ") {
		t.Fatalf("LHLO: %q, want 250", line)
	}
	io.WriteString(conn, "MAIL FROM:<a@example.com>\r\n")
	if line := readReply(t, r); !strings.HasPrefix(line, "250 ") {
		t.Errorf("MAIL after LHLO: %q, want 250", line)
	}
}

// greetingBackend is an LMTP backend that answers XCLIENT with a new greeting, as
// go-smtp does, and logs per connection the HELO= name XCLIENT gave it, the envelope
// commands it received, and the end of the connection.
type greetingBackend struct {
	addr string
	mu   sync.Mutex
	log  []string
}

func startGreetingBackend(t *testing.T) *greetingBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	b := &greetingBackend{addr: ln.Addr().String()}
	go func() {
		for id := 1; ; id++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go b.serve(conn, id)
		}
	}()
	return b
}

func (b *greetingBackend) record(id int, line string) {
	b.mu.Lock()
	b.log = append(b.log, fmt.Sprintf("#%d %s", id, line))
	b.mu.Unlock()
}

// commands returns the log without the connection ends, whose place in it is
// not ordered against the other connection's commands.
func (b *greetingBackend) commands() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, line := range b.log {
		if !strings.HasSuffix(line, " closed") {
			out = append(out, line)
		}
	}
	return out
}

func (b *greetingBackend) waitClosed(t *testing.T, id int) {
	t.Helper()
	want := fmt.Sprintf("#%d closed", id)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		b.mu.Lock()
		for _, line := range b.log {
			if line == want {
				b.mu.Unlock()
				return
			}
		}
		b.mu.Unlock()
	}
	t.Errorf("backend connection #%d is still open", id)
}

func (b *greetingBackend) serve(conn net.Conn, id int) {
	defer b.record(id, "closed")
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(conn, "220 backend ready\r\n")
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb, args, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "LHLO":
			io.WriteString(conn, "250-backend\r\n250 PIPELINING\r\n")
		case "XCLIENT":
			helo := ""
			for _, arg := range strings.Fields(args) {
				if name, ok := strings.CutPrefix(arg, "HELO="); ok {
					helo = name
				}
			}
			b.record(id, "XCLIENT HELO="+helo)
			io.WriteString(conn, "220 backend ready\r\n")
		case "MAIL", "RCPT", "RSET":
			b.record(id, line)
			io.WriteString(conn, "250 2.0.0 Ok\r\n")
		case "QUIT":
			io.WriteString(conn, "221 2.0.0 Bye\r\n")
			return
		default:
			io.WriteString(conn, "250 2.0.0 Ok\r\n")
		}
	}
}

// An accepted LHLO and a completed STARTTLS both start the session over:
//
//   - RFC 5321 section 4.1.4: an EHLO (LMTP's LHLO, RFC 2033 section 4.1) issued
//     after the session begins makes the server "clear all buffers and reset the
//     state exactly as if a RSET command had been issued".
//   - RFC 3207 section 4.2: after the TLS handshake "the SMTP protocol is reset to
//     the initial state", and "the server MUST discard any knowledge obtained from
//     the client, such as the argument to the EHLO command".
//
// So the transaction in progress is gone (RCPT gets 503 until a new MAIL), after
// STARTTLS a MAIL before a new LHLO is refused, and a backend held from before,
// whose XCLIENT carried the earlier LHLO name, is no longer used: the next recipient
// reaches the backend on a new connection that XCLIENT gives the new name.
func TestRegreetingResetsSession(t *testing.T) {
	for _, regreet := range []string{"LHLO", "STARTTLS"} {
		t.Run(regreet, func(t *testing.T) {
			backend := startGreetingBackend(t)
			lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("email")})
			}))
			t.Cleanup(lookup.Close)
			srv, err := New(context.Background(), nil, "test-host", ServerOptions{
				Name: "regreet", RemoteAddrs: []string{backend.addr}, RemotePort: 24, ConnectTimeout: time.Second,
				RemoteUseXCLIENT: true,
				RemoteLookup:     &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "1s"},
				TLS:              true,
				TLSUseStartTLS:   true,
				TLSCertFile:      "../../testdata/sora.crt",
				TLSKeyFile:       "../../testdata/sora.key",
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { srv.Stop() })

			front, accepted := net.Pipe()
			sess := newSession(srv, accepted, nil)
			done := make(chan struct{})
			go func() { defer close(done); sess.handleConnection() }()
			t.Cleanup(func() {
				front.Close()
				<-done
			})
			front.SetDeadline(time.Now().Add(10 * time.Second))
			var conn net.Conn = front
			reader := bufio.NewReader(front)
			if greeting := readReply(t, reader); !strings.HasPrefix(greeting, "220 ") {
				t.Fatalf("greeting = %q", greeting)
			}
			step := func(cmd, want string) {
				t.Helper()
				if _, err := io.WriteString(conn, cmd+"\r\n"); err != nil {
					t.Fatal(err)
				}
				if got := readReply(t, reader); !strings.HasPrefix(got, want) {
					t.Fatalf("%s: %q, want %q", cmd, got, want)
				}
			}

			step("LHLO first.example.com", "250 ")
			step("MAIL FROM:<first@example.com>", "250 ")
			step("RCPT TO:<a@example.com>", "250 ")

			if regreet == "STARTTLS" {
				conn, reader = upgrade(t, front, reader)
				step("MAIL FROM:<early@example.com>", "503 5.5.1 ")
				// The session wrote clientHelo, if at all, before the reply just read.
				if sess.clientHelo != "" {
					t.Errorf("client name after STARTTLS = %q, want none until the next LHLO", sess.clientHelo)
				}
			}
			step("LHLO second.example.com", "250 ")
			step("RCPT TO:<a@example.com>", "503 5.5.1 ")
			step("MAIL FROM:<second@example.com>", "250 ")
			step("RCPT TO:<a@example.com>", "250 ")

			want := []string{
				"#1 XCLIENT HELO=first.example.com",
				"#1 MAIL FROM:<first@example.com>",
				"#1 RCPT TO:<a@example.com>",
				"#2 XCLIENT HELO=second.example.com",
				"#2 MAIL FROM:<second@example.com>",
				"#2 RCPT TO:<a@example.com>",
			}
			if got := backend.commands(); !reflect.DeepEqual(got, want) {
				t.Errorf("backend received\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
			}
			backend.waitClosed(t, 1)
		})
	}
}
