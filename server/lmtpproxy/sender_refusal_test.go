package lmtpproxy

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// senderRefusingBackend is a scripted LMTP backend that takes a MAIL only from
// <a@example.org> and answers any other MAIL with refusal. Every other command is
// accepted. It serves any number of connections.
func senderRefusingBackend(t *testing.T, refusal string) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	serve := func(conn net.Conn) {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(conn, "220 backend ready\r\n")
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			verb, _, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
			reply := "250 2.0.0 OK"
			switch strings.ToUpper(verb) {
			case "LHLO":
				reply = "250-backend\r\n250 PIPELINING"
			case "MAIL":
				if !strings.HasPrefix(line, "MAIL FROM:<a@example.org>") {
					reply = refusal
				}
			case "QUIT":
				io.WriteString(conn, "221 bye\r\n")
				return
			}
			io.WriteString(conn, reply+"\r\n")
		}
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(conn)
		}
	}()
	return ln.Addr().String()
}

// The proxy answers MAIL itself and sends it to a backend with a transaction's first
// recipient. A backend that refuses the reverse-path refuses the message: a sora backend
// answers 501 5.5.2 for one go-smtp cannot parse ("<foo>") and 553 5.1.7 for one
// server.NewAddress does not take ("<foo@localhost>"), as it does on a direct
// connection. Each recipient is then refused permanently, 553 5.1.7 ("553 Requested
// action not taken: mailbox name not allowed (e.g., mailbox syntax incorrect)", RFC 5321
// section 4.2.2, a RCPT reply of section 4.3.2; "X.1.7 Bad sender's mailbox address
// syntax", RFC 3463), so the MTA returns the message at once instead of retrying it until
// it expires. Any other refusal of MAIL (a backend asking for authentication, refusing on
// policy) says nothing about the message and stays "451 4.4.1 Backend connection failed".
// A backend held from an earlier transaction answers as a new one does.
func TestBackendRefusalOfSenderIsPermanent(t *testing.T) {
	for _, tt := range []struct {
		name, sender, refusal, want string
	}{
		{"unparseable reverse-path", "foo", "501 5.5.2 Was expecting MAIL arg syntax of FROM:<address>", "553 5.1.7 "},
		{"sender refused", "foo@localhost", "553 5.1.7 Invalid sender", "553 5.1.7 "},
		{"authentication required", "foo@localhost", "530 5.7.0 Authentication required", "451 4.4.1 "},
		{"policy refusal", "foo@localhost", "550 5.7.1 Access denied", "451 4.4.1 "},
	} {
		t.Run(tt.name, func(t *testing.T) {
			send := startSizeForwardingSession(t, senderRefusingBackend(t, tt.refusal))
			for _, step := range []struct{ cmd, want string }{
				// A new backend for each recipient.
				{"MAIL FROM:<" + tt.sender + ">", "250 "},
				{"RCPT TO:<user@example.com>", tt.want},
				{"RCPT TO:<other@example.com>", tt.want},
				{"RSET", "250 "},
				// A sender the backend takes: connected and held.
				{"MAIL FROM:<a@example.org>", "250 "},
				{"RCPT TO:<user@example.com>", "250 "},
				{"RSET", "250 "},
				// The held backend.
				{"MAIL FROM:<" + tt.sender + ">", "250 "},
				{"RCPT TO:<user@example.com>", tt.want},
			} {
				if got := send(step.cmd); !strings.HasPrefix(got, step.want) {
					t.Errorf("%s: %q, want %q", step.cmd, got, step.want)
				}
			}
		})
	}
}
