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
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// The proxy must not announce DSN (RFC 3461): neither it nor the LMTP backend
// issues a "delivered" DSN (§5.2.3), and the parameters are not forwarded. An
// MTA that sees no DSN keeps the duties of §5.2.2 for itself (a "relayed" DSN
// for NOTIFY=SUCCESS). Parameters an MTA sends anyway are refused with 555 5.5.4,
// as the backend, which does not announce DSN either, refuses them: RFC 5321
// section 4.1.1.11, "If the server SMTP does not recognize or cannot implement one
// or more of the parameters associated with a particular MAIL FROM or RCPT TO
// command, it will return code 555." None reaches the backend.
func TestLMTPProxyDoesNotAnnounceDSN(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	backendCommands := make(chan string, 16)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(conn, "220 backend ready\r\n")
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			backendCommands <- strings.TrimRight(line, "\r\n")
			io.WriteString(conn, "250 OK\r\n")
		}
	}()
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("email")})
	}))
	t.Cleanup(lookup.Close)
	srv, err := New(context.Background(), nil, "test-host", ServerOptions{
		Name: "dsn", RemoteAddrs: []string{ln.Addr().String()}, RemotePort: 24, ConnectTimeout: time.Second,
		RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "1s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })

	front, accepted := net.Pipe()
	t.Cleanup(func() { front.Close() })
	sess := newSession(srv, accepted, nil)
	done := make(chan struct{})
	go func() { defer close(done); sess.handleConnection() }()
	front.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(front)
	if greeting := readReply(t, reader); !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("greeting = %q", greeting)
	}
	send := func(line string) {
		t.Helper()
		if _, err := fmt.Fprintf(front, "%s\r\n", line); err != nil {
			t.Fatal(err)
		}
	}

	send("LHLO client.example.org")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading the LHLO reply: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 4 || !strings.HasPrefix(line, "250") {
			t.Fatalf("LHLO reply line %q", line)
		}
		if fields := strings.Fields(line[4:]); len(fields) > 0 && strings.EqualFold(fields[0], "DSN") {
			t.Errorf("LHLO announces DSN (%q), but no DSN is issued and the parameters are dropped", line)
		}
		if line[3] != '-' {
			break
		}
	}

	send("MAIL FROM:<sender@example.org> RET=HDRS ENVID=abc123")
	if reply := readReply(t, reader); !strings.HasPrefix(reply, "555 5.5.4 ") {
		t.Errorf("MAIL with RET and ENVID = %q, want 555 5.5.4", reply)
		send("RSET")
		readReply(t, reader)
	}
	send("MAIL FROM:<sender@example.org>")
	if reply := readReply(t, reader); !strings.HasPrefix(reply, "250 ") {
		t.Fatalf("MAIL = %q, want 250", reply)
	}
	send("RCPT TO:<user@example.com> NOTIFY=SUCCESS ORCPT=rfc822;user@example.com")
	if reply := readReply(t, reader); !strings.HasPrefix(reply, "555 5.5.4 ") {
		t.Errorf("RCPT with NOTIFY and ORCPT = %q, want 555 5.5.4", reply)
	}
	send("RCPT TO:<user@example.com>")
	if reply := readReply(t, reader); !strings.HasPrefix(reply, "250 ") {
		t.Fatalf("RCPT = %q, want 250", reply)
	}

	// The backend has answered the last RCPT, so it has received every command by now.
	var mail, rcpt []string
	for len(backendCommands) > 0 {
		switch cmd := <-backendCommands; strings.ToUpper(cmd[:min(len(cmd), 4)]) {
		case "MAIL":
			mail = append(mail, cmd)
		case "RCPT":
			rcpt = append(rcpt, cmd)
		}
	}
	if want := "MAIL FROM:<sender@example.org>"; len(mail) != 1 || mail[0] != want {
		t.Errorf("backend received %q, want [%q] (RET and ENVID are not forwarded)", mail, want)
	}
	if want := "RCPT TO:<user@example.com>"; len(rcpt) != 1 || rcpt[0] != want {
		t.Errorf("backend received %q, want [%q] (NOTIFY and ORCPT are not forwarded)", rcpt, want)
	}

	send("QUIT")
	if reply := readReply(t, reader); !strings.HasPrefix(reply, "221 ") {
		t.Errorf("QUIT = %q, want 221", reply)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("session did not finish after QUIT")
	}
}
