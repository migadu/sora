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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// nestedMailBackend is an in-process scripted LMTP backend that tracks the open
// mail transaction (from and rcpts) the way go-smtp does:
//   - MAIL while a transaction is already open is refused with
//     "503 5.5.1 Sender already specified" without disturbing from or rcpts;
//   - RCPT requires an open MAIL and appends to rcpts;
//   - DATA requires at least one accepted recipient, replies 354, reads until
//     ".\r\n", emits one "250 2.0.0 Delivered from <from> to <rcpt>" line per
//     accepted recipient, and clears the transaction;
//   - LHLO and RSET clear the transaction.
type nestedMailBackend struct {
	addr  string
	conns atomic.Int32
	mu    sync.Mutex
	cmds  []string
}

func startNestedMailBackend(t *testing.T) *nestedMailBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	b := &nestedMailBackend{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			id := b.conns.Add(1)
			go b.serve(conn, id)
		}
	}()
	return b
}

func (b *nestedMailBackend) record(id int32, line string) {
	b.mu.Lock()
	b.cmds = append(b.cmds, fmt.Sprintf("#%d %s", id, line))
	b.mu.Unlock()
}

func (b *nestedMailBackend) commands() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.cmds))
	copy(out, b.cmds)
	return out
}

func extractAngleAddr(s string) string {
	start := strings.IndexByte(s, '<')
	end := strings.IndexByte(s, '>')
	if start >= 0 && end > start {
		return s[start+1 : end]
	}
	return ""
}

func (b *nestedMailBackend) serve(conn net.Conn, id int32) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "220 backend ready\r\n")

	reader := bufio.NewReader(conn)
	var (
		hasMail bool
		from    string
		rcpts   []string
	)
	resetTx := func() {
		hasMail = false
		from = ""
		rcpts = nil
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb, _, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "LHLO":
			resetTx()
			_, _ = io.WriteString(conn, "250-backend\r\n250 PIPELINING\r\n")
		case "MAIL":
			b.record(id, line)
			if hasMail {
				_, _ = io.WriteString(conn, "503 5.5.1 Sender already specified\r\n")
				continue
			}
			hasMail = true
			from = extractAngleAddr(line)
			rcpts = nil
			_, _ = io.WriteString(conn, "250 2.1.0 Ok\r\n")
		case "RCPT":
			b.record(id, line)
			if !hasMail {
				_, _ = io.WriteString(conn, "503 5.5.1 Error: need MAIL command\r\n")
				continue
			}
			rcpts = append(rcpts, extractAngleAddr(line))
			_, _ = io.WriteString(conn, "250 2.1.5 Ok\r\n")
		case "DATA":
			b.record(id, line)
			if len(rcpts) == 0 {
				_, _ = io.WriteString(conn, "503 5.5.1 Error: need RCPT command\r\n")
				continue
			}
			_, _ = io.WriteString(conn, "354 End data with <CR><LF>.<CR><LF>\r\n")
			for {
				bodyLine, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if bodyLine == ".\r\n" {
					break
				}
			}
			for _, rcpt := range rcpts {
				_, _ = fmt.Fprintf(conn, "250 2.0.0 Delivered from <%s> to <%s>\r\n", from, rcpt)
			}
			resetTx()
		case "RSET":
			b.record(id, line)
			resetTx()
			_, _ = io.WriteString(conn, "250 2.0.0 Reset state\r\n")
		case "QUIT":
			_, _ = io.WriteString(conn, "221 2.0.0 Bye\r\n")
			return
		default:
			_, _ = io.WriteString(conn, "500 5.5.2 Unrecognized command\r\n")
		}
	}
}

func startNestedMailProxySession(t *testing.T, backendAddr string) (net.Conn, *bufio.Reader, <-chan struct{}) {
	t.Helper()
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"address": r.URL.Query().Get("email"),
			"server":  backendAddr,
		})
	}))
	t.Cleanup(lookup.Close)

	srv, err := New(context.Background(), nil, "test-host", ServerOptions{
		Name:           "nested-mail",
		RemoteAddrs:    []string{backendAddr},
		RemotePort:     24,
		ConnectTimeout: time.Second,
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled: true,
			URL:     lookup.URL + "?email=$email",
			Timeout: "1s",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })

	front, accepted := net.Pipe()
	sess := newSession(srv, accepted, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.handleConnection()
	}()
	t.Cleanup(func() {
		_ = front.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("session did not finish")
		}
	})

	_ = front.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(front)
	if greeting := readReply(t, reader); !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("greeting = %q, want 220", greeting)
	}
	return front, reader, done
}

// RFC 5321 section 4.1.1.2 / section 5.4: MAIL begins a mail transaction and may
// only be sent when no mail transaction is already in progress. A nested MAIL
// (without RSET, LHLO, STARTTLS, or completing DATA) must be refused with
// "503 5.5.1 Sender already specified" and leave the open transaction — its
// sender, accepted recipient count, and any held backend transaction — intact.
func TestNestedMAILRefusedPreservingOpenTransaction(t *testing.T) {
	t.Run("before_first_rcpt", func(t *testing.T) {
		backend := startNestedMailBackend(t)
		conn, reader, _ := startNestedMailProxySession(t, backend.addr)

		send := func(cmd string) string {
			t.Helper()
			if _, err := io.WriteString(conn, cmd+"\r\n"); err != nil {
				t.Fatalf("writing %q: %v", cmd, err)
			}
			return readReply(t, reader)
		}

		if got := send("LHLO client.example.com"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("LHLO: %q, want 250", got)
		}
		if got := send("MAIL FROM:<first@example.com>"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("first MAIL: %q, want 250", got)
		}

		// Nested MAIL before any backend connection exists must be refused with
		// 503 5.5.1 and must NOT overwrite the first MAIL's sender.
		if got := send("MAIL FROM:<second@example.com>"); !strings.HasPrefix(got, "503 5.5.1 ") {
			t.Errorf("nested MAIL before RCPT: %q, want 503 5.5.1", got)
		}
		// Even a syntactically incomplete nested MAIL is out of sequence first
		// (matching go-smtp's check order before FROM: parsing).
		if got := send("MAIL"); !strings.HasPrefix(got, "503 5.5.1 ") {
			t.Errorf("nested bare MAIL before RCPT: %q, want 503 5.5.1", got)
		}

		if got := send("RCPT TO:<a@example.com>"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("RCPT after refused nested MAIL: %q, want 250", got)
		}
		if got := send("DATA"); !strings.HasPrefix(got, "354 ") {
			t.Fatalf("DATA: %q, want 354", got)
		}
		if _, err := io.WriteString(conn, "Subject: nested-before-rcpt\r\n\r\nhello\r\n.\r\n"); err != nil {
			t.Fatalf("writing DATA body: %v", err)
		}
		wantDelivered := "250 2.0.0 Delivered from <first@example.com> to <a@example.com>"
		if got := readReply(t, reader); got != wantDelivered {
			t.Fatalf("DATA reply: %q, want %q", got, wantDelivered)
		}
	})

	t.Run("after_accepted_rcpt", func(t *testing.T) {
		backend := startNestedMailBackend(t)
		conn, reader, done := startNestedMailProxySession(t, backend.addr)

		send := func(cmd string) string {
			t.Helper()
			if _, err := io.WriteString(conn, cmd+"\r\n"); err != nil {
				t.Fatalf("writing %q: %v", cmd, err)
			}
			return readReply(t, reader)
		}

		if got := send("LHLO client.example.com"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("LHLO: %q, want 250", got)
		}
		if got := send("MAIL FROM:<first@example.com>"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("first MAIL: %q, want 250", got)
		}
		if got := send("RCPT TO:<a@example.com>"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("first RCPT: %q, want 250", got)
		}

		// Nested MAIL after an accepted recipient must get 503 5.5.1 without
		// clearing mailFromReceived or acceptedRcpts on the proxy.
		if got := send("MAIL FROM:<second@example.com>"); !strings.HasPrefix(got, "503 5.5.1 ") {
			t.Errorf("nested MAIL after RCPT: %q, want 503 5.5.1", got)
		}

		// The open transaction must still accept additional recipients.
		if got := send("RCPT TO:<b@example.com>"); !strings.HasPrefix(got, "250 ") {
			t.Errorf("second RCPT after refused nested MAIL: %q, want 250", got)
		}

		if got := send("DATA"); !strings.HasPrefix(got, "354 ") {
			t.Fatalf("DATA: %q, want 354", got)
		}
		if _, err := io.WriteString(conn, "Subject: nested-after-rcpt\r\n\r\nhello\r\n.\r\n"); err != nil {
			t.Fatalf("writing DATA body: %v", err)
		}

		// Bound the end-of-data read tightly so a zeroed acceptedRcpts (causing
		// relayMessageData to read 0 replies and hang the client) fails fast.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		wantA := "250 2.0.0 Delivered from <first@example.com> to <a@example.com>"
		if got := readReply(t, reader); got != wantA {
			t.Fatalf("first end-of-data reply: %q, want %q", got, wantA)
		}
		wantB := "250 2.0.0 Delivered from <first@example.com> to <b@example.com>"
		if got := readReply(t, reader); got != wantB {
			t.Fatalf("second end-of-data reply: %q, want %q", got, wantB)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		// Subsequent transaction on the same connection: a nested MAIL right before
		// DATA (with no further RCPT) must also leave acceptedRcpts intact so DATA
		// delivers to <a@example.com> rather than failing 503 on the reused backend.
		if got := send("MAIL FROM:<next@example.com>"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("second tx MAIL: %q, want 250", got)
		}
		if got := send("RCPT TO:<a@example.com>"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("second tx RCPT: %q, want 250", got)
		}
		if got := send("MAIL FROM:<intruder@example.com>"); !strings.HasPrefix(got, "503 5.5.1 ") {
			t.Errorf("second tx nested MAIL before DATA: %q, want 503 5.5.1", got)
		}
		if got := send("DATA"); !strings.HasPrefix(got, "354 ") {
			t.Fatalf("second tx DATA: %q, want 354", got)
		}
		if _, err := io.WriteString(conn, "Subject: second-tx\r\n\r\nagain\r\n.\r\n"); err != nil {
			t.Fatalf("writing second tx DATA body: %v", err)
		}
		wantNext := "250 2.0.0 Delivered from <next@example.com> to <a@example.com>"
		if got := readReply(t, reader); got != wantNext {
			t.Fatalf("second tx end-of-data reply: %q, want %q", got, wantNext)
		}

		// Clean third transaction on the same reused backend connection.
		if got := send("MAIL FROM:<clean@example.com>"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("third tx MAIL: %q, want 250", got)
		}
		if got := send("RCPT TO:<a@example.com>"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("third tx RCPT: %q, want 250", got)
		}
		if got := send("DATA"); !strings.HasPrefix(got, "354 ") {
			t.Fatalf("third tx DATA: %q, want 354", got)
		}
		if _, err := io.WriteString(conn, "Subject: third-tx\r\n\r\nclean\r\n.\r\n"); err != nil {
			t.Fatalf("writing third tx DATA body: %v", err)
		}
		wantClean := "250 2.0.0 Delivered from <clean@example.com> to <a@example.com>"
		if got := readReply(t, reader); got != wantClean {
			t.Fatalf("third tx end-of-data reply: %q, want %q", got, wantClean)
		}

		// RSET after MAIL clears the open transaction so a new MAIL succeeds.
		if got := send("MAIL FROM:<aborted@example.com>"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("MAIL before RSET: %q, want 250", got)
		}
		if got := send("RSET"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("RSET: %q, want 250", got)
		}
		if got := send("MAIL FROM:<after-rset@example.com>"); !strings.HasPrefix(got, "250 ") {
			t.Fatalf("MAIL after RSET: %q, want 250", got)
		}
		if got := send("QUIT"); !strings.HasPrefix(got, "221 ") {
			t.Fatalf("QUIT: %q, want 221", got)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("session did not finish after QUIT")
		}

		if gotConns := backend.conns.Load(); gotConns != 1 {
			t.Errorf("backend connections = %d, want 1 reused connection", gotConns)
		}
		for _, cmd := range backend.commands() {
			if strings.Contains(cmd, "second@example.com") || strings.Contains(cmd, "intruder@example.com") {
				t.Errorf("backend unexpectedly saw nested MAIL command: %s", cmd)
			}
		}
	})
}
