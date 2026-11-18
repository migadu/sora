//go:build integration
// +build integration

package lmtpproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// TestHungBackendConnection drives a real proxy session into a backend that
// accepts TCP and then never sends a byte (no greeting, no FIN), with the
// backend connect timeout (the per-read deadline of readBackendLine) far longer
// than the absolute session timeout. The absolute session timeout must end the
// session: its watchdog closes the BACKEND connection too, which is what
// unblocks the goroutine parked in the backend read. Before that, closing only
// the client connection left such sessions hung (4,093 stuck connections in
// production). The connect-timeout deadline on the same read is covered by
// TestConnectToBackendSilentBackendTimesOut.
func TestHungBackendConnection(t *testing.T) {
	expectGoroutinesExit(t)
	const (
		absoluteTimeout = 2 * time.Second
		connectTimeout  = 30 * time.Second // the read deadline must not be what ends the session
		bound           = 10 * time.Second
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan struct{})
	backendClosed := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		// Never write. Reading only observes the proxy closing its side.
		io.Copy(io.Discard, conn)
		close(backendClosed)
	}()

	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("email")})
	}))
	t.Cleanup(lookup.Close)
	srv, err := New(context.Background(), nil, "test-host", ServerOptions{
		Name: "hung-backend", RemoteAddrs: []string{ln.Addr().String()}, RemotePort: 24,
		ConnectTimeout:         connectTimeout,
		AbsoluteSessionTimeout: absoluteTimeout,
		RemoteLookup:           &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "1s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })

	front, serverEnd := net.Pipe()
	sess := newSession(srv, serverEnd, nil)
	done := make(chan struct{})
	start := time.Now()
	go func() { defer close(done); sess.handleConnection() }()
	t.Cleanup(func() {
		front.Close()
		<-done
	})
	// Drain the client side so the session never blocks writing a reply.
	go io.Copy(io.Discard, front)

	write := func(cmd string) {
		t.Helper()
		front.SetWriteDeadline(time.Now().Add(bound))
		if _, err := io.WriteString(front, cmd+"\r\n"); err != nil {
			t.Fatalf("%s: %v", strings.Fields(cmd)[0], err)
		}
	}
	write("LHLO client.example.org")
	write("MAIL FROM:<sender@example.com>")
	write("RCPT TO:<user@example.com>") // the proxy dials the backend and waits for its greeting

	select {
	case <-accepted:
	case <-time.After(bound):
		t.Fatal("the proxy never connected to the backend")
	}
	select {
	case <-done:
		t.Fatalf("precondition: the session ended %v after it started, before blocking on the hung backend", time.Since(start))
	default:
	}

	select {
	case <-done:
	case <-time.After(bound):
		t.Fatalf("session still blocked on the hung backend %v after start (absolute timeout %v, connect timeout %v)",
			time.Since(start), absoluteTimeout, connectTimeout)
	}
	select {
	case <-backendClosed:
	case <-time.After(bound):
		t.Fatal("the session ended but left the backend connection open")
	}
	if elapsed := time.Since(start); elapsed < absoluteTimeout {
		t.Errorf("session ended after %v, before the absolute timeout %v: something other than the timeout ended it", elapsed, absoluteTimeout)
	}
}

// TestReadDeadlineDetectsStaleConnection drives a real session through a whole
// transaction into a backend that takes the message body and then never sends its
// end-of-data reply. relayEndOfDataTimeout (shortened here) must end the wait: the
// session drops the client and the backend connection instead of holding both until
// the absolute session timeout (none here). The proxy never invents an end-of-data
// reply, so the client sees its connection closed without one.
func TestReadDeadlineDetectsStaleConnection(t *testing.T) {
	expectGoroutinesExit(t)
	const bound = 10 * time.Second
	saved := relayEndOfDataTimeout
	relayEndOfDataTimeout = time.Second
	t.Cleanup(func() { relayEndOfDataTimeout = saved })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	bodyEnded := make(chan struct{})
	backendClosed := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		defer close(backendClosed)
		io.WriteString(conn, "220 backend ready\r\n")
		r := bufio.NewReader(conn)
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return // the proxy closed the connection
			}
			if inData {
				if line == ".\r\n" {
					close(bodyEnded)
					inData = false // go silent: no end-of-data reply
				}
				continue
			}
			switch verb, _, _ := strings.Cut(strings.ToUpper(strings.TrimRight(line, "\r\n")), " "); verb {
			case "LHLO":
				io.WriteString(conn, "250-backend\r\n250 PIPELINING\r\n")
			case "DATA":
				io.WriteString(conn, "354 go ahead\r\n")
				inData = true
			default:
				io.WriteString(conn, "250 2.0.0 OK\r\n")
			}
		}
	}()

	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("email")})
	}))
	t.Cleanup(lookup.Close)
	srv, err := New(context.Background(), nil, "test-host", ServerOptions{
		Name: "stale-backend", RemoteAddrs: []string{ln.Addr().String()}, RemotePort: 24, ConnectTimeout: time.Second,
		RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "1s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })

	front, serverEnd := net.Pipe()
	sess := newSession(srv, serverEnd, nil)
	done := make(chan struct{})
	go func() { defer close(done); sess.handleConnection() }()
	t.Cleanup(func() {
		sess.cancel() // a session still blocked on the backend (the failure) must end too
		front.Close()
		<-done
	})
	front.SetDeadline(time.Now().Add(bound))
	reader := bufio.NewReader(front)
	if greeting := readReply(t, reader); !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("greeting = %q", greeting)
	}
	for _, step := range []struct{ cmd, want string }{
		{"LHLO client.example.org", "250 "},
		{"MAIL FROM:<sender@example.com>", "250 "},
		{"RCPT TO:<user@example.com>", "250 "},
		{"DATA", "354 "},
	} {
		if _, err := io.WriteString(front, step.cmd+"\r\n"); err != nil {
			t.Fatal(err)
		}
		if got := readReply(t, reader); !strings.HasPrefix(got, step.want) {
			t.Fatalf("%s: %q, want %q", step.cmd, got, step.want)
		}
	}
	if _, err := io.WriteString(front, "Subject: test\r\n\r\nbody\r\n.\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-bodyEnded:
	case <-time.After(bound):
		t.Fatal("the backend never received the end of the message")
	}
	start := time.Now()

	if line, err := reader.ReadString('\n'); err == nil {
		t.Fatalf("got %q after the end of data; the backend sent no reply, so the proxy must not invent one", line)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("client connection still open %v after the backend went silent (end-of-data timeout %v)", bound, relayEndOfDataTimeout)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("client connection closed %v after the end of data; the end-of-data timeout is %v", elapsed, relayEndOfDataTimeout)
	}
	select {
	case <-backendClosed:
	case <-time.After(bound):
		t.Fatal("the session gave up on the backend but left its connection open")
	}
}
