package imapproxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPreAuthOverflowLiteralCloses(t *testing.T) {
	c, r := startPreAuthFramingTCPSession(t)
	fmt.Fprint(c, "a1 FOO {999999999999999999999999999999999999+}\r\nx2 NOOP\r\na3 NOOP\r\n")
	got := readReplies(t, r, "a3 ")
	if len(got) != 1 || got[0] != "* BYE [TOOBIG] Non-synchronizing literal too big" {
		t.Fatalf("got %q, want BYE/TOOBIG without executing payload", got)
	}
}
func TestPreAuthExtraLoginLiteralDrained(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"extra_after_plain_password", "a1 LOGIN user pass {7+}\r\nx2 NOOP\r\na3 NOOP\r\n"},
		{"extra_after_username_literal", "a1 LOGIN {4+}\r\nuser pass {7+}\r\nx2 NOOP\r\na3 NOOP\r\n"},
		{"extra_after_password_literal", "a1 LOGIN user {4+}\r\npass {7+}\r\nx2 NOOP\r\na3 NOOP\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, r := startPreAuthFramingTCPSession(t)
			fmt.Fprint(c, tc.input)
			got := readReplies(t, r, "a3 ")
			if len(got) != 2 || !strings.HasPrefix(got[0], "a1 BAD ") || got[1] != "a3 OK NOOP completed" {
				t.Fatalf("got %q, want one LOGIN BAD and a3 OK, no literal payload reply", got)
			}
		})
	}
}
func startPreAuthFramingTCPSession(t *testing.T, idleTimeout ...time.Duration) (net.Conn, *bufio.Reader) {
	timeout := 5 * time.Second
	if len(idleTimeout) > 0 {
		timeout = idleTimeout[0]
	}
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &Server{name: "framing-test", hostname: "localhost", ctx: ctx, cancel: cancel,
		activeSessions: make(map[*Session]struct{}), connManager: newTestConnManager(t, "127.0.0.1:1"),
		authLimiter: &fakeAuthLimiter{canErr: fmt.Errorf("test auth refusal")}, insecureAuth: true}
	srv.settings.Store(&reloadableSettings{maxAuthErrors: 3, authIdleTimeout: timeout})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		serverConn, err := ln.Accept()
		if err != nil {
			return
		}
		newSession(srv, serverConn).handleConnection()
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("session did not stop")
		}
	})
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(client)
	if line := readLine(t, reader); !strings.HasPrefix(line, "* OK") {
		t.Fatalf("greeting: %q", line)
	}
	return client, reader
}

func TestPreAuthOverflowSyncAndMalformedLiteralRecovery(t *testing.T) {
	for _, line := range []string{
		"a1 LOGIN {999999999999999999999999999999999999}",
		"a1 ID ({999999999999999999999999999999999999}",
		"a1 FOO {-1+}",
		"a1 FOO {+1+}",
		"a1 FOO {1x+}",
	} {
		t.Run(line, func(t *testing.T) {
			c, r := startPreAuthFramingTCPSession(t)
			fmt.Fprint(c, line+"\r\na3 NOOP\r\n")
			got := readReplies(t, r, "a3 ")
			if len(got) != 2 || !strings.HasPrefix(got[0], "a1 ") || strings.HasPrefix(got[0], "+") || got[1] != "a3 OK NOOP completed" {
				t.Fatalf("got %q, want one command reply then NOOP without continuation", got)
			}
		})
	}
}

func TestPreAuthManualLiteralTimeoutCloses(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"username", "a1 LOGIN {10+}\r\na"},
		{"password", "a1 LOGIN user {10+}\r\na"},
		{"both", "a1 LOGIN {4+}\r\nuser {10+}\r\na"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, r := startPreAuthFramingTCPSession(t, 150*time.Millisecond)
			fmt.Fprint(c, tc.input)
			if line := readLine(t, r); !strings.HasPrefix(line, "a1 BAD Failed to read ") {
				t.Fatalf("timeout reply:%q", line)
			}
			fmt.Fprint(c, "x2 NOOP\r\n\r\na3 NOOP\r\n")
			if line, err := r.ReadString('\n'); err == nil {
				t.Fatalf("partial literal tail resumed after timeout: %q", line)
			}
		})
	}
}
func TestPreAuthLiteralPrefixesDrained(t *testing.T) {
	for _, in := range []string{
		"a1 LOGIN user x{7+}\r\nx2 NOOP\r\na3 NOOP\r\n",
		"a1 LOGIN user ~{7+}\r\nx2 NOOP\r\na3 NOOP\r\n",
		"a1 LOGIN ~{7+}\r\nx2 NOOP\r\na3 NOOP\r\n",
		"a1 LOGIN x{7+}\r\nx2 NOOP\r\na3 NOOP\r\n",
		"a1 LOGIN {4+}\r\nuser x{7+}\r\nx2 NOOP\r\na3 NOOP\r\n",
	} {
		t.Run(in, func(t *testing.T) {
			c, r := startPreAuthFramingTCPSession(t)
			fmt.Fprint(c, in)
			got := readReplies(t, r, "a3 ")
			if len(got) != 2 || !strings.HasPrefix(got[0], "a1 BAD ") || got[1] != "a3 OK NOOP completed" {
				t.Fatalf("got %q; want one BAD and a3 OK, no payload reply", got)
			}
		})
	}
}
