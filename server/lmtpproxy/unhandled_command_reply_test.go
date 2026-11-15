package lmtpproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// startPlainSession runs a session of a plaintext proxy over a pipe and returns
// the client end with the greeting read.
func startPlainSession(t *testing.T) (net.Conn, *bufio.Reader) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &Server{
		name:           "test",
		hostname:       "test-host",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
	}

	serverEnd, client := net.Pipe()
	sess := newSession(srv, serverEnd, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sess.handleConnection()
	}()
	t.Cleanup(func() {
		client.Close()
		<-done
	})

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(client)
	if line := readReply(t, reader); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("greeting = %q", line)
	}
	return client, reader
}

// The proxy answers the commands it does not relay the way the LMTP backend
// (go-smtp) does, so a client gets the same reply from either:
//
//   - VRFY is a command every SMTP server MUST support (RFC 5321 section
//     4.5.1); one that does not verify MUST answer 252 (section 7.3).
//   - A command the server knows but does not implement gets 502, one it does
//     not recognize gets 500 (section 4.2.4). LMTP is SMTP here (RFC 2033
//     section 4).
//
// The session stays usable after each of these replies.
func TestLMTPProxyRepliesToUnhandledCommands(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{"VRFY postmaster", "252 2.5.0 "},
		{"vrfy <postmaster@example.com>", "252 2.5.0 "},
		{"EXPN staff", "502 5.5.1 "},
		{"HELP", "502 5.5.1 "},
		{"SEND FROM:<sender@example.com>", "502 5.5.1 "},
		{"SOML FROM:<sender@example.com>", "502 5.5.1 "},
		{"SAML FROM:<sender@example.com>", "502 5.5.1 "},
		{"TURN", "502 5.5.1 "},
		// Implemented by the backend, not by the proxy, which does not
		// advertise CHUNKING or AUTH.
		{"BDAT 10 LAST", "502 5.5.1 "},
		{"AUTH PLAIN", "502 5.5.1 "},
		{"XCLIENT ADDR=192.0.2.1", "502 5.5.1 "},
		{"FOO bar", "500 5.5.2 "},
		{"XYZZY", "500 5.5.2 "},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			conn, r := startPlainSession(t)
			io.WriteString(conn, tt.command+"\r\n")
			if line := readReply(t, r); !strings.HasPrefix(line, tt.want) {
				t.Errorf("%s: %q, want %q...", tt.command, line, tt.want)
			}
			io.WriteString(conn, "NOOP\r\n")
			if line := readReply(t, r); !strings.HasPrefix(line, "250 ") {
				t.Errorf("NOOP after %s: %q, want 250", tt.command, line)
			}
		})
	}
}
