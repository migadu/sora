package lmtpproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// startPlainSession runs a session of a plain-text proxy whose max_message_size is
// maxSize over a pipe and returns the client end with the greeting read.
func startPlainSession(t *testing.T, maxSize int64) (net.Conn, *bufio.Reader) {
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
	srv.settings.Store(&reloadableSettings{maxMessageSize: maxSize})

	serverEnd, client := net.Pipe()
	sess := newSession(srv, server.NewSoraConn(serverEnd, server.SoraConnConfig{Protocol: "lmtp_proxy"}), nil)
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

// The proxy advertises its max_message_size as "SIZE <n>" in LHLO. RFC 1870 section 6.1:
// "If the indicated size is larger than the server's fixed maximum message size, the
// server responds with code 552", and section 7 has a server with a fixed limit "return
// a 552 reply code if the client's declared size exceeds its fixed size limit". The
// refusal comes before RCPT, so the MTA never sends the body. A declaration at or under
// the limit, or with no SIZE, is accepted, and so is a value that is no number, as before.
func TestMAILRefusesDeclaredSizeOverTheAdvertisedLimit(t *testing.T) {
	conn, r := startPlainSession(t, 1024)
	io.WriteString(conn, "LHLO client.example.org\r\n")
	var lhlo []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("reading LHLO reply: %v", err)
		}
		lhlo = append(lhlo, strings.TrimRight(line, "\r\n"))
		if len(line) < 4 || line[3] != '-' {
			break
		}
	}
	if !strings.Contains(strings.Join(lhlo, "\n"), "250-SIZE 1024") {
		t.Fatalf("LHLO reply %q does not advertise SIZE 1024", lhlo)
	}

	tests := []struct {
		mail, want string
	}{
		{"MAIL FROM:<a@example.org> SIZE=1025", "552 5.3.4 "},
		{"MAIL FROM:<a@example.org> BODY=8BITMIME size=104857600", "552 5.3.4 "},
		{"MAIL FROM:<> SIZE=99999999999999999999", "552 5.3.4 "},
		{"MAIL FROM:<a@example.org> SIZE=12x", "250 "},
		{"MAIL FROM:<a@example.org> SIZE=1024", "250 "},
		{"MAIL FROM:<a@example.org>", "250 "},
	}
	for _, tt := range tests {
		io.WriteString(conn, tt.mail+"\r\n")
		if got := readReply(t, r); !strings.HasPrefix(got, tt.want) {
			t.Errorf("%s: %q, want %q", tt.mail, got, tt.want)
		}
		io.WriteString(conn, "RSET\r\n")
		readReply(t, r)
	}

	// A refused MAIL starts no transaction: RCPT has no sender to go with.
	io.WriteString(conn, fmt.Sprintf("MAIL FROM:<a@example.org> SIZE=%d\r\n", 2048))
	if got := readReply(t, r); !strings.HasPrefix(got, "552 ") {
		t.Fatalf("MAIL SIZE=2048 over a limit of 1024: %q, want 552", got)
	}
	io.WriteString(conn, "RCPT TO:<user@example.com>\r\n")
	if got := readReply(t, r); !strings.HasPrefix(got, "503 ") {
		t.Errorf("RCPT after a MAIL refused for its size: %q, want 503", got)
	}
}

// With no limit (max_message_size = 0) the proxy advertises no SIZE and refuses no
// declaration.
func TestMAILWithoutLimitAcceptsAnyDeclaredSize(t *testing.T) {
	conn, r := startPlainSession(t, 0)
	io.WriteString(conn, "MAIL FROM:<a@example.org> SIZE=104857600\r\n")
	if got := readReply(t, r); !strings.HasPrefix(got, "250 ") {
		t.Errorf("MAIL with SIZE and no limit: %q, want 250", got)
	}
}
