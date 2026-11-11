package lmtpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// startSTARTTLSSession runs a session of a STARTTLS proxy over a pipe whose
// server end is a SoraConn, as the listener's is, and returns that SoraConn and
// the client end with the greeting read.
func startSTARTTLSSession(t *testing.T) (*Server, *Session, *server.SoraConn, net.Conn, *bufio.Reader) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cert, err := tls.LoadX509KeyPair("../../testdata/sora.crt", "../../testdata/sora.key")
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		name:           "test",
		hostname:       "test-host",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
		tls:            true,
		tlsUseStartTLS: true,
		tlsConfig:      &tls.Config{Certificates: []tls.Certificate{cert}},
	}

	serverEnd, client := net.Pipe()
	listenerConn := server.NewSoraConn(serverEnd, server.SoraConnConfig{Protocol: "lmtp_proxy"})
	sess := newSession(srv, listenerConn, nil)
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
	return srv, sess, listenerConn, client, reader
}

// readReply returns the last line of the next reply, without its CRLF.
func readReply(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("reading a reply: %v", err)
		}
		if len(line) < 4 || line[3] != '-' {
			return strings.TrimRight(line, "\r\n")
		}
	}
}

// upgrade sends STARTTLS on a plaintext connection and completes the handshake.
func upgrade(t *testing.T, conn net.Conn, r *bufio.Reader) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	io.WriteString(conn, "STARTTLS\r\n")
	if line := readReply(t, r); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("STARTTLS = %q", line)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake after STARTTLS: %v", err)
	}
	return tlsConn, bufio.NewReader(tlsConn)
}

// The handshake is the session's, not an implicit-TLS listener's: the JA4 it
// sees must still reach the listener's SoraConn, and the session's log lines
// must keep reading it there after the transport moved to the TLS connection
// (#236).
func TestSTARTTLSRecordsJA4OnTheListenerConn(t *testing.T) {
	_, sess, listenerConn, conn, r := startSTARTTLSSession(t)
	tlsConn, tr := upgrade(t, conn, r)
	io.WriteString(tlsConn, "LHLO client.example\r\n")
	if line := readReply(t, tr); !strings.HasPrefix(line, "250 ") {
		t.Fatalf("LHLO after STARTTLS = %q", line)
	}

	ja4, _ := listenerConn.GetJA4Fingerprint()
	if !strings.HasPrefix(ja4, "t13") {
		t.Errorf("JA4 on the listener's SoraConn = %q, want a TLS 1.3 fingerprint", ja4)
	}
	logConn, ok := sess.getLogger().ClientConn.(interface{ GetJA4Fingerprint() (string, error) })
	if !ok {
		t.Fatalf("the session logs with %T after STARTTLS, which carries no JA4", sess.getLogger().ClientConn)
	}
	if ja4, _ := logConn.GetJA4Fingerprint(); !strings.HasPrefix(ja4, "t13") {
		t.Errorf("JA4 the session logs after STARTTLS = %q, want a TLS 1.3 fingerprint", ja4)
	}
}

// Commands pipelined behind STARTTLS were sent in plaintext, where anyone on
// the path could have added them; the upgraded session must not run them as if
// the client had sent them over TLS (CVE-2011-0411). The proxy refuses the
// STARTTLS instead, and the commands stay plaintext ones.
func TestSTARTTLSRefusesPipelinedCommands(t *testing.T) {
	_, _, _, conn, r := startSTARTTLSSession(t)
	io.WriteString(conn, "STARTTLS\r\nNOOP\r\n")
	if line := readReply(t, r); !strings.HasPrefix(line, "503 ") {
		t.Fatalf("pipelined STARTTLS = %q, want a 503 refusal", line)
	}
	if line := readReply(t, r); !strings.HasPrefix(line, "250 ") {
		t.Errorf("NOOP pipelined behind the refused STARTTLS = %q, want the plaintext reply", line)
	}
}

// A shutdown while STARTTLS is negotiating must not insert a plaintext 421
// into the TLS handshake.
func TestSTARTTLSOmitsPlaintextShutdownDuringHandshake(t *testing.T) {
	srv, _, _, conn, r := startSTARTTLSSession(t)
	io.WriteString(conn, "STARTTLS\r\n")
	if line := readReply(t, r); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("STARTTLS = %q", line)
	}
	go srv.sendGracefulShutdownMessage()
	conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if line, _ := r.ReadString('\n'); len(line) != 0 {
		t.Fatalf("plaintext after the positive STARTTLS reply: %q", line)
	}
}

// Before STARTTLS the client reads in plaintext and gets the shutdown notice.
func TestShutdownNoticeBeforeSTARTTLSReachesPlaintextClient(t *testing.T) {
	srv, _, _, _, r := startSTARTTLSSession(t)
	go srv.sendGracefulShutdownMessage()
	if line := readReply(t, r); !strings.HasPrefix(line, "421 ") {
		t.Fatalf("shutdown notice = %q, want a 421", line)
	}
}

// After STARTTLS the shutdown notice is readable through TLS.
func TestShutdownNoticeAfterSTARTTLSIsReadableThroughTLS(t *testing.T) {
	srv, _, _, conn, r := startSTARTTLSSession(t)
	tlsConn, tr := upgrade(t, conn, r)
	io.WriteString(tlsConn, "NOOP\r\n")
	if line := readReply(t, tr); !strings.HasPrefix(line, "250 ") {
		t.Fatalf("NOOP after STARTTLS = %q", line)
	}
	go srv.sendGracefulShutdownMessage()
	if line := readReply(t, tr); !strings.HasPrefix(line, "421 ") {
		t.Fatalf("shutdown notice through TLS = %q, want a 421", line)
	}
}

// A client that sends STARTTLS and then stalls must not hold the session until
// the absolute session timeout: with no auth idle timeout configured nothing
// bounded the handshake (#236).
func TestSTARTTLSHandshakeIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the handshake timeout")
	}
	_, _, _, conn, r := startSTARTTLSSession(t)
	io.WriteString(conn, "STARTTLS\r\n")
	if line := readReply(t, r); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("STARTTLS = %q", line)
	}
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	got, err := io.ReadAll(r)
	if len(got) != 0 {
		t.Fatalf("plaintext during the stalled handshake: %q", got)
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("the stalled handshake still held the connection after 15s")
	}
}
