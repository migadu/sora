package imapproxy

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

// startSTARTTLSSession runs a session of a STARTTLS proxy (insecure_auth off,
// as with tls = true) over a pipe whose server end is a SoraConn, as the
// listener's is, and returns the client end with the greeting read.
func startSTARTTLSSession(t *testing.T) (*Session, net.Conn, *bufio.Reader, string) {
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
		connManager:    newTestConnManager(t, "127.0.0.1:1"),
		authLimiter:    &fakeAuthLimiter{},
		insecureAuth:   false,
		startTLSConfig: server.StartTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}, "imap_proxy"),
	}
	srv.settings.Store(&reloadableSettings{maxAuthErrors: 5, authIdleTimeout: 5 * time.Second})

	serverEnd, client := net.Pipe()
	sess := newSession(srv, server.NewSoraConn(serverEnd, server.SoraConnConfig{Protocol: "imap_proxy"}))
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
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("greeting: %v", err)
	}
	return sess, client, reader, greeting
}

// readLine returns the next response line, without its CRLF.
func readLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("reading a response: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// upgrade sends STARTTLS on a plaintext connection and completes the handshake.
func upgrade(t *testing.T, conn net.Conn, r *bufio.Reader) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	io.WriteString(conn, "s STARTTLS\r\n")
	if line := readLine(t, r); line != "s OK Begin TLS negotiation now" {
		t.Fatalf("STARTTLS = %q", line)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake after STARTTLS: %v", err)
	}
	return tlsConn, bufio.NewReader(tlsConn)
}

// A STARTTLS proxy offers STARTTLS and LOGINDISABLED, not AUTH=PLAIN, until the
// client upgrades, and afterwards the list it offers over implicit TLS.
func TestSTARTTLSBeforeLogin(t *testing.T) {
	_, conn, r, greeting := startSTARTTLSSession(t)
	const plaintextCaps = "IMAP4rev2 IMAP4rev1 SASL-IR LITERAL- STARTTLS LOGINDISABLED"
	if want := "* OK [CAPABILITY " + plaintextCaps + "] Proxy Ready\r\n"; greeting != want {
		t.Errorf("plaintext greeting = %q, want %q", greeting, want)
	}
	io.WriteString(conn, "a CAPABILITY\r\n")
	if line := readLine(t, r); line != "* CAPABILITY "+plaintextCaps {
		t.Errorf("plaintext CAPABILITY = %q", line)
	}
	readLine(t, r)
	io.WriteString(conn, "b LOGIN user@example.com secret\r\n")
	if line := readLine(t, r); !strings.HasPrefix(line, "b NO [PRIVACYREQUIRED]") {
		t.Errorf("LOGIN before STARTTLS = %q, want NO [PRIVACYREQUIRED]", line)
	}

	tlsConn, tr := upgrade(t, conn, r)
	io.WriteString(tlsConn, "c CAPABILITY\r\n")
	if line := readLine(t, tr); line != "* CAPABILITY "+PreAuthCapabilities {
		t.Errorf("CAPABILITY after STARTTLS = %q, want %q", line, "* CAPABILITY "+PreAuthCapabilities)
	}
	readLine(t, tr)
	io.WriteString(tlsConn, "d STARTTLS\r\n")
	if line := readLine(t, tr); line != "d BAD STARTTLS not available" {
		t.Errorf("second STARTTLS = %q", line)
	}
}

// Commands pipelined behind STARTTLS were sent in plaintext, where anyone on
// the path could have added them; the upgraded session must not run them as if
// the client had sent them over TLS (CVE-2011-0411). The proxy refuses the
// STARTTLS instead, and the commands stay plaintext ones.
func TestSTARTTLSRefusesPipelinedCommands(t *testing.T) {
	_, conn, r, _ := startSTARTTLSSession(t)
	io.WriteString(conn, "s STARTTLS\r\nb LOGIN user@example.com secret\r\n")
	if line := readLine(t, r); line != "s BAD STARTTLS must be the last command sent before TLS negotiation" {
		t.Errorf("pipelined STARTTLS = %q", line)
	}
	if line := readLine(t, r); !strings.HasPrefix(line, "b NO [PRIVACYREQUIRED]") {
		t.Errorf("LOGIN pipelined behind the refused STARTTLS = %q, want the plaintext refusal", line)
	}
}

// The handshake is the session's, not an implicit-TLS listener's: the JA4 it
// sees must still reach the listener's SoraConn, where the ID forwarding, the
// PROXY v2 TLV and the session's log lines read it, while the transport moves to
// the TLS connection.
func TestSTARTTLSRecordsJA4OnTheListenerConn(t *testing.T) {
	sess, conn, r, _ := startSTARTTLSSession(t)
	tlsConn, tr := upgrade(t, conn, r)
	io.WriteString(tlsConn, "a NOOP\r\n")
	readLine(t, tr) // the NOOP ran after the upgrade, which republished clientConn

	sess.mu.Lock()
	clientConn := sess.clientConn
	sess.mu.Unlock()
	if _, ok := clientConn.(*tls.Conn); !ok {
		t.Errorf("clientConn after STARTTLS is %T, want the *tls.Conn", clientConn)
	}
	ja4, _ := sess.listenerConn.(interface{ GetJA4Fingerprint() (string, error) }).GetJA4Fingerprint()
	if !strings.HasPrefix(ja4, "t13") {
		t.Errorf("JA4 on the listener's SoraConn = %q, want a TLS 1.3 fingerprint", ja4)
	}
}
