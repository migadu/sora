package pop3

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	serverPkg "github.com/migadu/sora/server"
)

// dialPlaintext connects to a STARTTLS listener and reads the greeting.
func dialPlaintext(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("plaintext greeting = %q, %v", line, err)
	}
	return conn, reader
}

// A client that has not sent STLS reads in plaintext: the shutdown notice must
// reach it. It used to be withheld from every session of a STARTTLS listener
// that was not yet TLS, upgrade in progress or not (#236).
func TestShutdownNoticeBeforeSTLSReachesPlaintextClient(t *testing.T) {
	s, addr := startSTARTTLSTestServer(t)
	conn, reader := dialPlaintext(t, addr)
	readCapa(t, conn, reader)

	go s.sendGracefulShutdownMessage()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the shutdown notice in plaintext: %v", err)
	}
	if want := "-ERR Server shutting down, please reconnect\r\n"; line != want {
		t.Fatalf("shutdown notice = %q, want %q", line, want)
	}
}

// The slow-throughput notice of a session that stays plaintext on a listener
// offering STLS goes to it in plaintext.
func TestSlowThroughputNoticeOnPlaintextSessionOfSTLSListener(t *testing.T) {
	addr := startSTLSThroughputServer(t)
	conn, reader := dialPlaintext(t, addr)
	defer trickle(conn)()

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the timeout notice in plaintext: %v", err)
	}
	if want := "-ERR [IN-USE] Connection too slow, please reconnect\r\n"; line != want {
		t.Fatalf("timeout notice = %q, want %q", line, want)
	}
}

// heldWriteConn passes the first write through (the ClientHello) and holds
// every later one until release sends them as a single write, which is how a
// TLS 1.3 client's Finished and its first command reach the server in one read.
type heldWriteConn struct {
	net.Conn
	mu     sync.Mutex
	writes int
	held   []byte
}

func (c *heldWriteConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writes++; c.writes == 1 {
		return c.Conn.Write(b)
	}
	c.held = append(c.held, b...)
	return len(b), nil
}

func (c *heldWriteConn) release() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.Conn.Write(c.held)
	c.held = nil
	c.writes = 0
	return err
}

// parkingAuthLimiter parks the first authentication attempt until released,
// which holds the session inside a command with no network read behind it.
type parkingAuthLimiter struct {
	serverPkg.AuthLimiter
	parked  chan struct{}
	release chan struct{}
}

func (l *parkingAuthLimiter) CanAttemptAuthWithProxy(ctx context.Context, _ net.Conn, _ *serverPkg.ProxyProtocolInfo, _ string) error {
	close(l.parked)
	select {
	case <-l.release:
	case <-ctx.Done():
	}
	return errors.New("released")
}

func (l *parkingAuthLimiter) Stop() {}

// A TLS 1.3 client may send its Finished and its first command together. The
// library then decrypts that command from what the handshake already read, with
// no further read of the SoraConn, so a record of the session's connection made
// only as reads start still says "handshake in progress" for as long as the
// command runs (#236): a shutdown during a login dropped the notice.
func TestShutdownNoticeAfterCoalescedSTLSHandshakeIsReadableThroughTLS(t *testing.T) {
	limiter := &parkingAuthLimiter{parked: make(chan struct{}), release: make(chan struct{})}
	defer close(limiter.release)
	s, addr := newReloadTestServer(t, POP3ServerOptions{
		TLS:                 true,
		TLSCertFile:         "../../testdata/sora.crt",
		TLSKeyFile:          "../../testdata/sora.key",
		TLSUseStartTLS:      true,
		CommandTimeout:      time.Minute,
		AuthLimiterOverride: limiter,
	})
	errChan := make(chan error, 1)
	go s.Start(errChan)
	var conn net.Conn
	for deadline := time.Now().Add(3 * time.Second); ; {
		var err error
		if conn, err = net.Dial("tcp", addr); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("greeting = %q, %v", line, err)
	}
	fmt.Fprint(conn, "STLS\r\n")
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("STLS = %q, %v", line, err)
	}

	held := &heldWriteConn{Conn: conn}
	tlsConn := tls.Client(held, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	fmt.Fprint(tlsConn, "USER user@example.com\r\nPASS secret\r\n")
	if err := held.release(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-limiter.parked:
	case <-time.After(5 * time.Second):
		t.Fatal("the login coalesced with the handshake never started")
	}

	go s.sendGracefulShutdownMessage()
	tlsReader := bufio.NewReader(tlsConn)
	if line, err := tlsReader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("USER through TLS = %q, %v", line, err)
	}
	line, err := tlsReader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the shutdown notice through TLS: %v", err)
	}
	if want := "-ERR Server shutting down, please reconnect\r\n"; line != want {
		t.Fatalf("shutdown notice through TLS = %q, want %q", line, want)
	}
}

// Notice suppression follows the library's accepted transition, including
// whitespace its parser accepts, rather than a second command parser.
func TestShutdownNoticeDuringSTLSWithAcceptedWhitespaceIsSuppressed(t *testing.T) {
	for _, command := range []string{"STLS\v\r\n", "\vSTLS\r\n", "STLS\u00a0\r\n"} {
		t.Run(fmt.Sprintf("%q", command), func(t *testing.T) {
			s, addr := startSTARTTLSTestServer(t)
			conn, reader := dialPlaintext(t, addr)
			fmt.Fprint(conn, command)
			if line, err := reader.ReadString('\n'); err != nil || line != "+OK Begin TLS negotiation\r\n" {
				t.Fatalf("STLS reply = %q, %v", line, err)
			}
			go s.sendGracefulShutdownMessage()
			conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if line, _ := reader.ReadString('\n'); len(line) != 0 {
				t.Fatalf("plaintext after STLS acknowledgement = %q", line)
			}
		})
	}
}

// A command argument that looks like a TLS verb is ordinary protocol data.
func TestShutdownNoticeAfterUserNamedSTLSRemainsPlaintext(t *testing.T) {
	s, addr := newReloadTestServer(t, POP3ServerOptions{
		TLS:            true,
		TLSCertFile:    "../../testdata/sora.crt",
		TLSKeyFile:     "../../testdata/sora.key",
		TLSUseStartTLS: true,
		InsecureAuth:   true,
		CommandTimeout: time.Minute,
	})
	startListenerTestServer(t, s, addr)
	conn, reader := dialPlaintext(t, addr)
	fmt.Fprint(conn, "USER STLS\r\n")
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("USER reply = %q, %v", line, err)
	}
	go s.sendGracefulShutdownMessage()
	if line, err := reader.ReadString('\n'); err != nil || line != "-ERR Server shutting down, please reconnect\r\n" {
		t.Fatalf("plaintext shutdown notice = %q, %v", line, err)
	}
}
