package pop3

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// startSTARTTLSTestServer starts, through Start, a POP3 server with a
// certificate and tls_use_starttls, and waits until its listener accepts.
func startSTARTTLSTestServer(t *testing.T) (*POP3Server, string) {
	t.Helper()
	s, addr := newReloadTestServer(t, POP3ServerOptions{
		TLS:            true,
		TLSCertFile:    "../../testdata/sora.crt",
		TLSKeyFile:     "../../testdata/sora.key",
		TLSUseStartTLS: true,
		CommandTimeout: time.Minute,
	})
	errChan := make(chan error, 1)
	go s.Start(errChan)
	for deadline := time.Now().Add(3 * time.Second); ; {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return s, addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// readCapa sends CAPA and returns the capability lines.
func readCapa(t *testing.T, w net.Conn, r *bufio.Reader) string {
	t.Helper()
	fmt.Fprint(w, "CAPA\r\n")
	if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("CAPA = %q, %v", line, err)
	}
	var caps []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("reading CAPA: %v", err)
		}
		if line = strings.TrimSpace(line); line == "." {
			return strings.Join(caps, "\n")
		}
		caps = append(caps, line)
	}
}

// dialSTLS connects in plaintext, checks the server offers STLS and no login
// before it, and upgrades.
func dialSTLS(t *testing.T, addr string) (*tls.Conn, *bufio.Reader) {
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

	caps := readCapa(t, conn, reader)
	if !strings.Contains(caps, "STLS") {
		t.Errorf("plaintext CAPA must offer STLS, got:\n%s", caps)
	}
	// insecure_auth is off (tls = true), so login waits for the upgrade.
	if strings.Contains(caps, "USER") || strings.Contains(caps, "SASL") {
		t.Errorf("plaintext CAPA must not offer USER or SASL before STLS, got:\n%s", caps)
	}

	fmt.Fprint(conn, "STLS\r\n")
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("STLS = %q, %v", line, err)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake after STLS: %v", err)
	}
	return tlsConn, bufio.NewReader(tlsConn)
}

// tls_use_starttls must give a plaintext listener on which the library offers
// STLS; it used to be ignored, and a certificate always made the listener
// implicit-TLS (#191).
func TestSTARTTLSListenerOffersSTLS(t *testing.T) {
	_, addr := startSTARTTLSTestServer(t)
	conn, reader := dialSTLS(t, addr)

	caps := readCapa(t, conn, reader)
	if !strings.Contains(caps, "USER") || !strings.Contains(caps, "SASL") {
		t.Errorf("CAPA after STLS must offer USER and SASL, got:\n%s", caps)
	}
	if strings.Contains(caps, "STLS") {
		t.Errorf("CAPA after STLS must not offer STLS again, got:\n%s", caps)
	}
}

// The shutdown broadcast writes from the goroutine that stops the server. After
// STLS the client reads through the library's TLS connection, which sits above
// the session's SoraConn, so a notice written to the SoraConn arrives as
// plaintext inside the TLS stream and the client sees a TLS record error.
func TestShutdownNoticeAfterSTLSIsReadableThroughTLS(t *testing.T) {
	s, addr := startSTARTTLSTestServer(t)
	conn, reader := dialSTLS(t, addr)
	// A command through TLS: the library has read from its TLS connection, so
	// the SoraConn has recorded it as the connection the session is using.
	readCapa(t, conn, reader)

	go s.Close()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the shutdown notice through TLS: %v", err)
	}
	if want := "-ERR Server shutting down, please reconnect\r\n"; line != want {
		t.Fatalf("shutdown notice through TLS = %q, want %q", line, want)
	}
}

// A shutdown while STLS is negotiating must not insert a plaintext -ERR into
// the TLS handshake. The library exposes its plaintext NetConn until completion.
func TestShutdownDuringSTLSHandshakeOmitsPlaintextNotice(t *testing.T) {
	s, addr := startSTARTTLSTestServer(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "STLS\r\n")
	if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "+OK") {
		t.Fatalf("STLS = %q, %v", line, err)
	}
	// The positive response has been sent, so all subsequent bytes must be TLS.
	go s.sendGracefulShutdownMessage()
	conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	got := make([]byte, 128)
	if n, _ := r.Read(got); n != 0 {
		t.Fatalf("plaintext during STLS handshake: %q", got[:n])
	}
}
