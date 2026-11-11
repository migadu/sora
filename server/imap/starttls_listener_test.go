package imap

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// startSTARTTLSTestServer starts, through Serve, an IMAP server with a
// certificate and tls_use_starttls, and waits until its listener accepts.
// insecure_auth stays off, as it is by default with tls = true.
func startSTARTTLSTestServer(t *testing.T, commandTimeout time.Duration) (*IMAPServer, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	srv, err := New(ctx, "starttls", "localhost", addr, &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, &cache.Cache{}, IMAPServerOptions{
		TLS:            true,
		TLSCertFile:    "../../testdata/sora.crt",
		TLSKeyFile:     "../../testdata/sora.key",
		TLSUseStartTLS: true,
		CommandTimeout: commandTimeout,
		AppendLimit:    DefaultAppendLimit,
		MaxConnections: 10,
		Config:         &config.Config{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	serveReloadTestServer(t, srv, addr)
	return srv, addr
}

// capabilities sends CAPABILITY and returns the untagged capability line.
func capabilities(t *testing.T, w net.Conn, r *bufio.Reader, tag string) string {
	t.Helper()
	fmt.Fprintf(w, "%s CAPABILITY\r\n", tag)
	var caps string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("reading CAPABILITY: %v", err)
		}
		if strings.HasPrefix(line, "* CAPABILITY ") {
			caps = strings.TrimSpace(line)
		}
		if strings.HasPrefix(line, tag+" ") {
			if !strings.HasPrefix(line, tag+" OK") {
				t.Fatalf("CAPABILITY = %q", line)
			}
			return caps
		}
	}
}

// dialSTARTTLS connects in plaintext, checks the server offers STARTTLS and
// refuses login before it, and upgrades.
func dialSTARTTLS(t *testing.T, addr string) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "* OK") {
		t.Fatalf("plaintext greeting = %q, %v", line, err)
	}

	caps := capabilities(t, conn, reader, "a")
	if !strings.Contains(caps, " STARTTLS") || !strings.Contains(caps, " LOGINDISABLED") {
		t.Errorf("plaintext CAPABILITY must offer STARTTLS and LOGINDISABLED, got %q", caps)
	}
	if strings.Contains(caps, "AUTH=") {
		t.Errorf("plaintext CAPABILITY must not offer AUTH= before STARTTLS, got %q", caps)
	}
	fmt.Fprint(conn, "b LOGIN user@example.com secret\r\n")
	if line := readTagged(t, reader, "b "); !strings.HasPrefix(line, "b NO [PRIVACYREQUIRED]") {
		t.Errorf("LOGIN before STARTTLS = %q, want NO [PRIVACYREQUIRED]", line)
	}

	fmt.Fprint(conn, "c STARTTLS\r\n")
	if line := readTagged(t, reader, "c "); !strings.HasPrefix(line, "c OK") {
		t.Fatalf("STARTTLS = %q", line)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake after STARTTLS: %v", err)
	}
	return tlsConn, bufio.NewReader(tlsConn)
}

// tls_use_starttls must give a plaintext listener on which go-imap offers
// STARTTLS; it used to be ignored, and a certificate always made the listener
// implicit-TLS (#191).
func TestSTARTTLSListenerOffersSTARTTLS(t *testing.T) {
	_, addr := startSTARTTLSTestServer(t, time.Minute)
	conn, reader := dialSTARTTLS(t, addr)

	caps := capabilities(t, conn, reader, "d")
	if !strings.Contains(caps, " AUTH=PLAIN") {
		t.Errorf("CAPABILITY after STARTTLS must offer AUTH=PLAIN, got %q", caps)
	}
	if strings.Contains(caps, " STARTTLS") || strings.Contains(caps, " LOGINDISABLED") {
		t.Errorf("CAPABILITY after STARTTLS must offer neither STARTTLS nor LOGINDISABLED, got %q", caps)
	}
}

// The timeout BYE is written by the SoraConn's timeout goroutine. After
// STARTTLS the client reads through go-imap's TLS connection, which sits above
// the SoraConn, so a BYE written to the SoraConn's transport arrives as
// plaintext inside the TLS stream and the client sees a TLS record error.
func TestIdleTimeoutNoticeAfterSTARTTLSIsReadableThroughTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the idle timeout")
	}
	_, addr := startSTARTTLSTestServer(t, 2*time.Second)
	conn, reader := dialSTARTTLS(t, addr)
	// A command through TLS: go-imap has read from its TLS connection, so the
	// SoraConn has recorded it as the connection the session is using.
	capabilities(t, conn, reader, "d")

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the idle notice through TLS: %v", err)
	}
	if want := "* BYE [UNAVAILABLE] Idle timeout, please reconnect\r\n"; line != want {
		t.Fatalf("idle notice through TLS = %q, want %q", line, want)
	}
}

// The shutdown BYE goes through go-imap's own encoder, which STARTTLS rebinds
// to the TLS connection; this guards that it stays readable after the upgrade.
func TestShutdownByeAfterSTARTTLSIsReadableThroughTLS(t *testing.T) {
	srv, addr := startSTARTTLSTestServer(t, time.Minute)
	conn, reader := dialSTARTTLS(t, addr)
	capabilities(t, conn, reader, "d")

	go srv.Close()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the shutdown BYE through TLS: %v", err)
	}
	if want := "* BYE Server shutting down, please reconnect\r\n"; line != want {
		t.Fatalf("shutdown BYE through TLS = %q, want %q", line, want)
	}
}

// listenerConnOf returns the server's connection to the client at local, as
// the listener handed it to go-imap.
func listenerConnOf(t *testing.T, srv *IMAPServer, local net.Addr) net.Conn {
	t.Helper()
	srv.activeConnsMutex.RLock()
	defer srv.activeConnsMutex.RUnlock()
	for c := range srv.activeConns {
		if c.NetConn().RemoteAddr().String() == local.String() {
			return c.NetConn()
		}
	}
	t.Fatal("accepted connection was not registered")
	return nil
}

// The writer of an asynchronous notice follows the session: the plaintext
// connection until the client sends STARTTLS, none from then until the TLS
// handshake has completed, the TLS connection afterwards. go-imap publishes its
// *tls.Conn before the handshake runs, so being a *tls.Conn is not enough
// (#236).
func TestSTARTTLSNoticeWriterFollowsTheUpgrade(t *testing.T) {
	srv, addr := startSTARTTLSTestServer(t, time.Minute)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	capabilities(t, conn, reader, "a")
	plain := listenerConnOf(t, srv, conn.LocalAddr())
	if got := serverPkg.NoticeConn(plain); got != plain {
		t.Fatalf("notice writer of a plaintext session = %T, want its plaintext connection", got)
	}

	fmt.Fprint(conn, "c STARTTLS\r\n")
	if line := readTagged(t, reader, "c "); !strings.HasPrefix(line, "c OK") {
		t.Fatalf("STARTTLS = %q", line)
	}
	// go-imap is now waiting for the ClientHello inside its TLS connection.
	time.Sleep(100 * time.Millisecond)
	if got := serverPkg.NoticeConn(plain); got != nil {
		t.Fatalf("notice writer before the TLS handshake = %T, want none", got)
	}

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake after STARTTLS: %v", err)
	}
	capabilities(t, tlsConn, bufio.NewReader(tlsConn), "d")
	if _, ok := serverPkg.NoticeConn(plain).(*tls.Conn); !ok {
		t.Fatalf("notice writer after the TLS handshake = %T, want the TLS connection", serverPkg.NoticeConn(plain))
	}
}

// A client that has not sent STARTTLS reads in plaintext: the idle BYE must
// reach it. It used to be withheld from every session of a STARTTLS listener
// that was not yet TLS (#236).
func TestIdleTimeoutNoticeBeforeSTARTTLSReachesPlaintextClient(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the idle timeout")
	}
	_, addr := startSTARTTLSTestServer(t, 2*time.Second)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	capabilities(t, conn, reader, "a")

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the idle notice in plaintext: %v", err)
	}
	if want := "* BYE [UNAVAILABLE] Idle timeout, please reconnect\r\n"; line != want {
		t.Fatalf("idle notice = %q, want %q", line, want)
	}
}
