package managesieve

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

// The shutdown broadcast writes from the goroutine that stops the server. After
// STARTTLS the client reads through the library's TLS connection, which sits
// above the session's SoraConn, so a BYE written to the SoraConn arrives as
// plaintext inside the TLS stream and the client sees a TLS record error.
func TestShutdownNoticeAfterStartTLSIsReadableThroughTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	srv, err := New(ctx, "test", "localhost", addr, &resilient.ResilientDatabase{}, ManageSieveServerOptions{
		TLS:            true,
		TLSUseStartTLS: true,
		TLSCertFile:    "../../testdata/sora.crt",
		TLSKeyFile:     "../../testdata/sora.key",
		CommandTimeout: time.Minute,
		MaxConnections: 10,
		Config:         &config.Config{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	errChan := make(chan error, 1)
	go srv.Start(errChan)

	var conn net.Conn
	for deadline := time.Now().Add(3 * time.Second); ; {
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
	readUntilOK(t, reader, "greeting")
	fmt.Fprint(conn, "STARTTLS\r\n")
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "OK") {
		t.Fatalf("STARTTLS = %q, %v", line, err)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	tlsReader := bufio.NewReader(tlsConn)
	readUntilOK(t, tlsReader, "capabilities after STARTTLS") // RFC 5804 §2.2
	// A command through TLS: the library has read from its TLS connection, so
	// the SoraConn has recorded it as the connection the session is using.
	fmt.Fprint(tlsConn, "CAPABILITY\r\n")
	readUntilOK(t, tlsReader, "CAPABILITY through TLS")

	go srv.Close()
	line, err := tlsReader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the shutdown notice through TLS: %v", err)
	}
	if want := "BYE (TRYLATER) \"Server shutting down, please reconnect\"\r\n"; line != want {
		t.Fatalf("shutdown notice through TLS = %q, want %q", line, want)
	}
}
