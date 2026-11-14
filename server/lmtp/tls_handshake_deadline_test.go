package lmtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// A connection to the implicit-TLS listener that opens TCP and never sends a
// ClientHello must be closed after the handshake deadline, giving back its
// max_connections slot, as on the IMAP, POP3 and ManageSieve listeners. Before,
// go-smtp's greeting started the handshake with no read deadline and the
// connection held its slot until the client went away.
func TestImplicitTLSSilentConnectionReleasesSlot(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the TLS handshake deadline")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	b, err := New(ctx, "tls-deadline", "localhost", addr, &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, LMTPServerOptions{
		TLS:            true,
		TLSConfig:      &tls.Config{Certificates: []tls.Certificate{selfSignedTestCert(t)}},
		MaxConnections: 1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go b.Start(make(chan error, 1))
	defer b.Close()

	// The silent connection is the first one the server sees: no probe dial
	// that would itself take the only slot.
	var silent net.Conn
	for deadline := time.Now().Add(3 * time.Second); ; {
		silent, err = net.Dial("tcp", addr)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer silent.Close()

	waitFor(t, 3*time.Second, "the silent connection takes the slot", func() bool {
		return b.limiter.GetStats().TotalConnections == 1
	})

	// Send nothing. The server must close the connection on its own.
	start := time.Now()
	silent.SetReadDeadline(time.Now().Add(20 * time.Second))
	_, err = io.Copy(io.Discard, silent)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("connection that never handshakes still open after %v", time.Since(start).Round(time.Second))
	}
	t.Logf("server closed the silent connection after %v (err=%v)", time.Since(start).Round(100*time.Millisecond), err)

	waitFor(t, 3*time.Second, "the slot is released", func() bool {
		return b.limiter.GetStats().TotalConnections == 0
	})

	// The released slot serves a client that does handshake.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS dial after the silent connection was closed: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	if line := readReplyLine(t, r); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("greeting over implicit TLS: %q", line)
	}
	io.WriteString(conn, "LHLO client.example.com\r\n")
	for {
		line := readReplyLine(t, r)
		if !strings.HasPrefix(line, "250") {
			t.Fatalf("LHLO over implicit TLS: %q", line)
		}
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(timeout); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
