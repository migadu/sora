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

	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/testutil"
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

	b, addr := startImplicitTLSBackend(t, "tls-deadline")

	// The silent connection is the first one the server sees: no probe dial
	// that would itself take the only slot.
	silent := dialFirstConnection(t, addr)
	defer silent.Close()

	waitFor(t, 3*time.Second, "the silent connection takes the slot", func() bool {
		return b.limiter.GetStats().TotalConnections == 1
	})

	// Send nothing. The server must close the connection on its own.
	start := time.Now()
	silent.SetReadDeadline(time.Now().Add(20 * time.Second))
	_, err := io.Copy(io.Discard, silent)
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

// A plain-text client on the implicit-TLS port (#335 item 3) is told so and
// counted in sora_connection_timeouts_total{reason="plain_text_on_tls_port"},
// as on the other implicit-TLS listeners, and gives back its slot. Before, the
// handshake failed on its first line with nothing sent back or counted.
func TestImplicitTLSPlainTextClientRejected(t *testing.T) {
	const name = "tls-plaintext"
	b, addr := startImplicitTLSBackend(t, name)
	rejected := metrics.ConnectionTimeoutsTotal.WithLabelValues("lmtp", name, "localhost", "plain_text_on_tls_port")
	before := testutil.ToFloat64(rejected)

	conn := dialFirstConnection(t, addr)
	defer conn.Close()
	// A client that speaks first, as `printf 'LHLO x\r\n' | nc` does. One
	// that waits for a greeting sends nothing the probe could see, and gets
	// the handshake deadline as in TestImplicitTLSSilentConnectionReleasesSlot.
	io.WriteString(conn, "LHLO client.example.com\r\n")
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(conn)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("plain-text connection still open, server sent %q", got)
	}
	if !strings.Contains(string(got), "Plain-text connection attempted on TLS port") {
		t.Fatalf("plain-text client on the TLS port got %q (err=%v), want the plain-text notice", got, err)
	}
	if strings.Contains(string(got), "220") {
		t.Fatalf("greeting leaked in plain text: %q", got)
	}

	waitFor(t, 3*time.Second, "the rejection is counted", func() bool {
		return testutil.ToFloat64(rejected) == before+1
	})
	waitFor(t, 3*time.Second, "the slot is released", func() bool {
		return b.limiter.GetStats().TotalConnections == 0
	})
}

// startImplicitTLSBackend starts an LMTP backend on an implicit-TLS listener
// with a single max_connections slot, stopped when the test ends.
func startImplicitTLSBackend(t *testing.T, name string) (*LMTPServerBackend, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	b, err := New(ctx, name, "localhost", addr, &storage.S3Storage{}, &resilient.ResilientDatabase{}, &uploader.UploadWorker{}, LMTPServerOptions{
		TLS:            true,
		TLSConfig:      &tls.Config{Certificates: []tls.Certificate{selfSignedTestCert(t)}},
		MaxConnections: 1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go b.Start(make(chan error, 1))
	t.Cleanup(func() { b.Close() })
	return b, addr
}

// dialFirstConnection dials addr until the server listens, so the connection
// it returns is the first the server accepts.
func dialFirstConnection(t *testing.T, addr string) net.Conn {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); ; {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
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
